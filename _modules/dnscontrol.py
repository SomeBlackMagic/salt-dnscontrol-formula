"""dnscontrol execution helpers for Salt."""

import copy
import errno
import json
import os
import subprocess
import time
from collections import OrderedDict

try:
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None

__virtualname__ = "dnscontrol"
__salt__ = globals().get("__salt__", {})
__opts__ = globals().get("__opts__", {})

_DEFAULT_CONFIG = {
    "config_dir": "/etc/dnscontrol",
    "lock_file": "/var/lock/dnscontrol.lock",
    "lock_timeout_sec": 120,
    "dnscontrol_bin": "dnscontrol",
    "template_base": "salt://dnscontrol/templates",
    "saltenv": "base",
    "strict_duplicates": True,
    "fail_on_warnings": True,
    "multi_value_types": ["MX", "TXT", "SRV"],
    "providers": {},
    "zones": {},
    "creds_mode": "0600",
    "config_mode": "0700",
}

_SIMPLE_VALUE_TYPES = {"A", "AAAA", "CNAME", "NS", "PTR", "TXT"}


class DNSControlError(Exception):
    """Configuration or runtime error."""


class LockTimeoutError(DNSControlError):
    """Raised when lock acquisition times out."""


def __virtual__():
    return __virtualname__


def _new_report():
    return {
        "errors": [],
        "warnings": [],
        "info": [],
        "conflicts": [],
        "stats": {
            "zones": 0,
            "records_input": 0,
            "records_final": 0,
            "conflicts": 0,
            "warnings": 0,
            "errors": 0,
        },
    }


def _add_issue(report, level, message, **kwargs):
    entry = {"message": message}
    if kwargs:
        entry.update(kwargs)

    if level == "error":
        report["errors"].append(entry)
    elif level == "warning":
        report["warnings"].append(entry)
    else:
        report["info"].append(entry)


def _deep_merge(base, override):
    data = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(data.get(key), dict):
            data[key] = _deep_merge(data[key], value)
        else:
            data[key] = copy.deepcopy(value)
    return data


def _as_bool(value, default=False):
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        text = value.strip().lower()
        if text in ("1", "true", "yes", "on"):
            return True
        if text in ("0", "false", "no", "off"):
            return False
    return bool(value)


def _as_int(value, field_name):
    try:
        return int(value)
    except (TypeError, ValueError):
        raise DNSControlError("Field '{}' must be an integer".format(field_name))


def _shell_quote(value):
    return json.dumps(str(value), ensure_ascii=True)


def _normalize_name(name):
    text = str(name).strip()
    if not text:
        raise DNSControlError("Record name must not be empty")
    return text


def _normalize_fqdn(name, zone_name):
    low_zone = zone_name.lower().rstrip(".")
    if name == "@":
        return low_zone
    if name.endswith("."):
        return name[:-1].lower()

    low_name = name.lower().rstrip(".")
    if low_name == low_zone or low_name.endswith("." + low_zone):
        return low_name
    return "{}.{}".format(low_name, low_zone)


def _payload_signature(record):
    payload = {}
    for key, value in record.items():
        if key.startswith("__"):
            continue
        if key in ("override", "disabled", "call", "key"):
            continue
        payload[key] = value
    return json.dumps(payload, sort_keys=True, ensure_ascii=True)


def _record_to_call(record):
    ttl = record.get("ttl")
    ttl_arg = ", TTL({})".format(ttl) if ttl is not None else ""

    rtype = record["type"]
    qname = _shell_quote(record["name"])

    if rtype in _SIMPLE_VALUE_TYPES:
        return "{}({}, {}{})".format(rtype, qname, _shell_quote(record["value"]), ttl_arg)

    if rtype == "MX":
        return "MX({}, {}, {}{})".format(
            qname,
            record["priority"],
            _shell_quote(record["value"]),
            ttl_arg,
        )

    if rtype == "SRV":
        return "SRV({}, {}, {}, {}, {}{})".format(
            qname,
            record["priority"],
            record["weight"],
            record["port"],
            _shell_quote(record["target"]),
            ttl_arg,
        )

    if rtype == "CAA":
        return "CAA({}, {}, {}, {}{})".format(
            qname,
            record["flags"],
            _shell_quote(record["tag"]),
            _shell_quote(record["value"]),
            ttl_arg,
        )

    if "value" not in record:
        raise DNSControlError(
            "Unsupported record type '{}' requires 'value' field".format(rtype)
        )

    return "{}({}, {}{})".format(rtype, qname, _shell_quote(record["value"]), ttl_arg)


def _resolve_group_order(zone_name, zone_data):
    record_groups = zone_data.get("record_groups")
    if not isinstance(record_groups, dict) or not record_groups:
        raise DNSControlError(
            "Zone '{}' must define non-empty 'record_groups' mapping".format(zone_name)
        )

    configured_order = zone_data.get("record_group_order")
    if configured_order is None:
        return sorted(record_groups.keys())

    if not isinstance(configured_order, list):
        raise DNSControlError(
            "Zone '{}': 'record_group_order' must be a list".format(zone_name)
        )

    order = []
    seen = set()
    known_groups = set(record_groups.keys())

    for group_name in configured_order:
        if group_name not in known_groups:
            raise DNSControlError(
                "Zone '{}': group '{}' in record_group_order does not exist".format(
                    zone_name, group_name
                )
            )
        if group_name not in seen:
            seen.add(group_name)
            order.append(group_name)

    for group_name in sorted(record_groups.keys()):
        if group_name not in seen:
            order.append(group_name)

    return order


def _normalize_record(raw, zone_name, default_ttl, group_name, group_index, record_index):
    if not isinstance(raw, dict):
        raise DNSControlError("Zone '{}': record must be mapping".format(zone_name))

    if "name" not in raw:
        raise DNSControlError("Zone '{}': record missing 'name'".format(zone_name))
    if "type" not in raw:
        raise DNSControlError("Zone '{}': record missing 'type'".format(zone_name))

    name = _normalize_name(raw["name"])
    rtype = str(raw["type"]).strip().upper()
    if not rtype:
        raise DNSControlError("Zone '{}': record type must not be empty".format(zone_name))

    ttl = raw.get("ttl", default_ttl)
    if ttl is not None:
        ttl = _as_int(ttl, "ttl")
        if ttl <= 0:
            raise DNSControlError("Zone '{}': ttl must be > 0".format(zone_name))

    record = {
        "name": name,
        "type": rtype,
        "ttl": ttl,
        "override": _as_bool(raw.get("override"), False),
        "disabled": _as_bool(raw.get("disabled"), False),
        "fqdn": _normalize_fqdn(name, zone_name),
        "__group": group_name,
        "__group_index": group_index,
        "__record_index": record_index,
    }

    if record["disabled"]:
        # Disabled records participate in merge semantics (including tombstones)
        # but are never rendered into dnsconfig.js calls.
        record["key"] = "{}|{}".format(record["fqdn"], rtype)
        record["call"] = ""
        return record

    if rtype in _SIMPLE_VALUE_TYPES:
        if "value" not in raw:
            raise DNSControlError(
                "Zone '{}': {} record requires 'value'".format(zone_name, rtype)
            )
        record["value"] = str(raw["value"])

    elif rtype == "MX":
        if "priority" not in raw or "value" not in raw:
            raise DNSControlError(
                "Zone '{}': MX record requires 'priority' and 'value'".format(zone_name)
            )
        record["priority"] = _as_int(raw["priority"], "priority")
        record["value"] = str(raw["value"])

    elif rtype == "SRV":
        required = ("priority", "weight", "port", "target")
        missing = [f for f in required if f not in raw]
        if missing:
            raise DNSControlError(
                "Zone '{}': SRV record missing fields: {}".format(
                    zone_name, ", ".join(missing)
                )
            )
        record["priority"] = _as_int(raw["priority"], "priority")
        record["weight"] = _as_int(raw["weight"], "weight")
        record["port"] = _as_int(raw["port"], "port")
        record["target"] = str(raw["target"])

    elif rtype == "CAA":
        required = ("flags", "tag", "value")
        missing = [f for f in required if f not in raw]
        if missing:
            raise DNSControlError(
                "Zone '{}': CAA record missing fields: {}".format(
                    zone_name, ", ".join(missing)
                )
            )
        record["flags"] = _as_int(raw["flags"], "flags")
        record["tag"] = str(raw["tag"])
        record["value"] = str(raw["value"])

    else:
        if "value" not in raw:
            raise DNSControlError(
                "Zone '{}': record type '{}' requires 'value'".format(zone_name, rtype)
            )
        record["value"] = str(raw["value"])

    record["key"] = "{}|{}".format(record["fqdn"], rtype)
    record["call"] = _record_to_call(record)
    return record


def _prepare_provider(provider_name, provider_data):
    if not isinstance(provider_data, dict):
        raise DNSControlError("Provider '{}' must be a mapping".format(provider_name))

    ptype = str(provider_data.get("type", "")).strip()
    if not ptype:
        raise DNSControlError("Provider '{}': missing 'type'".format(provider_name))

    credentials = provider_data.get("credentials")
    if credentials is None:
        credentials = {}
    if not isinstance(credentials, dict):
        raise DNSControlError("Provider '{}': credentials must be mapping".format(provider_name))

    return {"type": ptype, "credentials": credentials}


def _build_zone_records(zone_name, zone_data, cfg, report):
    provider_name = zone_data.get("provider")
    if not provider_name:
        raise DNSControlError("Zone '{}': missing 'provider'".format(zone_name))
    if provider_name not in cfg["providers"]:
        raise DNSControlError(
            "Zone '{}': provider '{}' is not defined".format(zone_name, provider_name)
        )

    default_ttl = zone_data.get("default_ttl")
    if default_ttl is not None:
        default_ttl = _as_int(default_ttl, "default_ttl")
        if default_ttl <= 0:
            raise DNSControlError("Zone '{}': default_ttl must be > 0".format(zone_name))

    group_order = _resolve_group_order(zone_name, zone_data)
    record_groups = zone_data["record_groups"]

    buckets = OrderedDict()
    records_input = 0

    for group_index, group_name in enumerate(group_order):
        group_data = record_groups[group_name]
        if not isinstance(group_data, dict):
            raise DNSControlError(
                "Zone '{}': group '{}' must be a mapping".format(zone_name, group_name)
            )

        records = group_data.get("records", [])
        if not isinstance(records, list):
            raise DNSControlError(
                "Zone '{}': group '{}': records must be a list".format(
                    zone_name, group_name
                )
            )

        for record_index, raw in enumerate(records):
            records_input += 1
            try:
                rec = _normalize_record(
                    raw,
                    zone_name=zone_name,
                    default_ttl=default_ttl,
                    group_name=group_name,
                    group_index=group_index,
                    record_index=record_index,
                )
            except DNSControlError as exc:
                _add_issue(
                    report,
                    "error",
                    str(exc),
                    zone=zone_name,
                    group=group_name,
                    record_index=record_index,
                )
                continue

            key = rec["key"]
            if key not in buckets:
                buckets[key] = []

            if rec["disabled"] and not rec["override"]:
                _add_issue(
                    report,
                    "info",
                    "Disabled record skipped",
                    zone=zone_name,
                    group=group_name,
                    key=key,
                )
                continue

            if rec["disabled"] and rec["override"]:
                buckets[key] = []
                _add_issue(
                    report,
                    "info",
                    "Disabled override acts as tombstone",
                    zone=zone_name,
                    group=group_name,
                    key=key,
                )
                continue

            if rec["override"]:
                buckets[key] = [rec]
            else:
                buckets[key].append(rec)

    final_records = []
    multi_types = {str(t).upper() for t in cfg.get("multi_value_types", [])}

    for key, records in buckets.items():
        if not records:
            continue

        unique_records = []
        seen = set()
        for rec in records:
            signature = _payload_signature(rec)
            if signature in seen:
                _add_issue(
                    report,
                    "info",
                    "Exact duplicate removed",
                    zone=zone_name,
                    group=rec["__group"],
                    key=key,
                )
                continue
            seen.add(signature)
            unique_records.append(rec)

        records = unique_records
        rtype = records[0]["type"]

        if len(records) > 1 and rtype not in multi_types:
            conflict = {
                "zone": zone_name,
                "key": key,
                "groups": [rec["__group"] for rec in records],
                "records": [rec["call"] for rec in records],
            }
            report["conflicts"].append(conflict)

            message = (
                "Conflict duplicate in zone '{}' for key '{}': {}".format(
                    zone_name, key, ", ".join(conflict["groups"])
                )
            )
            if _as_bool(cfg.get("strict_duplicates"), True):
                _add_issue(report, "error", message, **conflict)
            else:
                _add_issue(report, "warning", message, **conflict)

        final_records.extend(records)

    sanitized = []
    for rec in final_records:
        sanitized.append(
            {
                "name": rec["name"],
                "type": rec["type"],
                "ttl": rec.get("ttl"),
                "call": rec["call"],
                "fqdn": rec["fqdn"],
                "group": rec["__group"],
            }
        )

    return {
        "provider": provider_name,
        "default_ttl": default_ttl,
        "records_input": records_input,
        "final_records": sanitized,
    }


def _finalize_report(report, zones):
    report["stats"]["zones"] = len(zones)
    report["stats"]["records_input"] = sum(
        zone.get("records_input", 0) for zone in zones.values()
    )
    report["stats"]["records_final"] = sum(
        len(zone.get("final_records", [])) for zone in zones.values()
    )
    report["stats"]["conflicts"] = len(report["conflicts"])
    report["stats"]["warnings"] = len(report["warnings"])
    report["stats"]["errors"] = len(report["errors"])


def _load_config(pillar_dnscontrol=None):
    cfg = copy.deepcopy(_DEFAULT_CONFIG)

    if pillar_dnscontrol is None:
        pillar_data = {}
        if "pillar.get" in __salt__:
            pillar_data = __salt__["pillar.get"]("dnscontrol", {})
    else:
        pillar_data = pillar_dnscontrol

    if not isinstance(pillar_data, dict):
        raise DNSControlError("dnscontrol pillar must be a mapping")

    cfg = _deep_merge(cfg, pillar_data)

    if not isinstance(cfg.get("providers"), dict):
        raise DNSControlError("dnscontrol.providers must be a mapping")
    if not isinstance(cfg.get("zones"), dict):
        raise DNSControlError("dnscontrol.zones must be a mapping")

    cfg["strict_duplicates"] = _as_bool(cfg.get("strict_duplicates"), True)
    cfg["fail_on_warnings"] = _as_bool(cfg.get("fail_on_warnings"), True)
    cfg["lock_timeout_sec"] = _as_int(cfg.get("lock_timeout_sec", 120), "lock_timeout_sec")

    return cfg


def build_records(pillar_dnscontrol=None):
    """Build and validate records from pillar configuration."""
    report = _new_report()

    try:
        cfg = _load_config(pillar_dnscontrol=pillar_dnscontrol)
    except DNSControlError as exc:
        _add_issue(report, "error", str(exc))
        _finalize_report(report, {})
        return {"zones": {}, "providers": {}, "report": report, "config": {}}

    providers = OrderedDict()
    for provider_name in sorted(cfg["providers"].keys()):
        try:
            providers[provider_name] = _prepare_provider(
                provider_name, cfg["providers"][provider_name]
            )
        except DNSControlError as exc:
            _add_issue(report, "error", str(exc), provider=provider_name)

    cfg["providers"] = providers

    zones = OrderedDict()
    for zone_name in sorted(cfg["zones"].keys()):
        zone_data = cfg["zones"][zone_name]
        if not isinstance(zone_data, dict):
            _add_issue(
                report,
                "error",
                "Zone '{}' must be a mapping".format(zone_name),
                zone=zone_name,
            )
            continue

        try:
            zones[zone_name] = _build_zone_records(zone_name, zone_data, cfg, report)
        except DNSControlError as exc:
            _add_issue(report, "error", str(exc), zone=zone_name)

    _finalize_report(report, zones)

    return {
        "zones": zones,
        "providers": providers,
        "report": report,
        "config": cfg,
    }


def detect_duplicates(zones=None, opts=None, pillar_dnscontrol=None):
    """Compatibility function. Duplicates are detected during build_records."""
    if zones is None:
        return build_records(pillar_dnscontrol=pillar_dnscontrol)["report"]

    report = _new_report()
    strict_duplicates = True
    multi_types = {"MX", "TXT", "SRV"}

    if isinstance(opts, dict):
        strict_duplicates = _as_bool(opts.get("strict_duplicates"), True)
        if isinstance(opts.get("multi_value_types"), list):
            multi_types = {str(t).upper() for t in opts["multi_value_types"]}

    for zone_name, zone_data in zones.items():
        index = {}
        for rec in zone_data.get("final_records", []):
            key = "{}|{}".format(rec.get("fqdn", rec.get("name", "")), rec.get("type", ""))
            index.setdefault(key, []).append(rec)

        for key, records in index.items():
            if len(records) <= 1:
                continue
            rtype = str(records[0].get("type", "")).upper()
            signatures = {_payload_signature(r) for r in records}
            if len(signatures) == 1:
                continue
            if rtype in multi_types:
                continue

            message = "Conflict duplicate in zone '{}' for key '{}'".format(zone_name, key)
            if strict_duplicates:
                _add_issue(report, "error", message, zone=zone_name, key=key)
            else:
                _add_issue(report, "warning", message, zone=zone_name, key=key)

    _finalize_report(report, zones)
    return report


def _ensure_dir(path, mode):
    os.makedirs(path, exist_ok=True)
    try:
        os.chmod(path, int(str(mode), 8))
    except (TypeError, ValueError):
        os.chmod(path, 0o700)


def _render_dnsconfig_content(zones, providers):
    lines = [
        'var REG_NONE = NewRegistrar("none");',
        "var DSP = NewDnsProvider;",
        "",
    ]

    for provider_name in providers.keys():
        ptype = providers[provider_name]["type"]
        lines.append('var {} = DSP("{}");'.format(provider_name, ptype))

    if providers:
        lines.append("")

    for zone_name in zones.keys():
        zone_data = zones[zone_name]
        lines.append(
            'D("{}", REG_NONE, DnsProvider({}),'.format(
                zone_name, zone_data["provider"]
            )
        )

        records = zone_data.get("final_records", [])
        for idx, rec in enumerate(records):
            suffix = "," if idx < len(records) - 1 else ""
            lines.append("  {}{}".format(rec["call"], suffix))

        lines.append(");")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def _render_creds_content(providers):
    content = OrderedDict()
    for provider_name in providers.keys():
        provider = providers[provider_name]
        entry = OrderedDict()
        entry["TYPE"] = provider["type"]
        for key, value in provider.get("credentials", {}).items():
            entry[str(key)] = str(value)
        content[provider_name] = entry

    return json.dumps(content, indent=2, ensure_ascii=True) + "\n"


def _render_via_salt_templates(config_dir, zones, providers, cfg):
    cp_template = __salt__.get("cp.get_template")
    if cp_template is None:
        return False

    saltenv = cfg.get("saltenv") or __opts__.get("saltenv") or "base"
    template_base = str(cfg.get("template_base", "salt://dnscontrol/templates")).rstrip("/")

    context = {"zones": zones, "providers": providers}

    dns_dest = os.path.join(config_dir, "dnsconfig.js")
    creds_dest = os.path.join(config_dir, "creds.json")

    dns_src = "{}/dnsconfig.js.jinja".format(template_base)
    creds_src = "{}/creds.json.jinja".format(template_base)

    dns_res = cp_template(
        dns_src,
        dns_dest,
        template="jinja",
        saltenv=saltenv,
        context=context,
    )
    creds_res = cp_template(
        creds_src,
        creds_dest,
        template="jinja",
        saltenv=saltenv,
        context=context,
    )

    return bool(dns_res and creds_res)


def render_config(config_dir=None, zones=None, providers=None, pillar_dnscontrol=None):
    """Render dnsconfig.js and creds.json."""
    result = {
        "result": False,
        "comment": "",
        "files": {},
        "report": None,
    }

    build_data = None
    cfg = None

    if zones is None or providers is None:
        build_data = build_records(pillar_dnscontrol=pillar_dnscontrol)
        cfg = build_data["config"]
        zones = build_data["zones"]
        providers = build_data["providers"]
        result["report"] = build_data["report"]
        if build_data["report"]["errors"]:
            result["comment"] = "build_records failed; render skipped"
            return result
    else:
        cfg = _load_config(pillar_dnscontrol=pillar_dnscontrol)

    if config_dir is None:
        config_dir = cfg["config_dir"]

    _ensure_dir(config_dir, cfg.get("config_mode", "0700"))

    dns_path = os.path.join(config_dir, "dnsconfig.js")
    creds_path = os.path.join(config_dir, "creds.json")

    rendered = False
    try:
        rendered = _render_via_salt_templates(config_dir, zones, providers, cfg)
    except Exception:  # pragma: no cover
        rendered = False

    if not rendered:
        dns_content = _render_dnsconfig_content(zones, providers)
        creds_content = _render_creds_content(providers)

        with open(dns_path, "w", encoding="utf-8") as fp:
            fp.write(dns_content)
        with open(creds_path, "w", encoding="utf-8") as fp:
            fp.write(creds_content)

    try:
        os.chmod(creds_path, int(str(cfg.get("creds_mode", "0600")), 8))
    except (TypeError, ValueError):
        os.chmod(creds_path, 0o600)

    result["result"] = True
    result["comment"] = "Rendered dnsconfig.js and creds.json"
    result["files"] = {"dnsconfig": dns_path, "creds": creds_path}

    if build_data is None:
        result["report"] = _new_report()
    return result


def _run_command(command, cwd):
    cmd_runner = __salt__.get("cmd.run_all")
    if cmd_runner:
        ret = cmd_runner(command, cwd=cwd, python_shell=False)
        return {
            "cmd": command,
            "cwd": cwd,
            "retcode": ret.get("retcode", 1),
            "stdout": ret.get("stdout", ""),
            "stderr": ret.get("stderr", ""),
        }

    proc = subprocess.run(
        command.split(),
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )
    return {
        "cmd": command,
        "cwd": cwd,
        "retcode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }


def preview(config_dir=None, pillar_dnscontrol=None):
    """Run `dnscontrol preview` in config_dir."""
    cfg = _load_config(pillar_dnscontrol=pillar_dnscontrol)
    if config_dir is None:
        config_dir = cfg["config_dir"]

    cmd = "{} preview".format(cfg.get("dnscontrol_bin", "dnscontrol"))
    return _run_command(cmd, cwd=config_dir)


def push(config_dir=None, pillar_dnscontrol=None):
    """Run `dnscontrol push` in config_dir."""
    cfg = _load_config(pillar_dnscontrol=pillar_dnscontrol)
    if config_dir is None:
        config_dir = cfg["config_dir"]

    cmd = "{} push".format(cfg.get("dnscontrol_bin", "dnscontrol"))
    return _run_command(cmd, cwd=config_dir)


def _preview_has_changes(preview_result):
    text = "{}\n{}".format(
        preview_result.get("stdout", ""), preview_result.get("stderr", "")
    ).lower()

    no_change_markers = [
        "no changes",
        "0 changes",
        "nothing to do",
        "all records are already correct",
    ]
    return not any(marker in text for marker in no_change_markers)


def _lock_file(lock_path, timeout_sec):
    if fcntl is None:
        # No reliable lock primitive on this platform, still keep file for visibility.
        lock_dir = os.path.dirname(lock_path)
        if lock_dir:
            os.makedirs(lock_dir, exist_ok=True)
        return open(lock_path, "a+", encoding="utf-8")

    lock_dir = os.path.dirname(lock_path)
    if lock_dir:
        os.makedirs(lock_dir, exist_ok=True)

    fd = open(lock_path, "a+", encoding="utf-8")
    deadline = time.time() + max(timeout_sec, 0)

    while True:
        try:
            fcntl.flock(fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            return fd
        except OSError as exc:
            if exc.errno not in (errno.EACCES, errno.EAGAIN):
                fd.close()
                raise
            if time.time() >= deadline:
                fd.close()
                raise LockTimeoutError(
                    "Timed out acquiring lock '{}'".format(lock_path)
                )
            time.sleep(0.2)


def _unlock_file(fd):
    if fd is None:
        return
    try:
        if fcntl is not None:
            fcntl.flock(fd.fileno(), fcntl.LOCK_UN)
    finally:
        fd.close()


def apply(config_dir=None, test=False, pillar_dnscontrol=None):
    """End-to-end pipeline: build, validate, render, preview, optional push."""
    result = {
        "result": False,
        "changes": {},
        "comment": "",
        "report": None,
    }

    try:
        cfg = _load_config(pillar_dnscontrol=pillar_dnscontrol)
    except DNSControlError as exc:
        result["comment"] = str(exc)
        result["report"] = _new_report()
        _add_issue(result["report"], "error", str(exc))
        return result

    if config_dir is None:
        config_dir = cfg["config_dir"]

    lock_fd = None
    try:
        lock_fd = _lock_file(cfg["lock_file"], cfg["lock_timeout_sec"])

        build_data = build_records(pillar_dnscontrol=cfg)
        report = build_data["report"]
        result["report"] = report

        if report["errors"]:
            result["comment"] = "Validation failed before render"
            return result

        render_result = render_config(
            config_dir=config_dir,
            zones=build_data["zones"],
            providers=build_data["providers"],
            pillar_dnscontrol=cfg,
        )
        if not render_result.get("result"):
            result["comment"] = render_result.get("comment", "render_config failed")
            return result

        result["changes"]["rendered_files"] = render_result["files"]

        preview_result = preview(config_dir=config_dir, pillar_dnscontrol=cfg)
        result["changes"]["preview"] = {
            "retcode": preview_result["retcode"],
            "stdout": preview_result["stdout"],
            "stderr": preview_result["stderr"],
        }
        if preview_result["retcode"] != 0:
            result["comment"] = "dnscontrol preview failed"
            return result

        has_changes = _preview_has_changes(preview_result)
        result["changes"]["would_push"] = has_changes

        if test:
            result["result"] = True
            result["comment"] = "Preview completed in test mode; push skipped"
            return result

        if report["warnings"] and cfg["fail_on_warnings"]:
            result["comment"] = "Warnings detected and fail_on_warnings=true; push blocked"
            return result

        if not has_changes:
            result["result"] = True
            result["comment"] = "No DNS changes detected; push skipped"
            return result

        push_result = push(config_dir=config_dir, pillar_dnscontrol=cfg)
        result["changes"]["push"] = {
            "retcode": push_result["retcode"],
            "stdout": push_result["stdout"],
            "stderr": push_result["stderr"],
        }
        if push_result["retcode"] != 0:
            result["comment"] = "dnscontrol push failed"
            return result

        result["result"] = True
        result["comment"] = "Preview and push completed successfully"
        return result

    except LockTimeoutError as exc:
        report = _new_report()
        _add_issue(report, "error", str(exc))
        result["report"] = report
        result["comment"] = str(exc)
        return result
    except Exception as exc:  # pragma: no cover
        report = result.get("report") or _new_report()
        _add_issue(report, "error", "Unhandled exception: {}".format(exc))
        result["report"] = report
        result["comment"] = "Unhandled exception during dnscontrol.apply"
        return result
    finally:
        _unlock_file(lock_fd)
