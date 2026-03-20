"""dnscontrol execution helpers for Salt."""

import copy
import errno
import json
import os
import re
import shlex
import shutil
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
    "dnscontrol_bin": "/usr/local/bin/dnscontrol",
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
_ANSI_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


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

    creds_key = str(provider_data.get("creds_key", ptype)).strip()
    if not creds_key:
        raise DNSControlError("Provider '{}': creds_key must not be empty".format(provider_name))

    return {"type": ptype, "creds_key": creds_key, "credentials": credentials}


def _validate_provider_creds_keys(providers, report):
    seen = {}
    for provider_name in providers.keys():
        provider = providers[provider_name]
        creds_key = str(provider.get("creds_key", provider.get("type", "")))
        signature = json.dumps(
            {
                "type": provider.get("type"),
                "credentials": provider.get("credentials", {}),
            },
            sort_keys=True,
            ensure_ascii=True,
        )

        if creds_key not in seen:
            seen[creds_key] = {
                "provider_name": provider_name,
                "signature": signature,
            }
            continue

        previous = seen[creds_key]
        if previous["signature"] != signature:
            _add_issue(
                report,
                "error",
                "Multiple providers map to creds key '{}' with different credentials".format(
                    creds_key
                ),
                provider=provider_name,
                creds_key=creds_key,
                clashes_with=previous["provider_name"],
            )
        else:
            _add_issue(
                report,
                "info",
                "Multiple providers share the same creds key '{}'".format(creds_key),
                provider=provider_name,
                creds_key=creds_key,
                same_as=previous["provider_name"],
            )


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
    _validate_provider_creds_keys(providers, report)

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
        creds_key = providers[provider_name].get("creds_key", providers[provider_name]["type"])
        lines.append('var {} = DSP("{}");'.format(provider_name, creds_key))

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
        creds_key = provider.get("creds_key", provider["type"])
        entry = OrderedDict()
        entry["TYPE"] = provider["type"]
        for key, value in provider.get("credentials", {}).items():
            entry[str(key)] = str(value)
        if creds_key in content and content[creds_key] != entry:
            raise DNSControlError(
                "Conflicting credentials for creds key '{}' from provider '{}'".format(
                    creds_key, provider_name
                )
            )
        content[creds_key] = entry

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
        try:
            dns_content = _render_dnsconfig_content(zones, providers)
            creds_content = _render_creds_content(providers)
        except DNSControlError as exc:
            result["comment"] = str(exc)
            return result

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
        try:
            ret = cmd_runner(command, cwd=cwd, python_shell=False)
            return {
                "cmd": command,
                "cwd": cwd,
                "retcode": ret.get("retcode", 1),
                "stdout": ret.get("stdout", ""),
                "stderr": ret.get("stderr", ""),
            }
        except Exception as exc:  # pragma: no cover
            return {
                "cmd": command,
                "cwd": cwd,
                "retcode": 1,
                "stdout": "",
                "stderr": "cmd.run_all failed: {}".format(exc),
            }

    try:
        argv = shlex.split(command)
    except Exception:
        argv = command.split()

    try:
        proc = subprocess.run(
            argv,
            cwd=cwd,
            capture_output=True,
            text=True,
            check=False,
        )
    except Exception as exc:  # pragma: no cover
        return {
            "cmd": command,
            "cwd": cwd,
            "retcode": 1,
            "stdout": "",
            "stderr": "subprocess execution failed: {}".format(exc),
        }

    return {
        "cmd": command,
        "cwd": cwd,
        "retcode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }


def _strip_ansi(text):
    if not text:
        return ""
    return _ANSI_RE.sub("", str(text))


def _resolve_binary_path(binary_name):
    if binary_name is None:
        return None

    binary = str(binary_name).strip()
    if not binary:
        return None

    if os.path.isabs(binary) or os.path.sep in binary:
        return os.path.expanduser(binary)

    cmd_which = __salt__.get("cmd.which")
    if cmd_which:
        try:
            resolved = cmd_which(binary)
            if resolved:
                return resolved
        except Exception:  # pragma: no cover
            pass

    return shutil.which(binary)


def _validate_dnscontrol_binary(binary_name):
    resolved = _resolve_binary_path(binary_name)
    if not resolved:
        return False, "dnscontrol binary not found: '{}'".format(binary_name), None

    if not os.path.exists(resolved):
        return False, "dnscontrol binary path does not exist: '{}'".format(resolved), resolved

    if not os.path.isfile(resolved):
        return False, "dnscontrol binary path is not a file: '{}'".format(resolved), resolved

    if not os.access(resolved, os.X_OK):
        return False, "dnscontrol binary is not executable (+x missing): '{}'".format(resolved), resolved

    check_cmd = "{} --version".format(shlex.quote(resolved))
    check = _run_command(check_cmd, cwd="/")
    if check.get("retcode", 1) != 0:
        details = (check.get("stderr") or check.get("stdout") or "").strip()
        if details:
            return (
                False,
                "dnscontrol binary is not runnable: {} ({})".format(resolved, details),
                resolved,
            )
        return False, "dnscontrol binary is not runnable: '{}'".format(resolved), resolved

    return True, "", resolved


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

    binary_ok, binary_msg, binary_path = _validate_dnscontrol_binary(
        cfg.get("dnscontrol_bin", "dnscontrol")
    )
    if not binary_ok:
        report = _new_report()
        _add_issue(report, "error", binary_msg)
        result["report"] = report
        result["comment"] = binary_msg
        return result

    result["changes"]["binary"] = {"path": binary_path, "check": "ok"}

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
        preview_stdout_clean = _strip_ansi(preview_result.get("stdout", ""))
        preview_stderr_clean = _strip_ansi(preview_result.get("stderr", ""))
        result["changes"]["preview"] = {
            "retcode": preview_result["retcode"],
            "stdout": preview_result["stdout"],
            "stderr": preview_result["stderr"],
            "stdout_clean": preview_stdout_clean,
            "stderr_clean": preview_stderr_clean,
        }
        if preview_result["retcode"] != 0:
            details = preview_stderr_clean or preview_stdout_clean or ""
            details = details.strip()
            if details:
                result["comment"] = "dnscontrol preview failed: {}".format(details)
            else:
                result["comment"] = "dnscontrol preview failed"
            return result

        has_changes = _preview_has_changes(preview_result)
        result["changes"]["would_push"] = has_changes

        if test:
            result["result"] = True
            result["comment"] = "Preview completed in test mode; push skipped"
            preview_text = preview_stdout_clean.strip()
            if preview_text:
                result["comment"] += "\n\n{}".format(preview_text)
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
            details = _strip_ansi(push_result.get("stderr") or push_result.get("stdout") or "")
            details = details.strip()
            if details:
                result["comment"] = "dnscontrol push failed: {}".format(details)
            else:
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
        result["comment"] = "Unhandled exception during dnscontrol.apply: {}".format(exc)
        return result
    finally:
        _unlock_file(lock_fd)


def _prepare_payload(providers, zones, report):
    if not isinstance(providers, dict):
        raise DNSControlError("'providers' must be a mapping")
    if not isinstance(zones, dict):
        raise DNSControlError("'zones' must be a mapping")

    prepared_providers = OrderedDict()
    for provider_name in sorted(providers.keys()):
        try:
            prepared_providers[provider_name] = _prepare_provider(
                provider_name, providers[provider_name]
            )
        except DNSControlError as exc:
            _add_issue(report, "error", str(exc), provider=provider_name)

    _validate_provider_creds_keys(prepared_providers, report)

    prepared_zones = OrderedDict()
    for zone_name in sorted(zones.keys()):
        zone_data = zones[zone_name]
        if not isinstance(zone_data, dict):
            _add_issue(
                report,
                "error",
                "Zone '{}' payload must be a mapping".format(zone_name),
                zone=zone_name,
            )
            continue

        provider_name = zone_data.get("provider")
        if not provider_name:
            _add_issue(
                report,
                "error",
                "Zone '{}' payload missing 'provider'".format(zone_name),
                zone=zone_name,
            )
            continue
        if provider_name not in prepared_providers:
            _add_issue(
                report,
                "error",
                "Zone '{}': provider '{}' is not defined".format(zone_name, provider_name),
                zone=zone_name,
            )
            continue

        records = zone_data.get("records")
        if records is None:
            records = zone_data.get("final_records", [])
        if not isinstance(records, list):
            _add_issue(
                report,
                "error",
                "Zone '{}': payload records must be a list".format(zone_name),
                zone=zone_name,
            )
            continue

        default_ttl = zone_data.get("default_ttl")
        if default_ttl is not None:
            try:
                default_ttl = _as_int(default_ttl, "default_ttl")
            except DNSControlError as exc:
                _add_issue(report, "error", str(exc), zone=zone_name)
                continue

        rendered_records = []
        for idx, raw in enumerate(records):
            if not isinstance(raw, dict):
                _add_issue(
                    report,
                    "error",
                    "Zone '{}': record index {} must be a mapping".format(zone_name, idx),
                    zone=zone_name,
                    record_index=idx,
                )
                continue

            # Support payload where records are already rendered as {"call": "..."}.
            if raw.get("call"):
                rendered_records.append(
                    {
                        "name": raw.get("name", "@"),
                        "type": str(raw.get("type", "RAW")).upper(),
                        "ttl": raw.get("ttl"),
                        "call": str(raw["call"]),
                        "fqdn": raw.get("fqdn", ""),
                        "group": raw.get("group", "payload"),
                    }
                )
                continue

            try:
                rec = _normalize_record(
                    raw,
                    zone_name=zone_name,
                    default_ttl=default_ttl,
                    group_name="payload",
                    group_index=0,
                    record_index=idx,
                )
            except DNSControlError as exc:
                _add_issue(
                    report,
                    "error",
                    str(exc),
                    zone=zone_name,
                    record_index=idx,
                )
                continue

            if rec.get("disabled"):
                continue

            rendered_records.append(
                {
                    "name": rec["name"],
                    "type": rec["type"],
                    "ttl": rec.get("ttl"),
                    "call": rec["call"],
                    "fqdn": rec["fqdn"],
                    "group": "payload",
                }
            )

        prepared_zones[zone_name] = {
            "provider": provider_name,
            "default_ttl": default_ttl,
            "records_input": len(records),
            "final_records": rendered_records,
        }

    _finalize_report(report, prepared_zones)
    return prepared_providers, prepared_zones


def apply_payload(
    zones=None,
    providers=None,
    warnings=None,
    fail_on_warnings=True,
    config_dir=None,
    dnscontrol_bin=None,
    lock_file=None,
    lock_timeout_sec=None,
    creds_mode=None,
    config_mode=None,
    template_base=None,
    saltenv=None,
    test=False,
):
    """Render and execute dnscontrol from pre-built payload (zones/providers)."""
    if zones is None or providers is None:
        return apply(config_dir=config_dir, test=test)

    result = {
        "result": False,
        "changes": {},
        "comment": "",
        "report": _new_report(),
    }

    try:
        cfg = _load_config()
    except DNSControlError as exc:
        _add_issue(result["report"], "error", str(exc))
        result["comment"] = str(exc)
        return result

    if config_dir is not None:
        cfg["config_dir"] = config_dir
    if dnscontrol_bin is not None:
        cfg["dnscontrol_bin"] = str(dnscontrol_bin)
    if lock_file is not None:
        cfg["lock_file"] = str(lock_file)
    if lock_timeout_sec is not None:
        try:
            cfg["lock_timeout_sec"] = _as_int(lock_timeout_sec, "lock_timeout_sec")
        except DNSControlError as exc:
            _add_issue(result["report"], "error", str(exc))
            result["comment"] = str(exc)
            return result
    if creds_mode is not None:
        cfg["creds_mode"] = str(creds_mode)
    if config_mode is not None:
        cfg["config_mode"] = str(config_mode)
    if template_base is not None:
        cfg["template_base"] = str(template_base)
    if saltenv is not None:
        cfg["saltenv"] = str(saltenv)

    cfg["fail_on_warnings"] = _as_bool(fail_on_warnings, True)

    if warnings:
        if not isinstance(warnings, list):
            warnings = [str(warnings)]
        for warning in warnings:
            _add_issue(result["report"], "warning", str(warning))

    binary_ok, binary_msg, binary_path = _validate_dnscontrol_binary(
        cfg.get("dnscontrol_bin", "dnscontrol")
    )
    if not binary_ok:
        _add_issue(result["report"], "error", binary_msg)
        result["comment"] = binary_msg
        return result

    result["changes"]["binary"] = {"path": binary_path, "check": "ok"}

    lock_fd = None
    try:
        lock_fd = _lock_file(cfg["lock_file"], cfg["lock_timeout_sec"])

        payload_providers, payload_zones = _prepare_payload(
            providers=providers,
            zones=zones,
            report=result["report"],
        )
        if result["report"]["errors"]:
            result["comment"] = "Invalid dnscontrol payload"
            return result

        render_result = render_config(
            config_dir=cfg["config_dir"],
            zones=payload_zones,
            providers=payload_providers,
            pillar_dnscontrol=cfg,
        )
        if not render_result.get("result"):
            result["comment"] = render_result.get("comment", "render_config failed")
            return result
        result["changes"]["rendered_files"] = render_result["files"]

        preview_result = _run_command(
            "{} preview".format(cfg.get("dnscontrol_bin", "dnscontrol")),
            cwd=cfg["config_dir"],
        )
        preview_stdout_clean = _strip_ansi(preview_result.get("stdout", ""))
        preview_stderr_clean = _strip_ansi(preview_result.get("stderr", ""))
        result["changes"]["preview"] = {
            "retcode": preview_result["retcode"],
            "stdout": preview_result["stdout"],
            "stderr": preview_result["stderr"],
            "stdout_clean": preview_stdout_clean,
            "stderr_clean": preview_stderr_clean,
        }
        if preview_result["retcode"] != 0:
            details = preview_stderr_clean or preview_stdout_clean or ""
            details = details.strip()
            if details:
                result["comment"] = "dnscontrol preview failed: {}".format(details)
            else:
                result["comment"] = "dnscontrol preview failed"
            return result

        has_changes = _preview_has_changes(preview_result)
        result["changes"]["would_push"] = has_changes

        if test:
            result["result"] = True
            result["comment"] = "Preview completed in test mode; push skipped"
            preview_text = preview_stdout_clean.strip()
            if preview_text:
                result["comment"] += "\n\n{}".format(preview_text)
            return result

        if result["report"]["warnings"] and cfg["fail_on_warnings"]:
            result["comment"] = "Warnings detected and fail_on_warnings=true; push blocked"
            return result

        if not has_changes:
            result["result"] = True
            result["comment"] = "No DNS changes detected; push skipped"
            return result

        push_result = _run_command(
            "{} push".format(cfg.get("dnscontrol_bin", "dnscontrol")),
            cwd=cfg["config_dir"],
        )
        result["changes"]["push"] = {
            "retcode": push_result["retcode"],
            "stdout": push_result["stdout"],
            "stderr": push_result["stderr"],
        }
        if push_result["retcode"] != 0:
            details = _strip_ansi(push_result.get("stderr") or push_result.get("stdout") or "")
            details = details.strip()
            if details:
                result["comment"] = "dnscontrol push failed: {}".format(details)
            else:
                result["comment"] = "dnscontrol push failed"
            return result

        result["result"] = True
        result["comment"] = "Preview and push completed successfully"
        return result

    except LockTimeoutError as exc:
        _add_issue(result["report"], "error", str(exc))
        result["comment"] = str(exc)
        return result
    except Exception as exc:  # pragma: no cover
        _add_issue(result["report"], "error", "Unhandled exception: {}".format(exc))
        result["comment"] = "Unhandled exception during dnscontrol.apply_payload: {}".format(
            exc
        )
        return result
    finally:
        _unlock_file(lock_fd)
