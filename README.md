# salt-dnscontrol-formula

Salt formula for managing DNS via DNSControl, with Salt Pillar as the source of truth.

## What this formula does

- reads DNS data from `pillar:dnscontrol`
- performs deterministic merge of `record_groups` in `apply.sls` (Jinja layer)
- applies `override` and `disabled` semantics (including tombstone via `disabled: true` + `override: true`)
- detects duplicates/conflicts (strict/relaxed modes)
- renders `dnsconfig.js` and `creds.json`
- runs `dnscontrol preview`, then `dnscontrol push` (when policy allows)
- uses file lock to prevent concurrent apply runs

## Project structure

- `init.sls` - formula entry point
- `install.sls` - package installation and directory preparation
- `apply.sls` - builds merged payload and invokes `dnscontrol.managed`
- `_modules/dnscontrol.py` - execution logic: render config + `preview/push` against provider
- `_states/dnscontrol.py` - state wrapper `managed`
- `templates/` - `dnsconfig.js.jinja` and `creds.json.jinja`
- `pillars.example/` - ready-to-use pillar examples
- `docs/dnscontrol_saltstack_tz_v3.md` - technical spec v3.1

## Requirements

- Salt 3006-3009
- internet access from minion to download release archive (default install mode)
- provider API credentials configured in Pillar

## Quick start

1. Place the formula in your Salt fileserver as `dnscontrol`.
2. Add pillar config (you can start from `pillars.example/*.sls`).
3. Apply the state:

```bash
salt '<minion>' state.apply dnscontrol
```

For dry-run:

```bash
salt '<minion>' state.apply dnscontrol test=True
```

## Minimal Pillar

```yaml
dnscontrol:
  enable: true

  strict_duplicates: true
  fail_on_warnings: true
  multi_value_types: [MX, TXT, SRV]

  install:
    enabled: true
    method: archive
    bin_path: /usr/local/bin/dnscontrol
    archive:
      url: https://github.com/StackExchange/dnscontrol/releases/download/v4.36.1/dnscontrol_4.36.1_linux_amd64.tar.gz
      version: "4.36.1"
      extract_root: /opt/dnscontrol
      binary_name: dnscontrol

  config_dir: /etc/dnscontrol
  lock_file: /var/lock/dnscontrol.lock
  lock_timeout_sec: 120

  providers:
    cloudflare_main:
      type: cloudflare
      credentials:
        api_token: "REPLACE_ME"

  zones:
    example.com:
      provider: cloudflare_main
      default_ttl: 300
      record_group_order: [base, overrides]
      record_groups:
        base:
          records:
            - name: www
              type: A
              value: 1.1.1.1
        overrides:
          records:
            - name: www
              type: A
              value: 9.9.9.9
              override: true
```

## Key `dnscontrol` fields

- `enable` - enables/disables formula states
- `install.enabled` - enables/disables binary installation step; directory setup still runs
- `install.method` - `archive` (default) or `package`
- `install.bin_path` - symlink path to active binary (default `/usr/local/bin/dnscontrol`)
- `install.package_name` - package name used only when `install.method: package`
- `install.archive.url` - URL to `.tar.gz` DNSControl release archive
- `install.archive.version` - release version used in install path under `install.archive.extract_root`
- `install.archive.extract_root` - base directory for extracted versions (default `/opt/dnscontrol`)
- `install.archive.binary_name` - binary filename inside extracted archive (default `dnscontrol`)
- `install.archive.source_hash` - optional checksum for archive verification
- `dnscontrol_bin` - optional runtime override for `preview/push` command path
- `config_dir` - output directory for `dnsconfig.js` and `creds.json`
- `strict_duplicates` - `true`: conflict = error, `false`: conflict = warning
- `fail_on_warnings` - blocks `push` when warnings are present
- `multi_value_types` - record types where multiple values per key are allowed
- `providers.*.type` and `providers.*.credentials`
- `zones.*.provider`, `zones.*.record_groups`, `zones.*.record_group_order`

## Supported record types

- `A`, `AAAA`, `CNAME`, `NS`, `PTR`, `TXT` (`value`)
- `MX` (`priority`, `value`)
- `SRV` (`priority`, `weight`, `port`, `target`)
- `CAA` (`flags`, `tag`, `value`)

## Examples

See `pillars.example/`:
- `01-basic.sls`
- `02-override-and-tombstone.sls`
- `03-multi-value-and-relaxed.sls`
- `04-strict-conflict.sls`
- `05-custom-archive-source.sls`

## Limitations

- Full end-to-end verification requires real `dnscontrol` binary and provider API access.
- "No changes" detection after `preview` is based on common DNSControl output markers.
- Archive extraction assumes the binary is available as `<install.archive.extract_root>/<install.archive.version>/<install.archive.binary_name>`.
