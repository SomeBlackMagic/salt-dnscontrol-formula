# salt-dnscontrol-formula

Salt formula for managing DNS via DNSControl, with Salt Pillar as the source of truth.

## What this formula does

- reads DNS data from `pillar:dnscontrol`
- performs deterministic merge of `record_groups`
- applies `override` and `disabled` semantics (including tombstone via `disabled: true` + `override: true`)
- detects duplicates/conflicts (strict/relaxed modes)
- renders `dnsconfig.js` and `creds.json`
- runs `dnscontrol preview`, then `dnscontrol push` (when policy allows)
- uses file lock to prevent concurrent apply runs

## Project structure

- `init.sls` - formula entry point
- `install.sls` - package installation and directory preparation
- `apply.sls` - invokes state `dnscontrol.managed`
- `_modules/dnscontrol.py` - build/validate/render/preview/push/apply logic
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
  install_method: archive

  strict_duplicates: true
  fail_on_warnings: true
  multi_value_types: [MX, TXT, SRV]

  archive_url: https://github.com/StackExchange/dnscontrol/releases/download/v4.36.1/dnscontrol_4.36.1_linux_amd64.tar.gz
  archive_version: "4.36.1"
  archive_extract_root: /opt/dnscontrol
  archive_binary_name: dnscontrol
  bin_path: /usr/local/bin/dnscontrol
  dnscontrol_bin: /usr/local/bin/dnscontrol

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
- `install_method` - `archive` (default) or `package`
- `archive_url` - URL to `.tar.gz` DNSControl release archive
- `archive_version` - release version, used in install path under `archive_extract_root`
- `archive_extract_root` - base directory for extracted versions (default `/opt/dnscontrol`)
- `archive_binary_name` - binary filename inside extracted archive (default `dnscontrol`)
- `bin_path` - symlink path to active binary (default `/usr/local/bin/dnscontrol`)
- `archive_source_hash` - optional checksum for archive verification
- `package_name` - package name used only when `install_method: package`
- `dnscontrol_bin` - binary path used for `preview/push` execution
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
- Archive extraction assumes the binary is available as `<archive_extract_root>/<archive_version>/<archive_binary_name>`.
