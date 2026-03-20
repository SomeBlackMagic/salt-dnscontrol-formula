# DNSControl + SaltStack Integration (Salt as Source of Truth, Record Groups Model) - v3.1

## Goal
Salt Pillar is the single source of truth for DNS.
DNSControl is used only as an execution engine (`preview` + `push`).

## Scope
In scope:
- data model in Pillar
- deterministic merge of record groups
- duplicate/conflict detection
- rendering `dnsconfig.js` and `creds.json`
- orchestration via Salt module/state

Out of scope:
- DNS business ownership process
- provider onboarding process outside this formula

---

## Architecture

Salt Pillar -> Data (`providers`, `zones`, `record_groups`)  
Salt Module -> Build + Normalize + Validate + Detect conflicts  
Salt Templates -> Generate `dnsconfig.js` / `creds.json`  
DNSControl -> `preview` / `push`  
Providers -> DNS API  

---

## Pillar Schema

```yaml
dnscontrol:
  strict_duplicates: true          # true: conflict => fail, false: conflict => warning
  fail_on_warnings: true           # if true, warnings also block push
  multi_value_types: [MX, TXT, SRV]
  config_dir: /etc/dnscontrol
  lock_file: /var/lock/dnscontrol.lock
  lock_timeout_sec: 120

  providers:
    cloudflare_main:
      type: cloudflare
      credentials:
        api_token: "SECRET"

  zones:
    example.com:
      provider: cloudflare_main
      default_ttl: 300
      record_group_order: [base, app, overrides]
      record_groups:
        base:
          records:
            - name: www
              type: A
              value: 1.1.1.1
        app:
          records:
            - name: api
              type: A
              value: 2.2.2.2
        overrides:
          records:
            - name: www
              type: A
              value: 9.9.9.9
              override: true
```

Required:
- `providers.<provider_name>.type`
- `zones.<zone>.provider`
- `zones.<zone>.record_groups`
- `record_groups.<group>.records[]`
- per record: `name`, `type` and required type-specific fields

---

## Record Model

`record_groups` is a dictionary for merge-safe composition across Pillars.
`records` remains a list for author-friendly DSL.
`final_records` is generated internally by the execution module.

Common fields:
- `name` (string): `@`, `*`, `www`, `api`, etc.
- `type` (string, upper-case)
- `ttl` (int, optional): fallback to `zone.default_ttl` if absent
- `override` (bool, default `false`)
- `disabled` (bool, default `false`)

Type-specific required fields:
- `A`, `AAAA`, `CNAME`, `NS`, `PTR`: `value`
- `MX`: `priority`, `value`
- `TXT`: `value`
- `SRV`: `priority`, `weight`, `port`, `target`
- `CAA`: `flags`, `tag`, `value`

---

## Normalization Rules

Before merge:
1. `type` -> upper-case.
2. `name` trimmed; `@` means zone apex.
3. Default `ttl` is applied if missing.
4. Record gets metadata:
   - `__group`
   - `__group_index`
   - `__record_index`
5. Canonical merge key is:
   - `key = (fqdn, type)` where `fqdn = normalize(name, zone)`

---

## Merge Algorithm (Deterministic)

1. Resolve group order:
   - use `record_group_order` if provided
   - otherwise lexical sort of `record_groups` keys
2. Iterate groups in resolved order and records by list order.
3. Normalize each record.
4. Handle disabled records:
   - `disabled: true` and `override: false` -> skip record
   - `disabled: true` and `override: true` -> tombstone:
     clear bucket for the same key and emit nothing
5. Handle active records:
   - `override: true` -> replace bucket for same key with this record
   - otherwise append to bucket for same key
6. Build `final_records` from buckets preserving stable order.
7. Deduplicate exact duplicates (same normalized payload) with `INFO` log.

Result:
- deterministic output
- idempotent rendering order

---

## Override Rules

`override: true` means "replace previous records for the same key `(fqdn, type)`".

Rules:
- override only affects records seen earlier in resolved order
- if multiple overrides exist, later one wins
- if several active records remain for a single-value type, this is a conflict

---

## Duplicate and Conflict Detection

Definitions:
- exact duplicate: same key and same payload
- conflict duplicate: same key, different payload, not allowed by type policy

Policy:
- allowed multi-value types are defined by `dnscontrol.multi_value_types`
- default: `[MX, TXT, SRV]`

Detection steps:
1. Build index `key -> records[]` from `final_records`.
2. For each key with multiple records:
   - if all payloads equal -> exact duplicate (dedupe + info)
   - if `type` in `multi_value_types` -> allowed
   - else -> conflict
3. Conflict handling:
   - `strict_duplicates: true` -> error
   - `strict_duplicates: false` -> warning
4. If `fail_on_warnings: true`, warnings also block `push`.

---

## Logging Format

```
[DNS CONFLICT]
zone=example.com key=www_A strict=true
groups=base,app
records=["A www 1.1.1.1","A www 2.2.2.2"]
action=fail
```

For relaxed mode:
```
action=warn
```

---

## Templates

### `dnsconfig.js` (provider binding is mandatory)

```jinja
{% raw %}
var REG_NONE = NewRegistrar("none");
var DSP = NewDnsProvider;

{% for provider_name, provider in pillar["dnscontrol"]["providers"].items() %}
var {{ provider_name }} = DSP("{{ provider.type }}");
{% endfor %}

{% for zone, data in zones.items() %}
D("{{ zone }}", REG_NONE, DnsProvider({{ data.provider }}),
{% for r in data.final_records %}
  {{ r.call }},
{% endfor %}
);
{% endfor %}
{% endraw %}
```

Notes:
- `data.provider` must be the provider variable name from Pillar.
- `r.call` is generated by module (`A(...)`, `MX(...)`, `SRV(...)`, etc.) to avoid type-specific logic in Jinja.

### `creds.json`

```jinja
{
{% for provider_name, provider in pillar["dnscontrol"]["providers"].items() %}
  "{{ provider_name }}": {
    "TYPE": "{{ provider.type }}"{% for k, v in provider.credentials.items() %},
    "{{ k }}": "{{ v }}"{% endfor %}
  }{% if not loop.last %},{% endif %}
{% endfor %}
}
```

---

## Execution Module Contract

Required functions:
- `build_records(pillar_dnscontrol) -> {zones, report}`
- `detect_duplicates(zones, opts) -> report`
- `render_config(config_dir, zones, providers) -> files`
- `preview(config_dir) -> result`
- `push(config_dir) -> result`

Behavior:
- `preview` always runs before `push`
- `push` runs only when:
  - no errors
  - and no warnings when `fail_on_warnings: true`

---

## State Module Contract

```yaml
dns_apply:
  dnscontrol.managed:
    - config_dir: /etc/dnscontrol
    - test: false
```

State behavior:
- acquires lock
- builds and validates config
- renders files
- runs `dnscontrol preview`
- runs `dnscontrol push` only if allowed by policy
- releases lock in `finally`

Idempotency:
- if preview reports no changes, state returns `result=True` with no push

---

## Workflow

Pillar -> Build/Normalize -> Merge -> Detect conflicts -> Render -> Preview -> Push

---

## Security

- secrets are stored in encrypted Pillar (Vault/GPG/SDB)
- secrets are never committed to git
- rendered `creds.json` file permissions: `0600`
- config directory permissions: `0700` (or stricter per host policy)

---

## Locking

Default:
```
/var/lock/dnscontrol.lock
```

Rules:
- lock is mandatory for both `preview` and `push` pipeline
- lock acquisition timeout is `lock_timeout_sec`
- timeout/failure to lock -> state failure

---

## Acceptance Criteria (Done)

1. Salt Pillar is the only source of DNS records and provider mapping.
2. Zone-level provider is correctly bound in generated `dnsconfig.js`.
3. Merge output is deterministic for equal input (same record order every run).
4. `override` behavior is deterministic and covered by tests.
5. `disabled` and tombstone semantics are implemented and tested.
6. Duplicate/conflict policy works in both strict and relaxed modes.
7. `fail_on_warnings` blocks push when enabled.
8. State is idempotent: second run with unchanged Pillar does not push.
9. Locking prevents concurrent apply.
10. Secrets are not exposed in git and rendered with restricted permissions.

---

## Minimum Test Matrix

- merge across two Pillars with overlapping groups
- two records with same key in non-multi type -> conflict
- same case with `strict_duplicates: false` -> warning behavior
- override replaces previous records
- disabled tombstone removes inherited record
- provider reference missing in zone -> validation error
- preview no-diff -> push skipped
