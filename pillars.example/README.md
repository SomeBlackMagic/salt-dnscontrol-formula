# Pillar Examples for `salt-dnscontrol-formula`

Examples in this directory use the `dnscontrol` pillar schema from `docs/dnscontrol_saltstack_tz_v3.md` (v3.1).

Files:
- `01-basic.sls` - minimal working setup with one provider and one zone.
- `02-override-and-tombstone.sls` - deterministic group ordering, `override`, and disabled tombstone.
- `03-multi-value-and-relaxed.sls` - relaxed duplicate policy and allowed multi-value records.
- `04-strict-conflict.sls` - strict duplicate conflict example that should fail validation.

How to use:
1. Copy one file content into your pillar tree (or include it).
2. Adjust provider credentials and zone names.
3. Apply state: `salt '<minion>' state.apply dnscontrol`.
