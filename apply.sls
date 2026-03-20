include:
  - .install

{% from tpldir ~ "/map.jinja" import dnscontrol with context %}
{% set install = dnscontrol.get('install', {}) %}
{% set dnscontrol_bin = dnscontrol.get('dnscontrol_bin', install.get('bin_path', '/usr/local/bin/dnscontrol')) %}

{% if dnscontrol.enable %}
{% set ns = namespace(zones={}, errors=[], warnings=[]) %}
{% set multi_value_types = [] %}
{% for t in dnscontrol.multi_value_types|default([]) %}
{% set _ = multi_value_types.append((t|string)|upper) %}
{% endfor %}

{# Merge/mapping happens here (SLS layer) #}
{% for zone_name, zone_data in dnscontrol.zones|default({})|dictsort %}
  {% if zone_data is mapping %}
    {% set provider_name = zone_data.get("provider") %}
    {% if provider_name %}
      {% if provider_name in dnscontrol.providers %}
        {% set record_groups = zone_data.get("record_groups", {}) %}
        {% if record_groups is mapping %}
          {% set configured_order = zone_data.get("record_group_order") %}
          {% set group_order = [] %}

          {% if configured_order is none %}
            {% set group_order = record_groups.keys()|list|sort %}
          {% else %}
            {% if configured_order is sequence and configured_order is not string %}
              {% for group_name in configured_order %}
                {% if group_name in record_groups %}
                  {% if group_name not in group_order %}
                    {% set _ = group_order.append(group_name) %}
                  {% endif %}
                {% else %}
                  {% set _ = ns.errors.append("Zone '" ~ zone_name ~ "': unknown group in record_group_order: " ~ group_name) %}
                {% endif %}
              {% endfor %}
              {% for group_name in record_groups.keys()|list|sort %}
                {% if group_name not in group_order %}
                  {% set _ = group_order.append(group_name) %}
                {% endif %}
              {% endfor %}
            {% else %}
              {% set _ = ns.errors.append("Zone '" ~ zone_name ~ "': record_group_order must be a list") %}
            {% endif %}
          {% endif %}

          {% set zone_ns = namespace(buckets={}, bucket_order=[], final_records=[]) %}

          {% for group_name in group_order %}
            {% set group_data = record_groups.get(group_name, {}) %}
            {% if group_data is mapping %}
              {% set records = group_data.get("records", []) %}
              {% if records is sequence and records is not string %}
                {% for raw_record in records %}
                  {% if raw_record is mapping %}
                    {% set rec_name = raw_record.get("name") %}
                    {% set rec_type = raw_record.get("type") %}
                    {% if rec_name and rec_type %}
                      {% set rec_type_norm = (rec_type|string)|upper %}
                      {% set rec_key = (rec_name|string) ~ "|" ~ rec_type_norm %}

                      {% if rec_key not in zone_ns.bucket_order %}
                        {% set _ = zone_ns.bucket_order.append(rec_key) %}
                      {% endif %}
                      {% if rec_key not in zone_ns.buckets %}
                        {% set _ = zone_ns.buckets.update({rec_key: []}) %}
                      {% endif %}

                      {% set rec_override = raw_record.get("override", false) %}
                      {% set rec_disabled = raw_record.get("disabled", false) %}

                      {% if rec_disabled and rec_override %}
                        {% set _ = zone_ns.buckets.update({rec_key: []}) %}
                      {% elif rec_disabled %}
                        {# disabled non-override => skip #}
                      {% else %}
                        {% set record = {} %}
                        {% set _ = record.update(raw_record) %}
                        {% set _ = record.update({"name": rec_name|string, "type": rec_type_norm}) %}
                        {% if rec_override %}
                          {% set _ = zone_ns.buckets.update({rec_key: [record]}) %}
                        {% else %}
                          {% set _ = zone_ns.buckets[rec_key].append(record) %}
                        {% endif %}
                      {% endif %}
                    {% else %}
                      {% set _ = ns.errors.append("Zone '" ~ zone_name ~ "': group '" ~ group_name ~ "': record requires name and type") %}
                    {% endif %}
                  {% else %}
                    {% set _ = ns.errors.append("Zone '" ~ zone_name ~ "': group '" ~ group_name ~ "': record must be a mapping") %}
                  {% endif %}
                {% endfor %}
              {% else %}
                {% set _ = ns.errors.append("Zone '" ~ zone_name ~ "': group '" ~ group_name ~ "': records must be a list") %}
              {% endif %}
            {% else %}
              {% set _ = ns.errors.append("Zone '" ~ zone_name ~ "': group '" ~ group_name ~ "' must be a mapping") %}
            {% endif %}
          {% endfor %}

          {% for rec_key in zone_ns.bucket_order %}
            {% set items = zone_ns.buckets.get(rec_key, []) %}
            {% if items %}
              {% set first_type = (items[0].get("type", "")|string)|upper %}
              {% if items|length > 1 and first_type not in multi_value_types %}
                {% set msg = "Conflict duplicate in zone '" ~ zone_name ~ "' for key '" ~ rec_key ~ "'" %}
                {% if dnscontrol.strict_duplicates %}
                  {% set _ = ns.errors.append(msg) %}
                {% else %}
                  {% set _ = ns.warnings.append(msg) %}
                {% endif %}
              {% endif %}
              {% for item in items %}
                {% set _ = zone_ns.final_records.append(item) %}
              {% endfor %}
            {% endif %}
          {% endfor %}

          {% set _ = ns.zones.update({
            zone_name: {
              "provider": provider_name,
              "default_ttl": zone_data.get("default_ttl"),
              "records": zone_ns.final_records
            }
          }) %}
        {% else %}
          {% set _ = ns.errors.append("Zone '" ~ zone_name ~ "': record_groups must be a mapping") %}
        {% endif %}
      {% else %}
        {% set _ = ns.errors.append("Zone '" ~ zone_name ~ "' references unknown provider '" ~ provider_name ~ "'") %}
      {% endif %}
    {% else %}
      {% set _ = ns.errors.append("Zone '" ~ zone_name ~ "' missing provider") %}
    {% endif %}
  {% else %}
    {% set _ = ns.errors.append("Zone '" ~ zone_name ~ "' must be a mapping") %}
  {% endif %}
{% endfor %}

{% if ns.errors %}
dnscontrol_input_validation:
  test.fail_without_changes:
    - name: "{{ ns.errors | join(' || ') }}"
    - require:
      - test: dnscontrol_install_ready
      - file: dnscontrol_config_dir
      - file: dnscontrol_lock_dir
{% else %}
dnscontrol_apply:
  dnscontrol.managed:
    - name: dnscontrol
    - config_dir: {{ dnscontrol.config_dir }}
    - zones: {{ ns.zones | json }}
    - providers: {{ dnscontrol.providers | json }}
    - warnings: {{ ns.warnings | json }}
    - fail_on_warnings: {{ dnscontrol.fail_on_warnings | json }}
    - dnscontrol_bin: {{ dnscontrol_bin }}
    - lock_file: {{ dnscontrol.lock_file }}
    - lock_timeout_sec: {{ dnscontrol.lock_timeout_sec }}
    - creds_mode: {{ dnscontrol.creds_mode }}
    - config_mode: {{ dnscontrol.config_mode }}
    - template_base: {{ dnscontrol.template_base }}
    - saltenv: {{ dnscontrol.saltenv }}
    - require:
      - test: dnscontrol_install_ready
      - file: dnscontrol_config_dir
      - file: dnscontrol_lock_dir
{% endif %}

{% endif %}
