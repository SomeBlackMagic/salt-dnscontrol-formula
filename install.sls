{#-
  Install dnscontrol and ensure runtime directories exist.
-#}
{% from tpldir ~ "/map.jinja" import dnscontrol with context %}
{% set lock_dir = dnscontrol.lock_file.rsplit('/', 1)[0] if '/' in dnscontrol.lock_file else '/var/lock' %}

{% if dnscontrol.enable %}

dnscontrol_pkg:
  pkg.installed:
    - name: {{ dnscontrol.package_name }}

dnscontrol_config_dir:
  file.directory:
    - name: {{ dnscontrol.config_dir }}
    - user: root
    - group: root
    - mode: {{ dnscontrol.config_mode }}
    - makedirs: true

dnscontrol_lock_dir:
  file.directory:
    - name: {{ lock_dir }}
    - user: root
    - group: root
    - mode: '0755'
    - makedirs: true

{% endif %}
