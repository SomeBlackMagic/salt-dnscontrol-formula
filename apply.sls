{% from tpldir ~ "/map.jinja" import dnscontrol with context %}

{% if dnscontrol.enable %}

dnscontrol_apply:
  dnscontrol.managed:
    - name: dnscontrol
    - config_dir: {{ dnscontrol.config_dir }}
    - require:
      - test: dnscontrol_install_ready
      - file: dnscontrol_config_dir
      - file: dnscontrol_lock_dir

{% endif %}
