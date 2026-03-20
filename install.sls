{#-
  Install dnscontrol and ensure runtime directories exist.
  Supports:
    - archive install (default)
    - package install (fallback)
-#}
{% from tpldir ~ "/map.jinja" import dnscontrol with context %}
{% set lock_dir = dnscontrol.lock_file.rsplit('/', 1)[0] if '/' in dnscontrol.lock_file else '/var/lock' %}
{% set bin_dir = dnscontrol.bin_path.rsplit('/', 1)[0] if '/' in dnscontrol.bin_path else '/usr/local/bin' %}
{% set install_method = dnscontrol.install_method|default('archive') %}
{% set release_dir = dnscontrol.archive_extract_root ~ '/' ~ dnscontrol.archive_version %}
{% set extracted_binary = release_dir ~ '/' ~ dnscontrol.archive_binary_name %}

{% if dnscontrol.enable %}

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

{% if install_method == 'archive' %}

dnscontrol_archive_root:
  file.directory:
    - name: {{ dnscontrol.archive_extract_root }}
    - user: root
    - group: root
    - mode: '0755'
    - makedirs: true

dnscontrol_bin_dir:
  file.directory:
    - name: {{ bin_dir }}
    - user: root
    - group: root
    - mode: '0755'
    - makedirs: true

dnscontrol_archive_extracted:
  archive.extracted:
    - name: {{ release_dir }}
    - source: {{ dnscontrol.archive_url }}
    - if_missing: {{ extracted_binary }}
    - enforce_toplevel: {{ dnscontrol.archive_enforce_toplevel }}
{% if dnscontrol.archive_source_hash %}
    - source_hash: {{ dnscontrol.archive_source_hash }}
{% endif %}
    - require:
      - file: dnscontrol_archive_root

dnscontrol_binary_link:
  file.symlink:
    - name: {{ dnscontrol.bin_path }}
    - target: {{ extracted_binary }}
    - force: true
    - require:
      - archive: dnscontrol_archive_extracted
      - file: dnscontrol_bin_dir

dnscontrol_install_ready:
  test.nop:
    - require:
      - file: dnscontrol_binary_link

{% elif install_method == 'package' %}

dnscontrol_pkg:
  pkg.installed:
    - name: {{ dnscontrol.package_name }}

dnscontrol_install_ready:
  test.nop:
    - require:
      - pkg: dnscontrol_pkg

{% else %}

dnscontrol_install_ready:
  test.fail_without_changes:
    - name: "Unsupported dnscontrol.install_method: {{ install_method }}"

{% endif %}

{% endif %}
