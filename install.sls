{#-
  Install dnscontrol and ensure runtime directories exist.
  Supports:
    - archive install (default)
    - package install (fallback)
-#}
{% from tpldir ~ "/map.jinja" import dnscontrol with context %}
{% set install = dnscontrol.get('install', {}) %}
{% set archive = install.get('archive', {}) %}
{% set lock_dir = dnscontrol.lock_file.rsplit('/', 1)[0] if '/' in dnscontrol.lock_file else '/var/lock' %}
{% set bin_path = install.get('bin_path', '/usr/local/bin/dnscontrol') %}
{% set bin_dir = bin_path.rsplit('/', 1)[0] if '/' in bin_path else '/usr/local/bin' %}
{% set install_method = install.get('method', 'archive') %}
{% set install_enabled = install.get('enabled', true) %}
{% set archive_extract_root = archive.get('extract_root', '/opt/dnscontrol') %}
{% set archive_version = archive.get('version', '4.36.1') %}
{% set archive_binary_name = archive.get('binary_name', 'dnscontrol') %}
{% set archive_url = archive.get('url', '') %}
{% set archive_source_hash = archive.get('source_hash', '') %}
{% set archive_enforce_toplevel = archive.get('enforce_toplevel', false) %}
{% set release_dir = archive_extract_root ~ '/' ~ archive_version %}
{% set extracted_binary = release_dir ~ '/' ~ archive_binary_name %}

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

{% if install_enabled %}
{% if install_method == 'archive' %}

dnscontrol_archive_root:
  file.directory:
    - name: {{ archive_extract_root }}
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
    - source: {{ archive_url }}
    - if_missing: {{ extracted_binary }}
    - enforce_toplevel: {{ archive_enforce_toplevel }}
{% if archive_source_hash %}
    - source_hash: {{ archive_source_hash }}
{% endif %}
    - require:
      - file: dnscontrol_archive_root

dnscontrol_binary_link:
  file.symlink:
    - name: {{ bin_path }}
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
    - name: {{ install.get('package_name', 'dnscontrol') }}

dnscontrol_install_ready:
  test.nop:
    - require:
      - pkg: dnscontrol_pkg

{% else %}

dnscontrol_install_ready:
  test.fail_without_changes:
    - name: "Unsupported dnscontrol.install.method: {{ install_method }}"

{% endif %}
{% else %}

dnscontrol_install_ready:
  test.nop:
    - name: "Binary installation skipped (dnscontrol.install.enabled=false)"
    - require:
      - file: dnscontrol_config_dir
      - file: dnscontrol_lock_dir

{% endif %}

{% endif %}
