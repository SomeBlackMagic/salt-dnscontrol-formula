dnscontrol:
  enable: true

  install:
    enabled: true
    method: archive
    package_name: dnscontrol
    bin_path: /usr/local/bin/dnscontrol
    archive:
      url: https://github.com/StackExchange/dnscontrol/releases/download/v4.36.1/dnscontrol_4.36.1_linux_amd64.tar.gz
      version: "4.36.1"
      extract_root: /opt/dnscontrol
      binary_name: dnscontrol

  config_dir: /etc/dnscontrol
  lock_file: /var/lock/dnscontrol.lock

  strict_duplicates: true
  fail_on_warnings: true
  multi_value_types:
    - MX
    - TXT
    - SRV

  providers:
    cloudflare_main:
      type: cloudflare
      credentials:
        api_token: "REPLACE_ME"

  zones:
    example.com:
      provider: cloudflare_main
      default_ttl: 300
      record_group_order:
        - base
      record_groups:
        base:
          records:
            - name: "@"
              type: A
              value: 1.1.1.1
            - name: www
              type: CNAME
              value: "@"
            - name: txt-check
              type: TXT
              value: "managed-by-salt"
