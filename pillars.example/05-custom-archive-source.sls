# Example: customize archive source, version and binary path.

dnscontrol:
  enable: true

  install:
    enabled: true
    method: archive
    bin_path: /usr/local/bin/dnscontrol
    archive:
      url: https://github.com/StackExchange/dnscontrol/releases/download/v4.36.1/dnscontrol_4.36.1_linux_amd64.tar.gz
      version: "4.36.1"
      extract_root: /opt/dnscontrol
      binary_name: dnscontrol
      # source_hash: sha256=<REPLACE_ME>

  dnscontrol_bin: /usr/local/bin/dnscontrol

  strict_duplicates: true
  fail_on_warnings: true

  providers:
    cloudflare_main:
      type: cloudflare
      credentials:
        api_token: "REPLACE_ME"

  zones:
    example.com:
      provider: cloudflare_main
      record_groups:
        base:
          records:
            - name: "@"
              type: A
              value: 1.1.1.1
