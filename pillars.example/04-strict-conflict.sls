# This example intentionally creates a conflict in strict mode.
# Expected behavior: build fails (same key `www + A` with different values, no override).

dnscontrol:
  enable: true
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
      record_group_order:
        - base
        - app
      record_groups:
        base:
          records:
            - name: www
              type: A
              value: 1.1.1.1
        app:
          records:
            - name: www
              type: A
              value: 2.2.2.2
