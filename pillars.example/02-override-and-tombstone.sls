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
      default_ttl: 300
      record_group_order:
        - base
        - app
        - overrides
        - cleanup
      record_groups:
        base:
          records:
            - name: api
              type: A
              value: 10.0.0.10
            - name: old
              type: A
              value: 10.0.0.50

        app:
          records:
            - name: app
              type: A
              value: 10.0.0.20

        overrides:
          records:
            - name: api
              type: A
              value: 10.0.0.11
              override: true

        cleanup:
          records:
            - name: old
              type: A
              override: true
              disabled: true
