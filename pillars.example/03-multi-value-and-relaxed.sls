dnscontrol:
  enable: true
  strict_duplicates: false
  fail_on_warnings: false
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
      default_ttl: 600
      record_group_order:
        - mail
        - services
      record_groups:
        mail:
          records:
            - name: "@"
              type: MX
              priority: 10
              value: mx1.example.com.
            - name: "@"
              type: MX
              priority: 20
              value: mx2.example.com.

        services:
          records:
            - name: _sip._tcp
              type: SRV
              priority: 10
              weight: 50
              port: 5060
              target: sip1.example.com.
            - name: _sip._tcp
              type: SRV
              priority: 10
              weight: 50
              port: 5060
              target: sip2.example.com.
            - name: info
              type: TXT
              value: "v=spf1 include:_spf.example.com ~all"
            - name: info
              type: TXT
              value: "owner=platform"
