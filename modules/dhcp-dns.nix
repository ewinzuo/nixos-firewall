# DHCP (Kea) and DNS (Unbound) for the LAN.
#
# - Kea hands out 192.168.1.100–192.168.1.250 on br-lan
# - Unbound provides recursive DNS on 192.168.1.1, forwarding to Quad9
# - Static leases can be added to the kea reservations list
{ config, lib, pkgs, ... }:

{
  # ── Kea DHCP server ─────────────────────────────────────────────────
  services.kea.dhcp4 = {
    enable = true;
    settings = {
      interfaces-config = {
        interfaces = [ "br-lan" ];
        # Retry opening sockets every 5s if br-lan isn't ready at startup.
        service-sockets-retry-wait-time = 5000;
        service-sockets-max-retries = 100;
      };
      lease-database = {
        type = "memfile";
        persist = true;
        name = "/var/lib/kea/dhcp4.leases";
      };
      valid-lifetime = 3600;
      max-valid-lifetime = 7200;
      subnet4 = [
        {
          id = 1;
          subnet = "192.168.1.0/24";
          pools = [
            { pool = "192.168.1.100 - 192.168.1.250"; }
          ];
          option-data = [
            { name = "routers";          data = "192.168.1.1"; }
            { name = "domain-name-servers"; data = "192.168.1.1"; }
            { name = "domain-name";      data = "lan.home"; }
            { name = "subnet-mask";      data = "255.255.255.0"; }
          ];
          # Static leases — add your devices here
          reservations = [
            # {
            #   hw-address = "aa:bb:cc:dd:ee:ff";
            #   ip-address = "10.0.1.10";
            #   hostname   = "my-server";
            # }
          ];
        }
      ];
    };
  };

  # Disable systemd-resolved — Unbound handles all DNS. The stub
  # resolver at 127.0.0.53 was shadowing Unbound and breaking DNS
  # when resolved had no working upstream configured.
  services.resolved.enable = false;
  networking.nameservers = [ "127.0.0.1" ];

  # ── Unbound recursive DNS resolver ──────────────────────────────────
  # Unbound must not start until Mullvad routes are active, otherwise
  # its first query to Quad9 goes out bare wan0.
  systemd.services.unbound = {
    after = [ "mullvad-routes.service" ];
    wants = [ "mullvad-routes.service" ];
  };

  services.unbound = {
    enable = true;
    settings = {
      server = {
        interface = [ "192.168.1.1" "127.0.0.1" ];
        access-control = [
          "192.168.1.0/24 allow"
          "127.0.0.0/8 allow"
          "::1/128 allow"
        ];
        port = 53;

        # Performance — tune num-threads and slabs to match your core count
        num-threads = 4;
        msg-cache-slabs = 4;
        rrset-cache-slabs = 4;
        infra-cache-slabs = 4;
        key-cache-slabs = 4;
        msg-cache-size = "64m";
        rrset-cache-size = "128m";
        key-cache-size = "32m";
        prefetch = true;
        prefetch-key = true;
        so-reuseport = true;

        # Privacy / hardening
        hide-identity = true;
        hide-version = true;
        harden-glue = true;
        harden-dnssec-stripped = true;
        harden-referral-path = true;
        use-caps-for-id = true;
        qname-minimisation = true;

        # Block common DNS rebinding
        private-address = [
          "10.0.0.0/8"
          "172.16.0.0/12"
          "192.168.0.0/16"
          "169.254.0.0/16"
          "fc00::/7"
          "fe80::/10"
        ];

        # Local zone for LAN hostnames
        local-zone = [ "lan.home. static" ];
        local-data = [
          ''"firewall.lan.home. IN A 192.168.1.1"''
        ];
      };

      remote-control.control-enable = true;

      # Upstream resolver — Quad9 over DNS-over-TLS (port 853).
      # Plain DNS (port 53) gets intercepted by Mullvad's tunnel-side
      # DNS hijacking and never reaches Quad9. DoT bypasses this.
      forward-zone = [
        {
          name = ".";
          forward-tls-upstream = true;
          forward-addr = [
            "9.9.9.11@853#dns11.quad9.net"
            "149.112.112.11@853#dns11.quad9.net"
          ];
        }
      ];
    };
  };
}
