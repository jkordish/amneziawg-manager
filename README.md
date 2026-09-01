# AmneziaWG operations

This host runs the native `awg-quick@awg0.service`. `/opt/amneziawg` is the
management source of truth; `/etc/amnezia/amneziawg/awg0.conf` is an atomic,
generated runtime copy. Do not enable `SaveConfig` or edit the runtime copy by
hand. `awgctl health` reports drift instead of overwriting it.

## Architecture and trust boundaries

- AWS Lightsail is the only public-ingress firewall. UFW is intentionally
  inactive. The host does not have a generic nftables/iptables INPUT policy.
- The required Lightsail rule is `Custom / UDP / 55323 / 0.0.0.0/0` (or the
  current port shown by `awgctl aws-rule`). `awgctl` never uses AWS credentials
  or changes AWS resources.
- `awg0` is an untrusted client boundary. The dedicated nftables tables
  `ip amneziawg_forward` and `ip amneziawg_nat` allow established replies and
  masqueraded public-Internet egress while dropping private, link-local,
  metadata, CGNAT, multicast, reserved, Docker/bridge, and other lateral
  forwarding destinations.
- Docker's host `FORWARD` policy is `drop`, so three comment-tagged awgctl rules
  in `ip filter DOCKER-USER` provide the final egress/established-return accept
  and default tunnel drop. All isolation policy remains in
  `amneziawg_forward`; unrelated Docker rules are not modified.
- There is deliberately no VPN INPUT firewall. An authenticated peer can reach
  services listening on `awg0` or wildcard host addresses. `awgctl health`
  warns about them. Bind administration/metrics services to loopback or an
  intended private interface, or remove them.

## Layout

```text
/opt/amneziawg/
  bin/awgctl                  manager (0755)
  config/server.json          non-secret source of truth
  keys/server/{private,public}
  keys/clients/NAME/{private,public,psk}
  clients/NAME/{metadata.json,NAME.conf,NAME.png}
  generated/{awg0.conf,nftables.nft}
  revoked/                    retained revoked/rotated material
  backups/YYYYMMDDTHHMMSSZ/   protected point-in-time state
  tests/test_awgctl.py        deterministic manager tests
  README.md
```

Credential directories are root-owned mode `0700`; keys, profiles, QR images,
metadata, generated configs, and backups are mode `0600`. The public executable
is root-owned mode `0755`. Mutation commands serialize on
`/run/lock/awgctl.lock` and log non-secret events with journald/syslog tag
`awgctl`.

## Common operations

```bash
sudo awgctl status
sudo awgctl health             # `check` is an alias
sudo awgctl start|stop|restart|reload
sudo awgctl client list
sudo awgctl client add kat-iphone
sudo awgctl client show kat-iphone
sudo awgctl client export kat-iphone --output /secure/path/kat-iphone.conf
sudo awgctl client qr kat-iphone
sudo awgctl client revoke kat-iphone
sudo awgctl client rotate kat-iphone
sudo awgctl config show
sudo awgctl config set endpoint vpn.example.com
sudo awgctl config set dns 1.1.1.1,1.0.0.1
sudo awgctl config set mtu 1280
sudo awgctl config set listen-port 55323
sudo awgctl backup
sudo awgctl aws-rule
```

Use one client profile per physical device. Addition allocates a unique IPv4
address and generates a unique private/public keypair and PSK. Revocation first
removes and verifies the server peer, then retains credentials under `revoked/`.
Rotation replaces the server peer and archives the old profile, so the old
profile stops authenticating.

Profiles and QR images contain credentials. Retrieve them from the protected
paths printed by `client show`, or copy a profile to an explicitly protected
destination with `client export --output`. Terminal QR display is intentionally
unsupported. `client export --stdout` is an explicit escape hatch and warns
because shell scrollback and logs can retain the secret.

`status` and `client list` show last-handshake age without revealing keys. For
scripted investigation use only safe narrow queries such as:

```bash
sudo awg show awg0 peers
sudo awg show awg0 latest-handshakes
sudo journalctl -t awgctl
```

AmneziaWG tooling 3.1 can segfault when unset `I1` through `I5` fields are
queried. `awgctl` never queries those fields. Do not add them to diagnostic
commands or introduce newer protocol fields without a deliberate migration.

## Recovery

Before risky work run `sudo awgctl backup`. To recover a bad managed change:

1. Stop further mutations and inspect `sudo awgctl health` and the newest
   `/opt/amneziawg/backups/` directory.
2. Restore `config/`, `keys/`, `clients/`, and `generated/` from one matching
   backup with root ownership and the permissions above.
3. Copy that backup's `generated/awg0.conf` atomically to
   `/etc/amnezia/amneziawg/awg0.conf`.
4. Run `sudo awgctl restart`, then `sudo awgctl health`.

For full pre-manager rollback use the preserved snapshot under
`/root/pre-amnezia-backup/20260831T192750Z`: restore its `/etc/amnezia`, client,
sysctl, and firewall helper files, restore the original server config, invoke
the legacy helper `up`, and reload or restart the native service. Do not
regenerate server or Kat credentials during recovery.

## Upgrades

The current kernel must have an installed `amneziawg` DKMS build before reboot.
First resolve any `health` disk warning; low root-disk space can leave a kernel
upgrade without a usable module. Then upgrade through the configured Ubuntu
package source, confirm `dkms status` lists `amneziawg` for the running/new
kernel, reboot only when that check passes, and run:

```bash
sudo awgctl restart
sudo awgctl health
```

Do not reinstall AmneziaWG as a routine manager upgrade, flush nftables
globally, enable UFW, or copy this host's global obfuscation values from a new
random profile.
