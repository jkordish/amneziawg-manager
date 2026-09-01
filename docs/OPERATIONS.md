# Operations

## Operational view

```bash
sudo awgctl status
sudo awgctl health
sudo awgctl status --json
sudo awgctl health --json
sudo journalctl -t awgctl
```

Health failures return exit code `3`; warnings return `0`. Warnings include low
disk (`>=90%` used or `<5 GiB` free), low available memory, no swap, unverified
Lightsail static IP, wildcard host listeners, and package/DKMS upgrade risk.

Do not claim a client is connected until its handshake changes from `never`.
Safe direct queries are limited to:

```bash
sudo awg show awg0 peers
sudo awg show awg0 latest-handshakes
```

AmneziaWG 3.1 may segfault when unset `I1`–`I5` fields are queried. The manager
does not query them. Do not add them to diagnostics or operational scripts.

## Service lifecycle

```bash
sudo awgctl start --dry-run
sudo awgctl start
sudo awgctl stop
sudo awgctl restart
sudo awgctl reload
```

These map to the native `awg-quick@awg0.service`. Peer-only changes use reload;
MTU, listen port, address, and lifecycle changes require restart. Starting and
stopping install/remove only the VPN-owned nftables state.

## Client lifecycle

```bash
sudo awgctl client add kat-iphone \
  --owner Kat --device iPhone --expires 2027-09-01
sudo awgctl client list
sudo awgctl client show kat-iphone
sudo awgctl client edit kat-iphone --device 'iPhone 18'
sudo awgctl client edit kat-iphone --expires none
```

Never reuse a profile across devices. Retrieve a profile through a protected
file path:

```bash
sudo awgctl client export kat-iphone --output /secure/path/kat-iphone.conf
sudo awgctl client qr kat-iphone
```

The default export reports the existing path. `--stdout` is explicit and warns
because terminal scrollback and logs can retain credentials. QR images are
never rendered in the terminal.

Import a profile only when its mode denies group/other access and its key,
server identity, PSK, address, endpoint, MTU, DNS, keepalive, and classic
obfuscation semantics match the existing managed server peer:

```bash
chmod 600 /secure/path/device.conf
sudo awgctl client import device --config /secure/path/device.conf --dry-run
sudo awgctl client import device --config /secure/path/device.conf
```

Revoke and rotate transactionally:

```bash
sudo awgctl client revoke kat-iphone --dry-run
sudo awgctl client revoke kat-iphone
sudo awgctl client rotate kat-macbook --dry-run
sudo awgctl client rotate kat-macbook
```

Revoked/old credentials are archived, not immediately destroyed. After a
successful rotation the old server public key is absent, so the old profile no
longer authenticates.

## Configuration

```bash
sudo awgctl config show
sudo awgctl config set endpoint vpn.example.com --dry-run
sudo awgctl config set dns 1.1.1.1,1.0.0.1
sudo awgctl config set mtu 1280
sudo awgctl config set listen-port 55323
```

A listen-port change prominently reports both old and new Lightsail rules. Add
the new AWS rule before relying on the new port and remove the old one only
after client connectivity is verified.

## Diagnostics and self-test

```bash
sudo awgctl diagnose --dry-run
sudo awgctl diagnose
sudo awgctl self-test --experimental --dry-run
sudo awgctl self-test --experimental
```

Diagnostics creates a protected directory with redacted configurations,
client metadata without keys, system/network state, and a SHA-256 manifest.
Review it before sharing because host metadata is still sensitive.

The experimental test creates two temporary Linux network namespaces and an
ephemeral AmneziaWG tunnel, sends ICMP traffic, then deletes namespaces and
keys. It does not touch `awg0` or host nftables.

## Signed updates

```bash
sudo awgctl update check
sudo awgctl update --dry-run
sudo awgctl update
```

Updates are operator-triggered. The CLI verifies the Ed25519 signature,
platform, tag/version, artifact size, and SHA-256 before activating an immutable
release. It runs health and restores the previous release selector on failure;
the VPN service is not restarted.
