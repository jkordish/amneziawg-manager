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

For guided profile creation, run:

```bash
sudo awgctl client add
```

The wizard requires an interactive terminal. It collects the intended owner
and physical device, suggests a profile name, accepts an optional `YYYY-MM-DD`
expiration date, and displays a review before making changes. Canceling the
review or reaching end-of-input leaves credentials, backups, files, and the
running service untouched. Use `sudo awgctl client add --dry-run` to walk
through the same wizard and validate the proposed transaction without changing
state.

Automation, redirected input, and `--json` require an explicit profile name:

```bash
sudo awgctl client add kat-iphone \
  --owner Kat --device iPhone --expires 2027-09-01
sudo awgctl client list
sudo awgctl client show kat-iphone
sudo awgctl client edit kat-iphone --device 'iPhone 18'
sudo awgctl client edit kat-iphone --expires none
sudo awgctl client edit kat-iphone --mark-distributed
```

After successful creation, the command prints protected canonical locations
and explicit `client export` and `client qr` examples. Choose one delivery
format and replace the example operator directory with a secure directory
owned by the invoking sudo user.

Metadata tracks a monotonically increasing profile revision and one of
`unknown`, `pending`, or `distributed`. Creating, rotating, or regenerating a
profile makes that revision `pending`. Mark it distributed only after the
intended owner confirms secure receipt/import; this does not claim a connection.
Only a nonzero handshake proves the device has connected.

Never reuse a profile across devices. Retrieve a profile through a protected
file path:

```bash
sudo awgctl client export kat-iphone --output /home/OPERATOR/kat-iphone.conf
sudo awgctl client qr kat-iphone --output /home/OPERATOR/kat-iphone.png
```

The default export reports the existing path. `--stdout` is explicit and warns
because terminal scrollback and logs can retain credentials. QR images are
never rendered in the terminal.

An output directory must be absolute, owned by the sudo invoker, and not
group/world-writable. The manager atomically creates the delivery copy as that
operator with mode `0600`; it never overwrites a path. Delete the delivery copy
after secure import. Canonical copies under `/opt` remain root-only.

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
sudo awgctl config set dns cloudflare-malware
sudo awgctl config set mtu 1280
sudo awgctl config set listen-port 55323
```

A listen-port change prominently reports both old and new Lightsail rules. Add
the new AWS rule before relying on the new port and remove the old one only
after client connectivity is verified.

Named policies are `cloudflare`, `cloudflare-malware`, and
`cloudflare-family`; comma-separated IPv4 resolvers remain supported. The
default malware policy stores `1.1.1.2,1.0.0.2`. Changing DNS regenerates
profiles but does not change keys, PSKs, tunnel addresses, or peer identities.

## First-use handoff for Kat

Kat has a prepared profile, not a deployed device. Test it before delivery,
then:

1. Export either `kat.conf` or `kat.png` to a validated operator-owned directory.
2. Transfer it over an end-to-end encrypted channel or in person; do not email
   it, paste it into chat, or leave it in cloud photo or terminal history.
3. Have Kat install the AmneziaWG client, import the profile on exactly one
   device, connect, and confirm expected Internet access.
4. Verify `sudo awgctl status` shows a recent handshake for `kat`.
5. Record the handoff with `sudo awgctl client edit kat --mark-distributed`.
6. Remove the temporary exported file or QR from the delivery location.

Create a different client such as `kat-iphone` or `kat-macbook` for every
additional device; never reuse `kat`.

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
