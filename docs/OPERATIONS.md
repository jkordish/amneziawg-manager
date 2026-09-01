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
public IPv4, missing ingress attestation, wildcard host listeners, and
package/DKMS upgrade risk. Status and health keep classic mode usable even when
AWG 3.1 capability inspection is absent or unqualified.

Do not claim a client is connected until its handshake changes from `never`.
Safe direct queries are limited to:

```bash
sudo awg show awg0 peers
sudo awg show awg0 latest-handshakes
```

AmneziaWG 3.1 may segfault when unset `I1`–`I5` fields are queried. The manager
does not query them. Do not add them to diagnostics or operational scripts.
Status instead derives mode and field presence from protected manager state and
reports only the short header-key fingerprint.

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

An expiration date becomes effective at `00:00:00 UTC` at the start of that
date. Expired peers are excluded from every newly rendered server config and
shown as `expired`; metadata and protected profile material remain until an
explicit revoke. The installed daily timer performs the reconciliation at UTC
midnight, and operators can preview or trigger the same transaction:

```bash
sudo awgctl client expire --dry-run --json
sudo awgctl client expire
systemctl status amneziawg-client-expiry.timer
```

## Configuration

```bash
sudo awgctl config show
sudo awgctl config set endpoint vpn.example.com --dry-run
sudo awgctl config set dns cloudflare-malware
sudo awgctl config set mtu 1280
sudo awgctl config set listen-port 55323
```

A listen-port change prominently reports both old and new external-firewall
rules. Add the new rule before relying on the new port and remove the old one
only after client connectivity is verified.

Named policies are `cloudflare`, `cloudflare-malware`, and
`cloudflare-family`; comma-separated IPv4 resolvers remain supported. The
default malware policy stores `1.1.1.2,1.0.0.2`. Changing DNS regenerates
profiles but does not change keys, PSKs, tunnel addresses, or peer identities.

## AWG 3.1 direct cutover

The initial profile is `russia-ios-v1` for the free standalone native
AmneziaWG iOS/iPadOS app with AWG 3.1 support. It uses conservative fixed
headers and no random trailers. The profile is not described as “best” or as a
guaranteed censorship bypass: AWG remains IP over UDP, so destination IP
blocking, blanket UDP blocking, or a restrictive UDP whitelist can stop it.
There is no XRay or other fallback transport.

The production qualification allowlist is currently empty. The commands below
are the operator contract for a future release with an exactly qualified
tools/module pair; today `prepare` must fail closed at the capability gate.

1. Inspect the non-secret state and perform a no-write preview:

   ```bash
   sudo awgctl obfuscation show --json
   sudo awgctl obfuscation prepare \
     --mode awg31 --profile russia-ios-v1 \
     --client kat-iphone --dry-run --json
   ```

2. Prepare the protected artifacts. Record the transaction ID, old/new UDP
   ports, backup name, and exact rule the command reports. `prepared` means
   no runtime or distributed profile changed.

   ```bash
   sudo awgctl obfuscation prepare \
     --mode awg31 --profile russia-ios-v1 \
     --client kat-iphone --json
   ```

3. Add the new `Custom / UDP / NEW_PORT / 0.0.0.0/0` rule at the attested
   external boundary. Do not remove the classic port yet. Then start the exact
   ten-minute direct-cutover window:

   ```bash
   sudo awgctl obfuscation activate TRANSACTION_ID \
     --ingress-ready --timeout 10m --json
   ```

4. Immediately export either the installed `kat-iphone.conf` or QR to a
   validated operator-owned directory. Transfer it end-to-end encrypted or in
   person; do not email it, paste it into chat, or leave it in cloud photos or
   terminal history. Kat imports it into exactly one device running the native
   app. Delete the delivery copy after import.

5. Complete the Kat acceptance checklist below. Confirmation itself enforces a
   fresh post-activation handshake and increases in both receive and transmit
   counters; the broader user-visible checks remain manual evidence.

6. Confirm before the deadline, then acknowledge secure delivery and remove
   the old external ingress rule only when the command says it can be removed:

   ```bash
   sudo awgctl obfuscation confirm TRANSACTION_ID --json
   sudo awgctl client edit kat-iphone --mark-distributed
   ```

Use `sudo awgctl obfuscation rollback TRANSACTION_ID` for an operator rollback.
A failed activation rolls back synchronously. An active transaction that is not
confirmed by the exact deadline invokes the root-only internal timeout through
a transient systemd timer. Classic and AWG 3.1 never run concurrently.

## Kat manual acceptance checklist

Retain timestamps and redacted observations, never profiles or keys. Acceptance
requires all of the following from Kat's device on the intended Russian network:

- a fresh handshake after activation;
- increasing receive and transmit counters beyond the activation floor;
- DNS resolution through the configured resolver;
- the expected public egress IP;
- ordinary HTTPS browsing;
- a multi-megabyte download and a multi-megabyte upload;
- disconnect and reconnect;
- screen lock followed by resume;
- a Wi-Fi-to-cellular switch and a cellular-to-Wi-Fi switch.

Handshake alone is not acceptance, and handshake plus only one increasing
counter cannot satisfy `confirm`. Create a different profile such as
`kat-macbook` for every additional device; never reuse `kat-iphone`.

## Evidence labels

Use precise labels in issues and release notes:

- **Source evidence:** code review, unit tests, schemas, release manifest, and
  packaging checks. It proves repository behavior only.
- **Generated evidence:** a canonical config/profile/QR exists. It does not
  prove import, deployment, or connectivity.
- **Local isolated evidence:** a mocked or namespace self-test passed. It does
  not prove the production host, external ingress, Russia, or iOS.
- **Prepared transition:** a protected backup and pending artifacts exist; the
  live interface is still classic.
- **Deployed host evidence:** exact release identity, package pair, runtime
  config, service, timer, listener, and ingress have been observed on the host.
- **Kat acceptance:** the complete checklist above passed on the intended
  device and network. It is the only lane that proves that user path.

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
sudo awgctl update apply --dry-run
sudo awgctl update apply
```

Updates are operator-triggered. The CLI verifies the Ed25519 signature,
platform, tag/version, artifact size, and SHA-256 before activating an immutable
release. It runs health and restores the previous release selector on failure;
the VPN service is not restarted.
