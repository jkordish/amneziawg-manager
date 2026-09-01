# AmneziaWG Manager

`awgctl` is a small, dependency-free management CLI for a native AmneziaWG
server on Ubuntu 24.04 amd64. It can install a fresh server, adopt a working
single-peer `awg0` installation without rotating its identity, manage one
client profile per device, and transactionally move a classic deployment to an
AWG 3.1 profile after an exact server package pair has been qualified.

The product installs under `/opt/amneziawg`; the Git checkout is only a source
and build tree. The manager uses the upstream `awg-quick@awg0.service` and the
package-native runtime configuration at
`/etc/amnezia/amneziawg/awg0.conf`. It does not add a daemon, web UI, management
port, AWS credential, or generic host firewall.

> **Beta support boundary:** v0.1 supports Ubuntu 24.04 LTS, amd64, IPv4, one
> `awg0`, and an explicitly attested public-ingress boundary: AWS Lightsail or
> an equivalent external firewall. Classic mode remains compatible. The AWG
> 3.1 model and direct-cutover controls are repository-tested, but the
> production qualification allowlist is intentionally empty. Therefore no
> package pair can activate AWG 3.1 in this release, and no in-Russia iOS result
> is claimed.

## Why this exists

- Safe client creation, import, metadata, rotation, and revocation.
- Atomic configuration commits with rollback and drift detection.
- Dedicated VPN-only nftables NAT and forwarding isolation.
- Verified backups and transactional restore.
- Stable JSON output, dry runs, redacted diagnostics, and an opt-in namespace
  self-test.
- Exact AWG tools/module qualification, protected AWG 3.1 key custody, and a
  single-interface cutover with a ten-minute automatic classic rollback.
- Immutable product releases and Ed25519-signed operator-triggered updates.
- A locked, nologin staging identity for confined builds and a separate scoped
  operator group.

## Quick start

Clone the repository on a supported server and run the read-only preflight:

```bash
git clone https://github.com/jkordish/amneziawg-manager.git
cd amneziawg-manager
python3 install.py check
```

For a fresh host, supply a DNS name that resolves to the instance's stable
Lightsail public IPv4:

```bash
python3 install.py install --dry-run \
  --endpoint vpn.example.com \
  --ingress-boundary lightsail \
  --first-client admin-iphone

sudo python3 install.py install --yes \
  --endpoint vpn.example.com \
  --ingress-boundary lightsail \
  --first-client admin-iphone \
  --owner admin --device iphone
```

The default client DNS policy is Cloudflare's malware-blocking resolver pair,
`1.1.1.2,1.0.0.2`. It blocks known malicious destinations; DNS filtering is
not a complete advertisement blocker. Override it with `--dns`,
`--default-dns`, or [install-settings.example.json](install-settings.example.json).

For a working host with exactly one existing server peer and its matching
client profile:

```bash
python3 install.py adopt --dry-run \
  --client-config /root/amneziawg-clients/device.conf \
  --client-name device

sudo python3 install.py adopt --yes \
  --ingress-boundary lightsail \
  --client-config /root/amneziawg-clients/device.conf \
  --client-name device
```

Adoption verifies the file identities against the live interface before it
commits. It does not regenerate the server key, client key, PSK, address,
endpoint, port, MTU, DNS, or classic obfuscation parameters.

The attested external firewall remains an operator responsibility. For the
default port, configure this inbound rule at that boundary:

```text
Custom / UDP / 55323 / 0.0.0.0/0
```

`awgctl aws-rule` reports the exact rule for the current port and names the
persisted attestation. The installer never changes AWS or another external
firewall and never enables UFW.

## Build, configure, and upgrade

The Git checkout is the one repository and build context. The installed product
under `/opt/amneziawg` is root-owned generated state and is never a Git working
tree. A normal source upgrade is:

```bash
git pull --ff-only
python3 install.py check
python3 install.py upgrade --dry-run
sudo python3 install.py upgrade --yes --ingress-boundary lightsail
```

On first installation the script creates locked `awgctl:awgctl` staging
identity, `/var/lib/amneziawg-manager`, and the `awgctl-admin` operator group.
The invoking sudo user is enrolled by default. Builds run as `awgctl` in a
transient no-network systemd worker; root validates and installs the artifact.
Upgrade does not combine release activation with later runtime/profile
mutations. After the upgrade and health check complete, apply any intended DNS
or service changes as separate operator-reviewed transactions:

```bash
sudo awgctl config set dns cloudflare-malware
sudo awgctl restart
```

## Everyday use

```bash
sudo awgctl status
sudo awgctl health
sudo awgctl client add
```

Running `client add` without a name opens an interactive profile wizard. It
collects the owner, device, optional expiration date, suggests a safe profile
name, and shows a final review before credentials are generated or the server
configuration is reloaded. To preview the transaction without changing state,
use `sudo awgctl client add --dry-run`.

For scripts and other non-interactive use, keep supplying every value
explicitly:

```bash
sudo awgctl client add kat-iphone --owner Kat --device iPhone
sudo awgctl client list
sudo awgctl client show kat-iphone
sudo awgctl client export kat-iphone --output /home/OPERATOR/kat-iphone.conf
sudo awgctl client qr kat-iphone --output /home/OPERATOR/kat-iphone.png
sudo awgctl client edit kat-iphone --mark-distributed
sudo awgctl client expire --dry-run
sudo awgctl client revoke kat-iphone --dry-run
sudo awgctl client revoke kat-iphone
sudo awgctl backup
sudo awgctl diagnose
```

Use `--json` on automation-facing commands. Put `--dry-run` on a mutation to
validate and display the intended transaction without generating keys,
creating a backup, writing files, reloading systemd, or changing nftables.

## AWG 3.1 release boundary

Kat's target client is the free, standalone native AmneziaWG app for
iOS/iPadOS with AWG 3.1 support. A generated profile is a credential artifact,
not evidence that it was imported or worked from inside Russia. Likewise,
source checks, mocked dry runs, the optional local namespace test, and a
`prepared` transition are not deployment evidence.

When a future release contains an exactly qualified tools/module pair, the
operator flow is `obfuscation prepare`, add the newly reported UDP ingress
rule, `activate --ingress-ready --timeout 10m`, securely deliver/import the new
profile, perform the full Kat checklist, then `confirm`. Activation replaces
classic mode directly; it never runs classic and AWG 3.1 in parallel. A failed
activation or unconfirmed deadline restores the protected classic backup.

AWG 3.1 changes packet appearance, not the IP/UDP transport. IP blocking or a
network policy that blocks all UDP—or allows only selected UDP destinations—
can still prevent it, and this manager has no AWG-only fallback transport.
See [Operations](docs/OPERATIONS.md) for the exact commands, secure-delivery
sequence, and manual acceptance evidence.

## Documentation

- [Installation and adoption](docs/INSTALL.md)
- [Architecture and security boundaries](docs/ARCHITECTURE.md)
- [Operations and client lifecycle](docs/OPERATIONS.md)
- [Backup, restore, and disaster recovery](docs/RECOVERY.md)
- [Development and testing](docs/DEVELOPMENT.md)
- [Release signing and publishing](docs/RELEASING.md)
- [Security policy](SECURITY.md)

## License

The manager is released under the [MIT License](LICENSE). AmneziaWG and its
kernel/userspace packages are separate upstream projects with their own
licenses.
