# Installation and adoption

## Support matrix

The beta deliberately fails closed outside:

- Ubuntu 24.04 LTS (`noble`)
- amd64/x86-64
- IPv4 and one interface named `awg0`
- native AmneziaWG kernel module and `awg-quick` systemd unit
- an explicitly attested `lightsail` or `equivalent-external-firewall`
  public-ingress boundary

The host needs root access, systemd, nftables, Python 3.12, and Internet access
to Ubuntu/Launchpad package repositories. A fresh DKMS install requires at
least 5 GiB free on `/`.

## Preflight

```bash
python3 install.py check
python3 install.py check --json
python3 install.py check --ingress-boundary lightsail
```

Before a fresh install, assign a stable public IPv4, point the endpoint DNS A
record to it, and add the intended UDP port to the attested external firewall.
The manager reports the requirement but has no cloud credentials and performs
no external-firewall mutation. The platform check and the ingress attestation
are separate: Ubuntu/amd64 alone never implies Lightsail.

## Fresh installation

Review the transaction:

```bash
python3 install.py install --dry-run \
  --endpoint vpn.example.com \
  --subnet 10.77.42.0/24 \
  --listen-port 55323 \
  --dns cloudflare-malware \
  --mtu 1280 \
  --keepalive 25 \
  --ingress-boundary lightsail \
  --first-client admin-iphone
```

Then execute it explicitly:

```bash
sudo python3 install.py install --yes \
  --endpoint vpn.example.com \
  --ingress-boundary lightsail \
  --first-client admin-iphone
```

The installer:

1. validates Ubuntu 24.04 amd64 and free disk space;
2. installs current-kernel and generic headers, then uses the official
   `ppa:amnezia/ppa` packages;
3. verifies `amneziawg` DKMS for the running kernel and loads the module;
4. creates a locked nologin staging user and a separate operator group;
5. copies only build inputs into `/var/lib/amneziawg-manager/jobs`, builds as
   that user in a no-network transient systemd unit, validates the output, and
   atomically deploys it as root;
6. generates a new server identity and one unique first-device profile;
7. writes validated managed/runtime configuration atomically;
8. enables IPv4 forwarding and `awg-quick@awg0.service`;
9. installs and enables the exact-midnight UTC client-expiry timer; and
10. verifies the server/peer identity and creates an initial verified backup.

It does not run `full-upgrade`, enable UFW, install an INPUT firewall, change
Lightsail, print credentials, or display a QR in the terminal.

## Adopt a working host

Adoption currently expects exactly one server peer and its exact matching
client profile. Multiple existing peers can be supported after adoption by
importing each profile, but the initial beta adoption transaction is purposely
narrow.

```bash
python3 install.py adopt --dry-run \
  --server-config /etc/amnezia/amneziawg/awg0.conf \
  --client-config /root/amneziawg-clients/device.conf \
  --client-name device

sudo python3 install.py adopt --yes \
  --ingress-boundary lightsail \
  --server-config /etc/amnezia/amneziawg/awg0.conf \
  --client-config /root/amneziawg-clients/device.conf \
  --client-name device
```

Before mutation, the source files are copied into a protected
`/opt/amneziawg/adoption-backups/TIMESTAMP/` directory. Adoption derives public
keys from the supplied private keys, compares them to the server files and live
interface, preserves every classic parameter, and rolls the runtime back if
post-migration identity verification fails.

## Source checkout upgrade

```bash
python3 install.py upgrade --dry-run
sudo python3 install.py upgrade --yes --ingress-boundary lightsail
```

This builds an immutable release under `/opt/amneziawg/releases/VERSION/`,
atomically switches `/opt/amneziawg/bin/awgctl`, runs health, and restores the
previous selector if health fails. It does not reinstall AmneziaWG or restart
the tunnel. Existing persisted ingress settings are reused; a legacy install
without the field must provide an explicit value before the new health gate.

Upgrade rejects `--apply-live` and `--apply-default-dns` before changing host or
release state. After the upgrade and health check complete, make either change
as its own operator-reviewed transaction:

```bash
sudo awgctl config set dns cloudflare-malware
sudo awgctl restart
```

Choose the intended named/custom DNS value; changing it regenerates managed
profiles and requires secure redistribution. The same flags remain available
to the separate `install.py configure` workflow when that explicit host-policy
transaction is intended.

## Host identities and customization

Defaults:

```text
staging user/group: awgctl:awgctl
staging home:       /var/lib/amneziawg-manager
login/password:     nologin / locked
operator group:     awgctl-admin
sudo policy:        NOPASSWD only for /usr/local/sbin/awgctl
systemd policy:     conservative
DNS policy:         cloudflare-malware (1.1.1.2,1.0.0.2)
ingress boundary:   required for mutation; no inferred default
```

Review and apply the host policy:

```bash
python3 install.py configure --dry-run --json
sudo python3 install.py configure --yes
```

Every default can be overridden with flags or a settings document:

```bash
cp install-settings.example.json local-install-settings.json
python3 install.py configure --dry-run --settings local-install-settings.json
sudo python3 install.py configure --yes --settings local-install-settings.json
```

CLI flags override JSON. Reusing a pre-existing account/group requires
`--adopt-existing-identities`, and succeeds only when that identity exactly
matches the locked/nologin/no-supplemental-groups policy. Later upgrades
recognize installed settings automatically. `--sudo-policy existing-sudo`
creates no new grant; `none` removes the manager-owned grant.

## Exact AWG 3.1 package qualification

Classic operation does not depend on the AWG 3.1 qualification allowlist.
Preparation for `russia-ios-v1` does: the manager parses the exact native
`awg --version`, loaded module version, and packaged module version, requires
the module versions to match, and then requires that pair in the versioned
source allowlist. Missing, malformed, mismatched, or unlisted evidence fails
closed before pending artifacts are written.

The production allowlist is intentionally empty in this release. The locally
installed or newest PPA package must not be added merely because it exists.
Qualification requires disposable-host compatibility evidence for that exact
tools/module pair and remains distinct from Kat's later in-Russia iOS
acceptance. `sudo awgctl status --json` and
`sudo awgctl obfuscation show --json` report only non-secret version evidence.

## Installed paths

```text
/opt/amneziawg/
  bin/awgctl -> ../releases/VERSION/awgctl
  libexec/awgctl-internal -> ../bin/awgctl
  releases/VERSION/{awgctl,install-manifest.json,share/}
  config/{server.json,installation.json}
  keys/{server/{private,public,header-protection},clients}/
  clients/
  revoked/
  generated/{awg0.conf,nftables.nft}
  backups/
  diagnostics/
  pending/obfuscation/TRANSACTION_ID/
  transitions/
  run/awgctl/
/usr/local/sbin/awgctl -> /opt/amneziawg/bin/awgctl
/etc/bash_completion.d/awgctl
/etc/sudoers.d/amneziawg-manager
/etc/modules-load.d/amneziawg-manager.conf
/etc/systemd/system/awg-quick@awg0.service.d/20-awgctl-hardening.conf
/etc/systemd/system/amneziawg-client-expiry.service
/etc/systemd/system/amneziawg-client-expiry.timer
/var/lib/amneziawg-manager/jobs/
```

Secret directories are `0700`; keys, profiles, QR images, metadata, generated
configuration, transitions, backups, and diagnostics are `0600`. Product code
and public documentation contain no credentials. Obfuscation rollback and
crash-recovery timers are persistent root-owned units created per transaction
with an exact absolute deadline and a transaction/origin-bound root-only
internal entrypoint; there is no static reusable timeout service. Installer
compensation reports every failed membership, user, or group rollback in
reverse order so residual sudo or group authority cannot be mistaken for a
successful rollback.
