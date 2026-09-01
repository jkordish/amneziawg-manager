# Installation and adoption

## Support matrix

The beta deliberately fails closed outside:

- Ubuntu 24.04 LTS (`noble`)
- amd64/x86-64
- AWS Lightsail
- IPv4 and one interface named `awg0`
- native AmneziaWG kernel module and `awg-quick` systemd unit

The host needs root access, systemd, nftables, Python 3.12, and Internet access
to Ubuntu/Launchpad package repositories. A fresh DKMS install requires at
least 5 GiB free on `/`.

## Preflight

```bash
python3 install.py check
python3 install.py check --json
```

Before a fresh install, assign a Lightsail static IPv4, point the endpoint DNS
A record to it, and add the intended UDP port to the Lightsail firewall. The
manager reports the requirement but has no AWS credentials and performs no AWS
mutation.

## Fresh installation

Review the transaction:

```bash
python3 install.py install --dry-run \
  --endpoint vpn.example.com \
  --subnet 10.77.42.0/24 \
  --listen-port 55323 \
  --dns 1.1.1.1,1.0.0.1 \
  --mtu 1280 \
  --keepalive 25 \
  --first-client admin-iphone
```

Then execute it explicitly:

```bash
sudo python3 install.py install --yes \
  --endpoint vpn.example.com \
  --first-client admin-iphone
```

The installer:

1. validates Ubuntu 24.04 amd64 and free disk space;
2. installs current-kernel and generic headers, then uses the official
   `ppa:amnezia/ppa` packages;
3. verifies `amneziawg` DKMS for the running kernel and loads the module;
4. builds and atomically deploys the dependency-free manager;
5. generates a new server identity and one unique first-device profile;
6. writes validated managed/runtime configuration atomically;
7. enables IPv4 forwarding and `awg-quick@awg0.service`;
8. verifies the server/peer identity and creates an initial verified backup.

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
sudo python3 install.py upgrade
```

This builds an immutable release under `/opt/amneziawg/releases/VERSION/`,
atomically switches `/opt/amneziawg/bin/awgctl`, runs health, and restores the
previous selector if health fails. It does not reinstall AmneziaWG or restart
the tunnel.

## Installed paths

```text
/opt/amneziawg/
  bin/awgctl -> ../releases/VERSION/awgctl
  releases/VERSION/{awgctl,install-manifest.json,share/}
  config/server.json
  keys/{server,clients}/
  clients/
  revoked/
  generated/{awg0.conf,nftables.nft}
  backups/
  diagnostics/
/usr/local/sbin/awgctl -> /opt/amneziawg/bin/awgctl
/etc/bash_completion.d/awgctl
```

Secret directories are `0700`; keys, profiles, QR images, metadata, generated
configuration, backups, and diagnostics are `0600`. Product code and public
documentation contain no credentials.
