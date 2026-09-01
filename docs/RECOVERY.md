# Backup and recovery

## Verified backups

```bash
sudo awgctl backup --dry-run
sudo awgctl backup
sudo awgctl backup list
sudo awgctl backup verify 20260901T020000Z
```

Each new backup contains management configuration, keys, active and revoked
client state, generated server/nftables files, and operational snapshots. Its
`manifest.json` records every file's SHA-256, size, mode, and ownership.

Backups created before manifests are displayed as `legacy/unverified`. They are
not accepted by the automated restore command.

## Restore

Always inspect first:

```bash
sudo awgctl restore 20260901T020000Z --dry-run
sudo awgctl backup verify 20260901T020000Z
sudo awgctl restore 20260901T020000Z
```

Restore verifies the exact file inventory, stages and validates configuration,
creates a new pre-restore backup, atomically replaces only manager-owned state,
and restarts/validates the interface only if it was running. On failure it
restores the pre-restore filesystem and runtime configuration and attempts to
verify that rollback.

## Bad product release

Product versions are immutable under `/opt/amneziawg/releases`. The active
selector is `/opt/amneziawg/bin/awgctl`. Automatic/source upgrades restore the
previous selector when health fails.

If manual intervention is required, inspect release manifests and choose a
known-good executable without changing VPN data:

```bash
sudo /opt/amneziawg/releases/PREVIOUS/awgctl health
sudo ln -sfn ../releases/PREVIOUS/awgctl /opt/amneziawg/bin/awgctl
sudo awgctl health
```

The selector change does not restart the tunnel.

## Package/kernel failure

Before a kernel upgrade, resolve disk warnings and confirm DKMS is installed for
the new kernel. Do not reboot into a kernel without AmneziaWG support.

```bash
dkms status
uname -r
sudo awgctl health
```

If a rebooted kernel lacks the module, select the prior known-good kernel from
the bootloader or install matching headers and rebuild through the upstream
package. Do not regenerate VPN identities during package recovery.

## Manual configuration recovery

Do not edit `server.json` or runtime `awg0.conf` casually. Preserve the broken
files, use a verified backup, and run health after restore. Never use
`nft flush ruleset`; `_firewall down` removes only manager-owned rules:

```bash
sudo /opt/amneziawg/bin/awgctl _firewall down
sudo awgctl restart
sudo awgctl health
```

Do not claim client connectivity until a new handshake is observed.
