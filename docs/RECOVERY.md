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

## AWG 3.1 transition recovery

Every preparation retains an ordinary verified classic backup plus protected
pending artifacts bound to one unpredictable transaction ID. Inspect the
secret-free lifecycle state before acting:

```bash
sudo awgctl obfuscation show
sudo awgctl obfuscation show --json
```

For a known prepared or active transaction, request a normal rollback with the
exact ID:

```bash
sudo awgctl obfuscation rollback TRANSACTION_ID --json
sudo awgctl status
sudo awgctl health
```

Activation arms crash recovery before installing AWG 3.1 artifacts and then
replaces it with an absolute-deadline ten-minute rollback timer. A reload,
verification, or timer-construction failure restores classic state
synchronously. If activation succeeds but is not confirmed, the transient
root-only `_obfuscation-timeout TRANSACTION_ID` unit performs the same verified
restore. Repeating rollback for the matching completed transaction is
idempotent; another or stale ID is rejected.

Do not edit transition JSON, copy a pending profile around the manager, cancel
the transient timer manually, or remove the classic backup during an active
window. The next lock-protected lifecycle command reconciles an interrupted
cleanup from its durable checkpoint. If recovery cannot prove classic state,
the manager stops the interface rather than serving an uncertain configuration.

After rollback, Kat's AWG 3.1 profile is not accepted evidence and must not be
marked distributed. After confirmation, retain the ordinary backup, securely
acknowledge the new profile revision, and remove the old ingress rule only when
the confirmation output says it is safe.

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
`nft flush ruleset`. Normal service stop removes only manager-owned rules and
proves the kernel interface is absent before firewall down:

```bash
sudo awgctl stop
sudo awgctl restart
sudo awgctl health
```

The internal `_firewall` command is a service hook, not a general repair API.
Do not call it directly while the service or kernel interface is present. Do
not claim client connectivity until a new handshake and increasing traffic are
observed.

## Host-policy rollback

VPN data and host identity policy are separate. Before changing identity,
sudo, or systemd settings, create `sudo awgctl backup` and preserve these
manager-owned files:

```text
/opt/amneziawg/config/installation.json
/etc/sudoers.d/amneziawg-manager
/etc/modules-load.d/amneziawg-manager.conf
/etc/systemd/system/awg-quick@awg0.service.d/20-awgctl-hardening.conf
/etc/systemd/system/amneziawg-client-expiry.service
/etc/systemd/system/amneziawg-client-expiry.timer
```

The installer restores those files and removes only accounts, groups, and
memberships it created if validation fails. To disable an applied service
sandbox for diagnosis, change the declared policy rather than editing the
drop-in:

```bash
sudo python3 install.py configure --yes --systemd-hardening off --apply-live
```

Re-enable it with `--systemd-hardening conservative --apply-live`. Do not delete
the staging account while a worker job is running.
