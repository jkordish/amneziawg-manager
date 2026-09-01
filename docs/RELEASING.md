# Releasing

Releases contain three assets:

- `awgctl.pyz`: dependency-free executable
- `release.json`: strict platform/version/size/SHA-256 manifest
- `release.json.sig`: OpenSSH Ed25519 signature over the exact manifest bytes

The committed public key is `release-signing-key.pub`; the same key is embedded
in the updater. Its fingerprint is:

```text
SHA256:A+5F4srwAQrJBPPagXTus/mguUQRTtEtfvns1yVXOLk
```

The private key must exist only as the GitHub Actions secret
`RELEASE_SIGNING_KEY`. Never commit it or place it under `/opt/amneziawg`.

## Release process

1. Update `src/awgctl/version.py` and `CHANGELOG.md`.
2. Run `make verify`.
3. Confirm the tag is exactly `v` plus the code version.
4. Push the signed/annotated tag. The release workflow rebuilds and retests the
   artifact, verifies tag/version equality, signs `release.json`, and publishes
   all three assets.
5. On a managed beta host, run `sudo awgctl update check`, then a dry run, then
   apply and run health.

Tags containing a prerelease suffix create a GitHub prerelease. A stable tag is
not justified until fresh-install E2E has passed on a disposable supported
instance.

## Disposable-instance release qualification

- Start from clean Ubuntu 24.04 amd64 Lightsail with a static IPv4.
- Run installer preflight, fresh dry run, then fresh install.
- Verify service, boot enablement, DKMS, UDP listener, address, endpoint DNS,
  required Lightsail rule, nftables lifecycle, and no UFW activation.
- Connect the first real test device and observe a handshake/Internet egress.
- Add/revoke a second client and verify isolation from RFC1918, metadata, Docker,
  and local bridges.
- Restart twice and confirm no duplicate nftables rules.
- Verify backup/restore and signed update rollback.
- Destroy the test instance and profiles after evidence is retained without
  secrets.
