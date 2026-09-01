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
   This includes the complete serial unittest suite, Python compilation,
   release/manifest build, zipapp version smoke, and installer preflight.
3. Confirm the tag is exactly `v` plus the code version.
4. Push the signed/annotated tag. The release workflow rebuilds and retests the
   artifact, verifies tag/version equality, signs `release.json`, and publishes
   all three assets.
5. On a managed host whose required host assets are already current, run
   `sudo awgctl update check`, then `sudo awgctl update apply --dry-run`, then
   `sudo awgctl update apply` and health. This path updates code only.

### Beta.4 to beta.5 host migration

Beta.5 adds a health-enforced client-expiry service/timer contract that the
signed updater cannot install. From a verified beta.5 source checkout, migrate
the host before relying on beta.5 code:

```bash
python3 install.py upgrade --dry-run --ingress-boundary lightsail
sudo python3 install.py upgrade --yes --ingress-boundary lightsail
sudo awgctl health
```

Use the `equivalent-external-firewall` choice only for a host that actually has
that attested boundary. The installer transaction writes and starts the exact
host units before it deploys and health-checks the new executable. A deploy or
health failure restores the prior release selector, exact prior managed files,
and the prior timer enabled/active state.

`awgctl update apply` remains compatible and fail closed across this boundary:
when beta.4 attempts a beta.5 code-only update without exact active expiry
assets, beta.5 health fails and the selector returns to beta.4. Do not describe
that refusal as a completed host migration, and do not tell operators to bypass
health or install units by hand.

The release and installation manifest schemas stay at 1 because AWG 3.1 does
not change either serialized shape. Server configuration is separately schema
2 and client metadata remains schema 3. Product and changelog versions still
advance normally.

The `make verify` installer check passes an explicit
`equivalent-external-firewall` test fixture so the read-only source gate can
exercise the supported parser/platform contract. It is not deployed-host
ingress evidence and must not be cited as such.

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

## AWG 3.1 qualification gates

The production `AWG31_QUALIFIED_PAIRS_V1` allowlist is intentionally empty for
this release. Do not publish a release as AWG 3.1-capable merely because the
model, dry runs, namespace renderer, or transaction tests pass, and do not add
the currently installed/newest package pair merely because it is available.

An allowlist change must name one exact native tools version and the matching
loaded/packaged module version and retain disposable Ubuntu 24.04 amd64
evidence for parsing, canonical native validation, classic compatibility,
AWG 3.1 handshake/traffic, restart, rollback, and relevant kernel/package
upgrade behavior. This qualifies the server pair only; it does not prove
Russian-network reachability.

After a qualified pair exists, release acceptance must also exercise the direct
cutover: prepared remains non-serving, the new external UDP rule precedes
activation, classic and AWG 3.1 are never concurrent, activation failure and
deadline both restore classic, confirmation rejects a handshake without both
counters increasing, and secure profile-delivery acknowledgement remains
separate.

Kat acceptance uses the free standalone native AmneziaWG iOS/iPadOS app and
requires a fresh handshake, increasing bidirectional counters, DNS, expected
egress IP, HTTPS, multi-megabyte download and upload, reconnect, screen-lock
resume, and Wi-Fi/cellular switching on the intended Russian network. Record
redacted timestamps/results only. IP blocking, blanket UDP blocking, or a UDP
whitelist may still prevent AWG; there is no alternate transport to claim.

Release notes must label evidence precisely: source/generated/local/prepared,
deployed-host, exact-package qualification, and Kat acceptance are distinct.
