# Changelog

All notable changes are documented here. The project follows semantic
versioning while preserving explicit beta labels for unqualified host paths.

## 0.1.0-beta.5 - 2026-09-01

- Add a versioned AWG 3.1 server/profile model with `russia-ios-v1`, strict CPS
  validation, protected header-key custody, secret-safe status/diagnostics, and
  lossless schema-1 classic normalization. Client metadata remains schema 3.
- Add an exact tools/loaded/packaged-module capability gate. The production
  qualification allowlist is intentionally empty, so this release does not
  activate AWG 3.1 or claim successful use from inside Russia.
- Add one-interface `prepare`, `activate`, `confirm`, and `rollback` lifecycle
  with protected pending artifacts, exact ingress requirements, a verified
  classic backup, direct cutover, synchronous failure rollback, and an exact
  ten-minute transient rollback timer.
- Require a fresh post-activation Kat handshake and increasing receive and
  transmit counters before confirmation, while keeping secure profile delivery
  acknowledgement and full native-iOS acceptance as separate gates.
- Add explicit Lightsail/equivalent external-ingress attestation, exact UTC
  client expiration with a daily systemd timer, and transaction-aware service
  and canonical nftables lifecycle proof.
- Make expiry host assets part of management health: both canonical units must
  be root-owned mode `0644`, and the timer must be enabled and active. Signed
  code-only updates fail health and restore the prior selector on drift.
- Apply requested/current host configuration before installer upgrade health,
  with exact file and timer-state compensation on configuration, deployment,
  or health failure. Beta.4 hosts migrate through `install.py upgrade --yes`
  after reviewing its dry run.
- Require exact textual systemd state: persistent `enabled` and `active` for
  health, while installer rollback preserves supported persistent, runtime, or
  disabled prior enablement and exact active/inactive state.
- Build before entrypoint mutation and transactionally restore README,
  internal/public symlinks, completion, and their exact metadata on any later
  entrypoint, deploy, selector, or health failure.
- Reject upgrade `--apply-default-dns` and `--apply-live` before mutation;
  profile DNS changes and service restart are separate post-upgrade commands.
- Harden release workflow references, SemVer precedence, diagnostic directory
  creation, profile import, transition recovery, service/firewall coordination,
  and AWG 3.1 CPS redaction.
- Ship updated completion and repository-only end-to-end dry-run coverage for
  classic compatibility, preparation, activation rollback, timeout construction,
  confirmation rejection, and public-output redaction.
- Document that generated/source/local/prepared evidence is not deployed or Kat
  acceptance evidence, and that IP blocking or blanket/whitelist UDP policy has
  no AWG-only fallback in this project.

## 0.1.0-beta.4 - 2026-09-01

- Add an interactive, validation-first client profile wizard with a final
  review, safe cancellation, dry-run support, and secure delivery guidance.
- Preserve installed privilege settings during upgrades unless an operator
  explicitly overrides them.
- Reject undeclared operator-group members so local authorization cannot drift
  wider than the manager's declared policy.
- Deploy and health-check the split public/internal CLI before installing its
  final sudo grant, with compensating rollback for failed bootstraps.
- Preserve client recipient metadata and increment profile revisions during
  credential rotation.

## 0.1.0-beta.3 - 2026-09-01

- Added locked staging and separate operator identities with validated adoption,
  configurable scoped sudo, and transactional rollback.
- Added no-network transient systemd source builds and conservative hardening
  for the native awg-quick unit.
- Split public and internal entrypoints so lifecycle and migration helpers are
  outside the operator-facing grammar.
- Made Cloudflare's malware-blocking resolvers the fresh-install default while
  retaining named and custom DNS policies.
- Added client profile revision/delivery metadata and explicit distribution
  acknowledgement without changing peer identity.
- Added secure operator-owned profile/QR export paths and installation-schema
  declarations in release manifests.

## 0.1.0-beta.2 - 2026-09-01

- Made successful mutation commands honor the stable JSON response envelope.
- Rejected the unsafe/ambiguous `client export --stdout --json` combination.
- Updated GitHub workflow checkout runtime to the current maintained release.

## 0.1.0-beta.1 - 2026-09-01

- Added fresh Ubuntu 24.04 amd64 installation and working-host adoption.
- Added transactional client add/import/edit/revoke/rotate workflows.
- Added stable JSON envelopes and mutation dry runs.
- Added SHA-256-manifested backups, verification, and transactional restore.
- Added redacted diagnostics and an experimental namespace handshake test.
- Added immutable versioned deployment and Ed25519-signed GitHub updates.
- Added VPN-only nftables forwarding, isolation, and NAT lifecycle management.
