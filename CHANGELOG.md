# Changelog

All notable changes are documented here. The project follows semantic
versioning while preserving explicit beta labels for unqualified host paths.

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
