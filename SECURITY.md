# Security policy

## Reporting a vulnerability

Do not open a public issue for a vulnerability that could expose VPN keys,
profiles, host access, or a practical firewall bypass. Use GitHub's private
security advisory flow for this repository. Include affected versions,
reproduction steps, impact, and a redacted diagnostic bundle when useful.

Never attach a client profile, QR image, private key, preshared key,
`HeaderProtectionKey`, CPS-generated packet bytes, raw `/opt/amneziawg/keys`,
or an unreviewed backup to an issue.

## Supported versions

Only the newest published beta or stable release is supported. During the beta,
the supported platform is Ubuntu 24.04 LTS amd64 with one `awg0` and an
explicitly attested Lightsail or equivalent external-firewall ingress boundary.

## Security design

- Root is required for mutations; operations serialize on a filesystem lock.
- Source builds run as a locked nologin staging user in a capability-free,
  no-network transient systemd worker; root validates the single output.
- The operator group receives scoped sudo for the public CLI only. Internal
  initialization, migration, and lifecycle commands use a separate path.
- Secrets are written with restrictive umask, root ownership, and mode `0600`.
- No command uses `eval` or `shell=True`; secrets are passed through stdin or
  protected files when an upstream tool requires them.
- The CLI never logs private keys, PSKs, complete profiles, or QR contents.
- AWG 3.1 output reports only a short SHA-256 fingerprint of the protected
  header key. CPS `I1`-`I5` material is removed from status, JSON, diagnostics,
  native-tool errors, and journal-derived text.
- AWG 3.1 preparation fails closed unless the exact `awg --version` and loaded
  and packaged module versions match a source-controlled qualification pair.
  The production allowlist is currently empty; repository behavior is not a
  claim that a package pair or Russian network path has been qualified.
- The source-only AWG 3.1 qualifier is root/operator-triggered and refuses a
  dirty or disconnected source revision, unhealthy/non-classic production, an
  active transition, version drift, or pre-existing qualifier resources. It
  may create only owned isolated `awgq-*` namespaces and links. After external
  health/status preflight it holds the existing manager mutation lock, directly
  revalidates locked state, and compares complete live plus aggregate
  protected production snapshots before and after, never repairs a mismatch,
  and writes a closed redacted receipt only after successful cleanup. That
  receipt explicitly disclaims disposable-host, package-upgrade, future-kernel,
  Russian-network, and physical-device evidence.
- Direct cutover is one transaction and one live configuration. It binds a
  protected backup, pending artifacts, ingress attestation, package evidence,
  activation deadline, handshake, and bidirectional counter floor. A failed or
  unconfirmed activation restores classic state.
- Service and firewall lifecycle operations share a protected intent and the
  global mutation lock. Internal hooks cannot authorize an unrelated public
  call, and firewall removal requires both the service and kernel interface to
  be absent.
- GitHub updates require an embedded Ed25519 public key, a valid signed
  manifest, an exact platform, and an artifact SHA-256 match.
- The attested external boundary controls public ingress. Host nftables is
  limited to VPN forwarding, isolation, and source NAT; there is intentionally
  no generic INPUT firewall.

AWG remains IP over UDP. IP blocking, blanket UDP blocking, or a restrictive
UDP whitelist can defeat it, and this project has no alternate transport.

Authenticated VPN clients may reach services listening on `awg0` or wildcard
host addresses. `awgctl health` warns about those listeners. Bind private
administration and monitoring services to loopback or another intended private
interface.
