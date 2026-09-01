# Security policy

## Reporting a vulnerability

Do not open a public issue for a vulnerability that could expose VPN keys,
profiles, host access, or a practical firewall bypass. Use GitHub's private
security advisory flow for this repository. Include affected versions,
reproduction steps, impact, and a redacted diagnostic bundle when useful.

Never attach a client profile, QR image, private key, preshared key, raw
`/opt/amneziawg/keys`, or an unreviewed backup to an issue.

## Supported versions

Only the newest published beta or stable release is supported. During the beta,
the supported platform is Ubuntu 24.04 LTS amd64 on AWS Lightsail.

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
- GitHub updates require an embedded Ed25519 public key, a valid signed
  manifest, an exact platform, and an artifact SHA-256 match.
- Lightsail controls public ingress. Host nftables is limited to VPN forwarding,
  isolation, and source NAT; there is intentionally no generic INPUT firewall.

Authenticated VPN clients may reach services listening on `awg0` or wildcard
host addresses. `awgctl health` warns about those listeners. Bind private
administration and monitoring services to loopback or another intended private
interface.
