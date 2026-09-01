# Architecture and trust boundaries

## Sources of truth

`/opt/amneziawg/config/server.json` stores stable non-secret configuration.
Server schema 2 carries either a losslessly normalized classic profile or a
versioned AWG 3.1 profile. Legacy server schema 1 remains readable and
normalizes to classic without changing its nine obfuscation values. Client
metadata is a separate serialized contract and remains schema 3.

Keys live in separate protected files, and every client has explicit metadata.
In AWG 3.1 mode the 32-byte `HeaderProtectionKey` is held in a root-only key
file; manager state contains only its protected path. Rendering receives the
material explicitly. Public output exposes at most a 12-hex SHA-256 fingerprint
and never the key or CPS-generated `I1`-`I5` packet bytes.
The manager renders `/opt/amneziawg/generated/awg0.conf`, validates it through
the native tools and a disposable interface, then atomically installs it at
`/etc/amnezia/amneziawg/awg0.conf`.

`SaveConfig=true` is never used. Manual edits are reported as drift and block
mutations until an operator reconciles them.

## Public ingress and transport boundary

Installation state must explicitly attest `lightsail` or
`equivalent-external-firewall` as the public-ingress boundary. The manager does
not infer a provider from Ubuntu, amd64, or generic cloud metadata. `awgctl`
never enables UFW, creates nftables/iptables INPUT filtering, duplicates public
port policy, or uses cloud credentials. `awgctl aws-rule` reports the one
required public UDP rule and its attested owner.

AWG 3.1 changes the native AmneziaWG UDP packet representation; it is not a
second transport. Destination IP blocking, blanket UDP blocking, and UDP
whitelists can still stop it. There is no XRay, TCP/TLS encapsulation, or other
AWG-only fallback in this architecture.

Because there is intentionally no host INPUT firewall, an authenticated VPN
peer may reach a service bound to `awg0` or `0.0.0.0`. Health reports wildcard
listeners—including Prometheus/node-exporter patterns—as warnings. Fix the
service binding or remove the listener; do not conceal it with an undocumented
INPUT policy.

## VPN forwarding and NAT

Local packet processing is still required. Two clearly owned nftables tables
follow the `awg0` lifecycle:

- `ip amneziawg_forward`: source validation, established return traffic,
  private/reserved destination blocking, external-interface restriction, and a
  tunnel default drop.
- `ip amneziawg_nat`: source masquerading only for the VPN subnet leaving the
  configured external interface.

Forwarded VPN traffic is blocked from RFC1918, CGNAT, loopback, link-local/AWS
metadata, multicast, documentation, benchmark, reserved ranges, Docker
bridges, other interfaces, and lateral destinations. Internet egress through
the configured external interface remains allowed.

If Docker's `DOCKER-USER` chain exists, three comment-tagged integration rules
bridge the VPN decision into Docker's later drop policy. If Docker is absent,
those rules are neither required nor created. Unrelated Docker, system, and
application rules are never flushed or rewritten. `nft flush ruleset` is never
used.

## Client trust boundary

One profile equals one physical device. Each managed device gets a unique
private/public keypair, PSK, `/32` address, server peer, metadata record, profile,
and QR. Revocation removes that one server peer before retaining its material
under `revoked/`; rotation replaces it and archives the old identity.

External peers imported from an existing server can be listed, labeled, and
revoked without inventing a private key. Profile-dependent operations remain
unavailable until the exact profile is securely imported.

Kat's AWG 3.1 target is the free standalone native AmneziaWG app for
iOS/iPadOS. A generated configuration or QR is still a credential at rest, not
proof that the app imported it, connected in Russia, resolved DNS, or carried
traffic. Delivery acknowledgement and network acceptance are separate records.

## AWG 3.1 qualification and direct cutover

Capability inspection binds the exact native tools version to matching loaded
and packaged module versions. Only pairs in the versioned source allowlist may
prepare AWG 3.1. The production allowlist is intentionally empty in this
release, so the state machine is present but cannot activate a real pair.

Preparation is non-serving: it validates Kat and the complete managed client
set, selects an unused UDP port, creates an ordinary verified classic backup,
and writes protected pending server/profile artifacts. It does not change
`awg0`, the runtime config, current profiles, or distribution metadata.

Activation directly replaces classic with AWG 3.1 on the same interface after
the operator attests the new ingress rule. A protected recovery journal is
armed before artifact installation. The manager reloads and proves the exact
configuration, captures a fresh handshake and RX/TX floor, and creates an
absolute-deadline transient systemd rollback unit. Classic and AWG 3.1 are
never live together. Confirmation requires a post-activation handshake plus
both counters increasing; failure or timeout restores the bound classic backup.

## Transactions and audit

Mutation commands acquire `/run/lock/awgctl.lock`, verify no drift, create a
backup/snapshot, stage and validate changes, commit atomically, reload or
restart only when needed, verify runtime identity, and roll back on failure.
Non-secret events are logged with syslog/journald tag `awgctl`.

The awg-quick PostUp/PostDown hooks coordinate through a protected durable
service-operation intent. Hooks normally take the same mutation lock, reject an
unrelated generation/transition, and prove canonical nftables postconditions.
Firewall down additionally requires the systemd service and kernel interface to
be absent. This avoids a public reusable bearer while allowing bounded crash
compensation.

No private key, PSK, complete profile, or QR content is printed or logged by a
normal command.

## Privilege separation

Root remains the only identity that can read VPN secrets, write `/opt`, mutate
network state, or run the native `awg-quick` service. The public entrypoint is
`/usr/local/sbin/awgctl`; internal initialization, migration, and lifecycle
helpers are accepted through `/opt/amneziawg/libexec/awgctl-internal`.

The locked `awgctl` account has a `nologin` shell, no password, no supplemental
groups, and a `0700` home under `/var/lib`. It is only a staging worker. Source
builds receive a minimal `src/` and `tools/` copy, run in a transient systemd
unit with no capabilities or network, and cannot access VPN secret paths. Root
accepts only a regular single-link output with the expected UID, mode, and
bounded size.

Operators belong to the separate `awgctl-admin` group. The default sudoers file
allows only `/usr/local/sbin/awgctl` as root with `NOSETENV`; it does not grant a
shell, the internal entrypoint, package tools, or generic systemctl/nft access.
Custom policy is recorded in `config/installation.json` and checked by health.

The native service remains root-run. Its conservative drop-in preloads the
module before sandboxing, protects host filesystems/home/devices/kernel
interfaces, and retains the address families needed by awg-quick. The installer
validates and rolls back manager-owned host files on failure. It also installs
a persistent daily client-expiry service/timer. Obfuscation rollback units are
transaction-specific transient units, not reusable static service files.
