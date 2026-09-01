# AWG 3.1 in-place qualification design

## Status and decision

This design replaces the proposed paid disposable-host qualification with an
operator-approved qualification on the existing Ubuntu 24.04 amd64 Lightsail
host. The qualification must use the exact installed AmneziaWG tools, loaded
module, packaged module, running kernel, and repository candidate. It must not
change the production `awg0` interface, its service, its listener, host
nftables, manager state, client profiles, package state, or kernel-module
state.

Passing this qualification may justify allowlisting the exact tested
tools/module pair for this host and a beta release. It does not constitute
disposable-host evidence, package/kernel-upgrade evidence, Russian-network
reachability, Kat-device acceptance, or a censorship-bypass guarantee. Those
absent evidence lanes must remain explicit in the receipt, changelog, and
release notes.

## Goals

- Exercise classic and `russia-ios-v1` AWG 3.1 traffic through the real native
  tools and loaded kernel module.
- Prove bidirectional overlay traffic and nonzero bidirectional transfer
  counters in isolated Linux network namespaces.
- Prove isolated-interface recreation and an AWG 3.1-to-classic rollback.
- Bind the result to exact tools, loaded module, packaged module, kernel,
  architecture, operating system, source commit, and qualification policy.
- Produce a bounded redacted JSON receipt with no keys, profiles, packet
  signatures, host addresses, public IP, instance identifier, or raw command
  output.
- Fail closed unless cleanup succeeds and every protected production invariant
  is unchanged.

## Non-goals

- Installing, reinstalling, upgrading, or removing apt packages, DKMS, kernel
  headers, or kernel modules.
- Stopping, restarting, reloading, or editing `awg-quick@awg0.service`.
- Creating, editing, exporting, rotating, revoking, or distributing a managed
  client profile.
- Changing the production UDP port or Lightsail ingress rules.
- Preparing, activating, confirming, or rolling back a production obfuscation
  transition during qualification.
- Claiming future-kernel compatibility, package-upgrade behavior, Russian
  reachability, or physical-device acceptance.

## Components

### Source-only qualification runner

Add `tools/qualify_awg31_host.py`. It is invoked explicitly from a clean source
checkout with root privileges and is not included as an installed `awgctl`
command. Keeping qualification source-only avoids adding a policy-bypass path
to the production CLI: the tool may construct an unallowlisted candidate only
inside its own temporary namespaces, while normal `awgctl obfuscation prepare`
continues to enforce `AWG31_QUALIFIED_PAIRS_V1`.

The runner uses dependency-injected command, clock, entropy, filesystem, and
namespace adapters so its orchestration and redaction behavior can be unit
tested without root or network mutation. The live adapter uses bounded command
timeouts and captures output only for validation; raw output is never copied
into the receipt.

### Redacted receipt

On success, write a root-owned mode `0600` JSON receipt under
`/opt/amneziawg/qualification/`. The schema contains only:

- schema and policy versions;
- UTC start/completion timestamps;
- source commit and dirty-worktree boolean;
- OS version, architecture, and kernel release;
- exact tools, loaded-module, packaged-module, and DKMS versions;
- named pass/fail checks for parsing, native validation, classic traffic,
  AWG 3.1 traffic, counters, recreation, rollback, cleanup, and production
  invariants;
- explicit evidence flags: `disposable_host=false`,
  `package_upgrade_test=false`, `future_kernel_test=false`,
  `russia_network=false`, and `physical_device=false`.

The receipt excludes generated field values, keys, PSKs, CPS/header-protection
material, namespace names, interface names, underlay/overlay addresses, host
network state, nftables contents, public IPs, and instance metadata. A separate
repository receipt may record the exact source commit, version pair, kernel,
and named results after human review, but never copy secrets or host identity.

## Safety invariants

Before entropy generation or namespace mutation, the live runner must require:

- effective UID zero;
- Ubuntu 24.04 amd64 and the expected source checkout;
- a clean source worktree whose `HEAD` equals `origin/main`;
- installed `awgctl` health with zero failures;
- production mode `classic`, transition state `none`, service exactly active,
  boot exactly enabled, interface `awg0` up, and one expected UDP listener;
- exact parseable and equal loaded/packaged module versions;
- no pre-existing qualifier namespaces, links, or temporary root.

The runner captures in memory, but does not emit, comparison digests for:

- protected manager configuration, generated/runtime configuration, client
  metadata/profiles, keys, transitions, and pending artifacts;
- production interface/address/peer/listener state;
- `awg-quick@awg0.service` active/enabled state;
- host nftables ruleset;
- module and package state.

The qualifier uses random names with a fixed `awgq-` prefix and Linux-safe
length limits. It rejects collisions instead of deleting anything it did not
create. All ephemeral credentials live beneath a new root-owned mode `0700`
temporary directory; files are mode `0600`. A registered cleanup journal owns
only exact resources created by the current process and removes them in reverse
order on success, failure, signal, or timeout.

After cleanup, the runner must prove that no qualifier namespace, link, file,
or process remains and that every protected production comparison digest and
textual service state is unchanged. Any cleanup or invariant failure produces
no qualifying receipt and exits nonzero. It must never attempt to repair a
production difference automatically.

## Live qualification sequence

1. Record the preflight snapshot and exact version evidence.
2. Generate one ephemeral server/client key pair, PSK, and header-protection
   key without printing or persisting their values outside the temporary root.
3. Create two isolated namespaces connected by a private veth underlay.
4. Create classic AmneziaWG interfaces, apply canonical classic configs, bring
   up overlay addresses, and prove ICMP in both directions.
5. Destroy only those isolated interfaces and recreate them using the same
   classic configs; repeat bidirectional traffic to prove recreation.
6. Replace the isolated interfaces with canonical `russia-ios-v1` configs
   generated by the candidate source. Require native config acceptance, a
   handshake, ICMP in both directions, and nonzero receive and transmit
   counters on both peers.
7. Destroy and recreate the AWG 3.1 interfaces and repeat the complete traffic
   and counter proof.
8. Roll the isolated pair back to canonical classic configs and repeat
   bidirectional traffic, proving the same native pair retains classic
   compatibility after the AWG 3.1 exercise.
9. Remove all owned resources, verify production invariants, and only then
   atomically write the redacted receipt.

Every command has a bounded timeout. Traffic checks use bounded retries based
on observable interface/handshake state rather than unbounded sleeps. The
runner avoids queries for unset `I1` through `I5`; counters and handshakes use
the safe peer-oriented query forms already used by the manager.

## Qualification decision and source policy

The exact pair may be added to `AWG31_QUALIFIED_PAIRS_V1` only when the live
receipt reports every required check as passing, cleanup as passing, and all
production invariants unchanged. Unit tests must continue to prove that absent,
malformed, mismatched, or any other pair fails closed before entropy or writes.

The policy documentation changes from “disposable-host qualified” to the exact
truth: “qualified on the target Ubuntu 24.04 amd64 Lightsail host through
isolated native namespace traffic.” Documentation must retain the missing
disposable, package-upgrade, future-kernel, Russian-network, and physical-device
evidence flags. A version bump to beta.6 is required before publishing the
nonempty production policy.

## Testing and delivery

Implementation follows test-driven development:

- unit tests for preflight rejection, exact-version binding, resource
  ownership, reverse cleanup, timeouts, signal/failure cleanup, invariant
  comparison, receipt schema, atomic mode/ownership, and secret redaction;
- contract tests that the installed CLI still cannot bypass an unqualified
  pair and that only the exact qualified pair passes after the policy change;
- workflow/static tests for any added operator command documentation;
- focused live qualification on this host only after unit tests pass;
- the complete `make verify` gate before merge/release.

Delivery is staged:

1. Implement and review the source-only qualifier while the production
   allowlist remains empty.
2. Run the live qualifier and retain the root-only receipt.
3. Review the redacted result and add the exact pair, repository receipt,
   documentation changes, beta.6 version, and changelog entry.
4. Merge through required CI and publish the signed beta.6 release.
5. Upgrade the host from the verified source/release path and run health.
6. Run production `obfuscation prepare` first as a dry run and then prepare the
   non-serving transaction. Report the generated transaction ID, old/new UDP
   ports, deadline contract, and exact new Lightsail rule without activating.
7. Activation waits for the external ingress rule and Kat's physical device.
   Confirmation and distribution acknowledgement wait for fresh bidirectional
   counters plus the complete manual acceptance checklist.

## Rollback and failure handling

Qualification failure removes only resources recorded in its ownership
journal, retains no credential material, writes no passing receipt, and leaves
the allowlist empty. A production-invariant mismatch stops work for manual
inspection; it never triggers automated production rollback.

Before a beta.6 policy release, rollback is ordinary source control because
production remains classic. After beta.6 installation, a prepared transition
is still non-serving and can be terminally cancelled. Once activated, the
existing transaction-specific synchronous/deadline rollback remains the only
supported live rollback mechanism.
