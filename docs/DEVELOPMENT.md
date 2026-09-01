# Development

The project uses Python 3.12 and only the standard library. The release artifact
is an executable zipapp containing `awgctl` and the small installer/deployment
modules. Runtime integration uses normal Ubuntu tools through argument arrays;
there is no `shell=True`.

## Repository layout

```text
src/awgctl/       product CLI, contracts, backups, diagnostics, releases, self-test
src/awginstall/   settings, identities, confined workers, host/deploy transactions
tools/            zipapp and signed-manifest builders
tests/            dependency-free unittest suite
docs/             operator and contributor runbooks
.github/workflows CI and signed tag releases
```

## Local checks

```bash
make test
make build
dist/awgctl.pyz version
python3 install.py check
python3 install.py install --dry-run --endpoint vpn.example.com \
  --ingress-boundary lightsail
python3 install.py configure --dry-run --json
python3 -m unittest -v tests.test_end_to_end_dry_run tests.test_packaging
```

Tests run without root and must not read live credentials. The network namespace
self-test's renderer is unit-tested; the actual namespace test is explicitly
root-only and operator-triggered.

The source-only AWG 3.1 host qualifier is intentionally excluded from the
installed zipapp. After the source and tests have merged, an operator may run it
from an exact clean `main` checkout whose `HEAD` equals `origin/main`:

```bash
sudo python3 tools/qualify_awg31_host.py \
  --expected-tools 3.1.20260812 \
  --expected-module 3.1.20260812
```

The qualifier requires healthy classic production with no active transition,
captures production state before and after, and owns only token-scoped
`awgq-*` namespaces and links. It never reloads or reconfigures `awg0`, changes
packages/DKMS, restarts a service, or changes host nftables. A passing root-only
receipt under `/opt/amneziawg/qualification/` is exact-host isolated evidence;
it is not disposable-host, package-upgrade, future-kernel, Russian-network, or
physical-device evidence.

The production build path is deliberately stricter than `make build`: the
installer creates the staging identity, copies only `src/` and `tools/` into a
protected job, and invokes `tools/build_release.py` through `systemd-run` with
`PrivateNetwork=yes`. Tests may inject a local runner but exercise the same
command construction and output validation.

The zipapp copies the complete `awgctl` and `awginstall` packages, including
AWG 3.1 contracts, redaction, self-test rendering, host timer rendering, and
the internal dispatcher. The stable public selector and internal symlink both
point at the signed artifact. Persistent client expiry uses installed static
service/timer files; transaction-specific obfuscation recovery and rollback
render exact root-owned persistent units at runtime. They bind one transaction
ID and origin, are not reusable packaged templates, and are removed after the
terminal outcome.

## Serialized contracts

Increment a schema only when its serialized wire shape changes. Current
contracts are intentionally independent:

- release manifest schema 1 and installation schema 1;
- server configuration schema 2, with lossless schema-1 classic normalization;
- AWG profile schema 1;
- client metadata schema 3;
- transition, outcome, activation journal, service intent, backup manifest, and
  public JSON envelope schemas at their existing declared versions.

Do not renumber client metadata merely because the server model changed. Do not
renumber release/install manifests for new code that their existing file lists
and integrity fields already describe.

## Design rules

- Add a failing test before behavior.
- Preserve one-device/one-profile identity.
- Keep JSON contracts stable and secret-free.
- Keep mutations lock-protected, backed up, atomic, verified, and reversible.
- Keep public ingress in Lightsail and packet forwarding/NAT in dedicated local
  nftables tables, or explicitly attest the supported equivalent external
  firewall; never infer that boundary from platform metadata.
- Never query `I1`–`I5` with the affected AmneziaWG 3.1 tooling.
- Keep `AWG31_QUALIFIED_PAIRS_V1` empty until an exact tools/module candidate
  has completed the reviewed qualification policy. Adding a pair is a reviewed
  release decision based on a passing redacted receipt, not an automatic
  package-discovery side effect.
- Preserve unknown/unrelated host firewall, Docker, service, and application
  state.

Repository tests, source review, generated profiles, mocked dry runs, and a
local namespace self-test are separate non-deployment evidence lanes. Fresh
installation stays beta until the release candidate passes the disposable-host
checklist. AWG 3.1 remains separately unqualified until an exact native pair has
a reviewed live qualification receipt; Kat's in-Russia native-iOS checklist is
still a separate final acceptance lane.

`make verify` supplies `equivalent-external-firewall` only as an explicit
non-live parser/platform fixture for the read-only installer check. It does not
attest the CI runner's ingress or replace the persisted production setting.
