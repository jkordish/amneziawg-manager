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
python3 install.py install --dry-run --endpoint vpn.example.com
python3 install.py configure --dry-run --json
```

Tests run without root and must not read live credentials. The network namespace
self-test's renderer is unit-tested; the actual namespace test is explicitly
root-only and operator-triggered.

The production build path is deliberately stricter than `make build`: the
installer creates the staging identity, copies only `src/` and `tools/` into a
protected job, and invokes `tools/build_release.py` through `systemd-run` with
`PrivateNetwork=yes`. Tests may inject a local runner but exercise the same
command construction and output validation.

## Design rules

- Add a failing test before behavior.
- Preserve one-device/one-profile identity.
- Keep JSON contracts stable and secret-free.
- Keep mutations lock-protected, backed up, atomic, verified, and reversible.
- Keep public ingress in Lightsail and packet forwarding/NAT in dedicated local
  nftables tables.
- Never query `I1`–`I5` with the affected AmneziaWG 3.1 tooling.
- Preserve unknown/unrelated host firewall, Docker, service, and application
  state.

Fresh installation stays beta until the release candidate passes the checklist
on a disposable Ubuntu 24.04 amd64 Lightsail instance.
