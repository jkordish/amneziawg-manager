# AWG 3.1 In-Place Qualification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Qualify the exact installed AmneziaWG 3.1 tools/module pair through isolated native traffic on the existing host, publish the qualified beta.6 policy, install it, and prepare a non-serving Kat transition without touching production traffic during qualification.

**Architecture:** A source-only Python qualifier reuses the manager's canonical classic/AWG 3.1 renderers but owns only randomly named network namespaces and a private temporary root. It records comparison digests internally, emits a bounded redacted receipt only after cleanup and production invariants pass, and leaves the production allowlist empty until that live receipt exists. A second policy/release change allowlists only the exact proven pair and preserves all external-ingress and physical-device gates.

**Tech Stack:** Python 3.12 standard library, `unittest`, native `ip`/`awg`/`modinfo`/`systemctl`/`nft` commands, GitHub Actions CI and signed releases, Ubuntu 24.04 amd64.

**Spec:** `docs/superpowers/specs/2026-09-01-awg31-in-place-qualification-design.md`

## Global Constraints

- Qualification runs on the existing Ubuntu 24.04 amd64 Lightsail host because the user declined a paid disposable instance.
- Never install/reinstall/upgrade/remove packages, headers, DKMS, kernels, or modules during qualification.
- Never stop/restart/reload/edit `awg-quick@awg0.service`, mutate `awg0`, change its UDP listener, alter host nftables, or write manager/client/transition state during qualification.
- The source-only qualifier is not an installed `awgctl` subcommand and cannot bypass `AWG31_QUALIFIED_PAIRS_V1` in production commands.
- Every command uses an argument array and a bounded timeout; there is no `shell=True`.
- Ephemeral secrets remain beneath one root-owned `0700` temporary directory with `0600` files and are never emitted in errors, logs, or receipts.
- The receipt must explicitly retain `disposable_host=false`, `package_upgrade_test=false`, `future_kernel_test=false`, `russia_network=false`, and `physical_device=false`.
- Adding an allowlist pair requires a successful live receipt, cleanup proof, unchanged production invariants, review, beta.6 version bump, full `make verify`, merge, and signed release.
- Production preparation is non-serving. Activation waits for the new Lightsail UDP rule and Kat's physical iPhone.

---

### Task 1: Qualification contracts, command boundary, and redacted evidence

**Files:**
- Create: `tools/qualify_awg31_host.py`
- Create: `tests/test_awg31_qualification.py`

**Interfaces:**
- Consumes: `awgctl.core.inspect_awg_versions`, `awgctl.core.AWG31_QUALIFICATION_POLICY_VERSION`, `awgctl.core.sha256_bytes`.
- Produces: `QualificationError`; `run_command(argv: Sequence[str], *, input_data: bytes | None = None, timeout: float = 20) -> subprocess.CompletedProcess[bytes]`; `VersionEvidence`; `ProductionSnapshot`; `build_receipt(*, source_commit: str, dirty_worktree: bool, os_version: str, architecture: str, kernel: str, versions: VersionEvidence, checks: Mapping[str, bool], started_at: str, completed_at: str) -> dict[str, object]`; and `atomic_write_receipt(receipt: Mapping[str, object], output_dir: pathlib.Path, filename: str) -> pathlib.Path` for Task 2 and Task 3.

- [ ] **Step 1: Write failing contract and redaction tests**

Add tests that import `tools/qualify_awg31_host.py` with `importlib.util` and prove strict types, bounded command execution, deterministic receipt keys, and secret exclusion:

```python
class QualificationContractTests(unittest.TestCase):
    def test_receipt_is_bounded_and_names_absent_evidence(self):
        receipt = qualification.build_receipt(
            source_commit="a" * 40,
            dirty_worktree=False,
            os_version="24.04",
            architecture="amd64",
            kernel="7.0.0-1011-aws",
            versions=qualification.VersionEvidence(
                tools="3.1.20260812",
                loaded_module="3.1.20260812",
                packaged_module="3.1.20260812",
                dkms="3.1.20260812",
            ),
            checks={name: True for name in qualification.REQUIRED_CHECKS},
            started_at="2026-09-01T20:00:00Z",
            completed_at="2026-09-01T20:01:00Z",
        )
        self.assertEqual(set(receipt), qualification.RECEIPT_FIELDS)
        self.assertEqual(receipt["evidence"]["disposable_host"], False)
        self.assertEqual(receipt["evidence"]["russia_network"], False)
        self.assertNotIn("namespace", json.dumps(receipt).lower())

    def test_public_error_redacts_all_native_key_directives(self):
        secret = "A" * 43 + "="
        error = qualification.safe_error(
            f"PrivateKey = {secret}\nHeaderProtectionKey = {secret}\nI1 = <b 0xdeadbeef>"
        )
        self.assertNotIn(secret, error)
        self.assertNotIn("deadbeef", error)
```

- [ ] **Step 2: Run the focused test and verify red**

Run: `python3 -m unittest -v tests.test_awg31_qualification.QualificationContractTests`

Expected: import failure because `tools/qualify_awg31_host.py` does not exist.

- [ ] **Step 3: Implement strict data contracts and the command boundary**

Implement frozen dataclasses and constants with no host mutation:

```python
REQUIRED_CHECKS = (
    "version_parsing", "native_validation", "classic_traffic",
    "classic_recreation", "awg31_traffic", "awg31_counters",
    "awg31_recreation", "classic_rollback", "cleanup",
    "production_invariants",
)

@dataclasses.dataclass(frozen=True)
class VersionEvidence:
    tools: str
    loaded_module: str
    packaged_module: str
    dkms: str

@dataclasses.dataclass(frozen=True)
class ProductionSnapshot:
    protected_tree_sha256: str
    interface_sha256: str
    listener_sha256: str
    nftables_sha256: str
    service_state: tuple[str, str]
    package_sha256: str
```

`run_command` must reject empty/non-string arguments, set `stdout`/`stderr` pipes, use `timeout`, never use a shell, and convert failures through `safe_error`, which calls the existing AWG-config redactor and additionally removes CPS bodies and key-shaped base64.

`build_receipt` must reject missing/extra checks and any false required check. `atomic_write_receipt` must create `/opt/amneziawg/qualification` as root `0700`, use an exclusive `0600` temporary file, fsync file and directory, and refuse symlink/non-root/writable-parent paths.

- [ ] **Step 4: Run contract tests and verify green**

Run: `python3 -m unittest -v tests.test_awg31_qualification.QualificationContractTests`

Expected: all contract/redaction/atomic-write tests pass.

- [ ] **Step 5: Commit Task 1**

```bash
git add tools/qualify_awg31_host.py tests/test_awg31_qualification.py
git commit -m "Add AWG 3.1 qualification contracts"
```

---

### Task 2: Owned namespace lifecycle and real traffic orchestration

**Files:**
- Modify: `tools/qualify_awg31_host.py`
- Modify: `tests/test_awg31_qualification.py`
- Reuse unchanged: `src/awgctl/selftest.py:20-145`
- Reuse unchanged: `src/awgctl/core.py:1702-1768`

**Interfaces:**
- Consumes: Task 1 command/redaction contracts, `awgctl.selftest.render_peer_configs`, and `awgctl.core.build_russia_ios_obfuscation`.
- Produces: `OwnedResources`; `NamespaceQualifier`; `qualify_mode(mode: str, obfuscation: Mapping[str, object], *, header_protection_key: bytes | None) -> dict[str, bool]`; `parse_transfer_counters(output: bytes) -> tuple[int, int]`; and `cleanup_owned_resources(resources: OwnedResources) -> None` for Task 3.

- [ ] **Step 1: Write failing orchestration and cleanup tests**

Use a scripted fake command runner. Test that only exact `awgq-` namespace/link names created by the current process are deleted, cleanup is reverse-ordered after every injected failure point, both ping directions are required, counters must be nonzero for both peers, and no unsafe `I1`-`I5` query occurs:

```python
class NamespaceQualificationTests(unittest.TestCase):
    def test_failure_cleans_only_current_owned_resources_in_reverse_order(self):
        runner = ScriptedRunner(fail_when=lambda argv: argv[-3:] == ["link", "set", "up"])
        qualifier = qualification.NamespaceQualifier(runner=runner, token="a1b2c3")
        with self.assertRaises(qualification.QualificationError):
            qualifier.qualify(classic_obfuscation(), awg31_obfuscation(), b"h" * 32)
        self.assertEqual(runner.deleted_namespaces, ["awgq-c-a1b2c3", "awgq-s-a1b2c3"])
        self.assertNotIn("awg0", " ".join(runner.flattened_argv))

    def test_awg31_requires_bidirectional_ping_and_both_peer_counters(self):
        for counters in ("0 10", "10 0", "0 0"):
            with self.subTest(counters=counters), self.assertRaises(qualification.QualificationError):
                qualification.require_bidirectional_counters(counters, counters)
```

- [ ] **Step 2: Run orchestration tests and verify red**

Run: `python3 -m unittest -v tests.test_awg31_qualification.NamespaceQualificationTests`

Expected: missing `NamespaceQualifier`/counter helpers.

- [ ] **Step 3: Implement exact resource ownership and mode cycles**

Implement an ownership journal that records a resource only after successful creation. Use two namespaces, one veth pair, and an `awgt` interface inside each namespace. Fail if any generated name exists before mutation.

Call `render_peer_configs` with the generated server/client private/public keys,
PSK, candidate obfuscation mapping, optional 32-byte header key, and port 51871.
Use these exact candidate mappings:

```python
classic = {
    "Jc": 6, "Jmin": 8, "Jmax": 80, "S1": 25, "S2": 75,
    "H1": 101, "H2": 102, "H3": 103, "H4": 104,
}
awg31 = core.build_russia_ios_obfuscation(
    ephemeral_root / "header-protection",
    mtu=1280,
)
```

Run this exact isolated sequence:

1. create namespaces/veth/underlay;
2. classic apply, bidirectional ping, destroy/recreate tunnel interfaces, repeat;
3. AWG 3.1 apply with one 32-byte header key, bidirectional ping, safe peer transfer query, destroy/recreate, repeat;
4. classic apply again and repeat bidirectional ping;
5. cleanup all owned resources.

Query only safe peer output such as `awg show awgt transfer` and `awg show awgt latest-handshakes`; never query individual AWG 3.1 fields. Poll handshake/traffic with bounded monotonic deadlines and at most five attempts.

- [ ] **Step 4: Run orchestration tests and existing renderer tests**

Run: `python3 -m unittest -v tests.test_awg31_qualification.NamespaceQualificationTests tests.test_selftest tests.test_awg31.Awg31RenderingTests`

Expected: all pass.

- [ ] **Step 5: Commit Task 2**

```bash
git add tools/qualify_awg31_host.py tests/test_awg31_qualification.py
git commit -m "Exercise isolated classic and AWG 3.1 traffic"
```

---

### Task 3: Production invariant snapshot, root CLI, and operator documentation

**Files:**
- Modify: `tools/qualify_awg31_host.py`
- Modify: `tests/test_awg31_qualification.py`
- Modify: `docs/DEVELOPMENT.md`
- Modify: `docs/RELEASING.md`
- Modify: `SECURITY.md`

**Interfaces:**
- Consumes: Tasks 1-2 contracts/orchestrator.
- Produces: `CommandRunner`, `ProtectedReader`, and `ReceiptWriter` protocols; `capture_production_snapshot(command_runner: CommandRunner, protected_reader: ProtectedReader) -> ProductionSnapshot`; `verify_preflight(*, expected_tools: str, expected_module: str, command_runner: CommandRunner) -> VersionEvidence`; `LiveAdapters(command_runner, protected_reader, namespace_factory, clock)`; `execute_qualification(*, expected_tools: str, expected_module: str, adapters: LiveAdapters, receipt_writer: ReceiptWriter) -> pathlib.Path`; `main(argv: Sequence[str] | None = None, *, stdout: TextIO | None = None) -> int`; and the operator command `sudo python3 tools/qualify_awg31_host.py --expected-tools 3.1.20260812 --expected-module 3.1.20260812`.

- [ ] **Step 1: Write failing preflight/invariant/CLI tests**

Cover non-root, dirty/non-main source, nonzero health failures, non-classic mode, active transition, inactive service, existing qualifier resources, version mismatch, before/after snapshot mismatch, receipt suppression on any failure, and success-only JSON output:

```python
class QualificationCliTests(unittest.TestCase):
    def test_snapshot_mismatch_blocks_receipt_without_repair(self):
        before = qualification.ProductionSnapshot(
            protected_tree_sha256="a" * 64,
            interface_sha256="b" * 64,
            listener_sha256="c" * 64,
            nftables_sha256="d" * 64,
            service_state=("active", "enabled"),
            package_sha256="e" * 64,
        )
        after = dataclasses.replace(before, nftables_sha256="b" * 64)
        writer = mock.Mock()
        adapters = mock.Mock(spec=qualification.LiveAdapters)
        adapters.capture_snapshot.side_effect = (before, after)
        with self.assertRaisesRegex(qualification.QualificationError, "production invariants"):
            qualification.execute_qualification(
                expected_tools="3.1.20260812",
                expected_module="3.1.20260812",
                adapters=adapters,
                receipt_writer=writer,
            )
        writer.assert_not_called()

    def test_success_stdout_contains_only_receipt_path_and_nonsecret_summary(self):
        output = io.StringIO()
        with mock.patch.object(
            qualification,
            "execute_qualification",
            return_value=pathlib.Path("/opt/amneziawg/qualification/receipt.json"),
        ):
            result = qualification.main(
                ["--expected-tools", "3.1.20260812", "--expected-module", "3.1.20260812"],
                stdout=output,
            )
        self.assertEqual(result, 0)
        self.assertNotRegex(output.getvalue(), qualification.KEY_SHAPED_BASE64)
        self.assertNotIn("I1", output.getvalue())
```

- [ ] **Step 2: Run CLI tests and verify red**

Run: `python3 -m unittest -v tests.test_awg31_qualification.QualificationCliTests`

Expected: missing preflight/snapshot/CLI interfaces.

- [ ] **Step 3: Implement read-only production snapshots and main**

Capture canonical JSON or sorted byte output from fixed commands/paths and hash it only in memory. Include:

```text
git status --porcelain=v1
git rev-parse HEAD
git rev-parse origin/main
/usr/local/sbin/awgctl health --json
/usr/local/sbin/awgctl status --json
systemctl is-active awg-quick@awg0.service
systemctl is-enabled awg-quick@awg0.service
ip -j address show dev awg0
awg show awg0 peers
awg show awg0 latest-handshakes
ss -H -lunp
nft -j list ruleset
dpkg-query -W amneziawg amneziawg-tools amneziawg-dkms
dkms status
```

Hash protected fixed trees using descriptor-relative reads with no symlink following. Store only aggregate hashes in `ProductionSnapshot`; do not place hashes in the receipt. Re-run the full snapshot after namespace cleanup and require dataclass equality.

`main` must require explicit expected versions, check root, install SIGINT/SIGTERM cleanup handlers, use `umask(0o077)`, and print one secret-free JSON envelope plus the receipt path. It must never call `logger` with command output.

- [ ] **Step 4: Document exact boundaries and invocation**

Update contributor/release/security docs to state that this source-only tool is operator-triggered, root-only, does not alter production state, and produces exact-host isolated evidence rather than disposable/package-upgrade/Russia/device evidence.

- [ ] **Step 5: Run focused and full source verification**

Run:

```bash
python3 -m unittest -v tests.test_awg31_qualification tests.test_selftest tests.test_awg31
python3 -m py_compile tools/qualify_awg31_host.py
git diff --check
make verify
```

Expected: all  qualification tests and the complete repository gate pass.

- [ ] **Step 6: Commit Task 3**

```bash
git add tools/qualify_awg31_host.py tests/test_awg31_qualification.py docs/DEVELOPMENT.md docs/RELEASING.md SECURITY.md
git commit -m "Add production-safe AWG 3.1 host qualification"
```

---

### Task 4: Merge the empty-policy qualifier and produce live evidence

**Files:**
- No source changes during the live run.
- Create at runtime only: `/opt/amneziawg/qualification/TIMESTAMP-3.1.20260812.json`

**Interfaces:**
- Consumes: Tasks 1-3 qualifier with `AWG31_QUALIFIED_PAIRS_V1` still empty.
- Produces: one reviewed root-only receipt and a pass/fail decision for Task 5.

- [ ] **Step 1: Push the implementation branch and open a PR**

```bash
git push -u origin HEAD
gh pr create --base main \
  --title "Add in-place AWG 3.1 qualification" \
  --body "Adds a source-only, root-triggered qualifier while leaving the production allowlist empty. It owns only isolated awgq-* namespaces, verifies production state before and after, and cannot mutate awg0."
```

The PR body must state that the qualifier does not yet change the allowlist and cannot touch production `awg0`.

- [ ] **Step 2: Wait for required CI and resolve every review thread**

Run `gh pr checks --watch`, inspect any failures, fix through TDD, reply to review threads, and verify every thread is resolved before merge.

- [ ] **Step 3: Merge, fast-forward local main, and re-verify health**

```bash
gh pr merge --rebase
git switch main
git pull --ff-only
sudo awgctl health --json
```

- [ ] **Step 4: Run the live qualifier from exact clean main**

```bash
sudo python3 tools/qualify_awg31_host.py \
  --expected-tools 3.1.20260812 \
  --expected-module 3.1.20260812
```

Expected: a root-only receipt path, all required checks pass, no raw keys/config/CPS in stdout, production service remains active, and production snapshot comparison passes.

- [ ] **Step 5: Independently inspect the receipt and live cleanup**

Verify mode/owner/schema, all check booleans, explicit absent-evidence flags, no `awgq-` namespaces/links/processes, `awg0` listener/state, health zero failures, and unchanged managed Git tree. If any condition fails, stop with the allowlist empty.

---

### Task 5: Add the exact policy pair, redacted receipt, and beta.6 release candidate

**Files:**
- Modify: `src/awgctl/core.py:125-131`
- Modify: `tests/test_awg31.py:760-835`
- Modify: `tests/test_end_to_end_dry_run.py:200-210`
- Modify: `src/awgctl/version.py`
- Modify: `pyproject.toml`
- Modify: `CHANGELOG.md`
- Modify: `README.md`
- Modify: `docs/ARCHITECTURE.md`
- Modify: `docs/INSTALL.md`
- Modify: `docs/OPERATIONS.md`
- Modify: `docs/RELEASING.md`
- Modify: `docs/DEVELOPMENT.md`
- Create: `docs/qualification/2026-09-01-awg31-3.1.20260812.md`

**Interfaces:**
- Consumes: successful Task 4 receipt for exact pair `("3.1.20260812", "3.1.20260812")`.
- Produces: beta.6 source policy that accepts exactly that pair and no other pair.

- [ ] **Step 1: Write failing exact-policy tests before changing the constant**

```python
def test_production_policy_contains_only_the_reviewed_exact_host_pair(self):
    self.assertEqual(
        core.AWG31_QUALIFIED_PAIRS_V1,
        frozenset({("3.1.20260812", "3.1.20260812")}),
    )
    evidence = core.require_awg31_capability(
        command_runner=self.runner_for("3.1.20260812", "3.1.20260812"),
        loaded_version_reader=lambda: "3.1.20260812\n",
    )
    self.assertTrue(evidence["qualified"])

def test_neighboring_or_mismatched_pairs_remain_unqualified(self):
    for tools, module in (("3.1.20260811", "3.1.20260812"), ("3.1.20260812", "3.1.20260813")):
        with self.assertRaises(core.AwgctlError):
            core.require_awg31_capability(
                command_runner=self.runner_for(tools, module),
                loaded_version_reader=lambda value=module: value + "\n",
            )
```

- [ ] **Step 2: Run exact-policy tests and verify red**

Run: `python3 -m unittest -v tests.test_awg31.Awg31CapabilityTests tests.test_end_to_end_dry_run`

Expected: production-pair assertion fails while the allowlist is empty.

- [ ] **Step 3: Add only the proven exact pair**

```python
AWG31_QUALIFIED_PAIRS_V1: frozenset[tuple[str, str]] = frozenset({
    ("3.1.20260812", "3.1.20260812"),
})
```

Retain all absent/malformed/mismatched/unlisted failure tests and replace only assertions that the production policy is empty.

- [ ] **Step 4: Add the reviewed repository receipt and honest documentation**

The repository receipt records the source commit, host OS/architecture/kernel, exact pair, named pass results, cleanup/invariant results, root-only live receipt path, and absent evidence flags. It must contain no public IP, instance ID, keys, config, CPS, namespaces, or comparison hashes.

Update documentation to say the pair is qualified on the exact target host through isolated native traffic, not disposable/package-upgrade/future-kernel/Russia/device qualified.

- [ ] **Step 5: Bump beta.6 consistently**

Set `VERSION = "0.1.0-beta.6"`, `pyproject.toml` version `0.1.0b6`, and add a dated beta.6 changelog section describing the exact pair and evidence limits.

- [ ] **Step 6: Run policy tests and full verification**

```bash
python3 -m unittest -v tests.test_awg31 tests.test_end_to_end_dry_run tests.test_awg31_qualification tests.test_packaging
git grep -nE '(^|[^A-Za-z0-9+/])[A-Za-z0-9+/]{43}=($|[^A-Za-z0-9+/=])' -- ':!tests/**' ':!release-signing-key.pub' ':!src/awgctl/releases.py'
git diff --check
make verify
```

Expected: focused tests and all repository gates pass; secret-pattern guard finds nothing.

- [ ] **Step 7: Commit the policy release candidate**

```bash
git add src/awgctl/core.py src/awgctl/version.py pyproject.toml CHANGELOG.md README.md docs tests
git commit -m "Qualify AWG 3.1 pair for the target host"
```

---

### Task 6: Merge, sign, publish, and install beta.6

**Files:**
- No new source files beyond Task 5.

**Interfaces:**
- Consumes: reviewed beta.6 candidate and required CI.
- Produces: signed GitHub beta.6 release installed on the target host.

- [ ] **Step 1: Push, open PR, and resolve CI/review**

```bash
git push -u origin HEAD
gh pr create --base main \
  --title "Qualify AWG 3.1 pair for the target host" \
  --body "All isolated native traffic, recreation, rollback, cleanup, and production-invariant checks passed for tools/module 3.1.20260812 on the target Ubuntu 24.04 amd64 host. Evidence does not claim a disposable host, package/future-kernel upgrade, Russia, or physical-device acceptance."
gh pr checks --watch
```

Address every CI or review finding with a failing test first, reply to and
resolve every review thread, and merge via rebase only when the PR reports
`mergeStateStatus: CLEAN`.

- [ ] **Step 2: Fast-forward local main and verify exact merged source**

```bash
git switch main
git pull --ff-only
git status --short --branch
make verify
```

- [ ] **Step 3: Publish signed beta.6**

```bash
git tag -a v0.1.0-beta.6 -m 'AmneziaWG Manager v0.1.0-beta.6'
git push origin refs/tags/v0.1.0-beta.6
release_run=$(gh run list --workflow 'Signed release' --branch v0.1.0-beta.6 --limit 1 --json databaseId --jq '.[0].databaseId')
test -n "$release_run"
gh run watch "$release_run" --exit-status
gh release view v0.1.0-beta.6
```

Confirm the workflow tests, builds, signs `release.json`, and publishes all three assets.

- [ ] **Step 4: Verify signed updater and install through source upgrade**

Because documentation/share files changed, use the source upgrade transaction:

```bash
sudo awgctl update check --channel beta --json
sudo awgctl update apply --channel beta --dry-run --json
python3 install.py upgrade --dry-run --ingress-boundary lightsail
sudo python3 install.py upgrade --yes --ingress-boundary lightsail
sudo awgctl version
sudo awgctl health --json
sudo awgctl obfuscation show --json
```

Expected: installed beta.6, zero health failures, classic mode, no transition, exact pair visible.

---

### Task 7: Prepare the non-serving production transition

**Files:**
- Runtime-only protected artifacts under `/opt/amneziawg/pending/obfuscation/TRANSACTION_ID/` and an ordinary verified classic backup.

**Interfaces:**
- Consumes: installed beta.6 exact-pair policy, healthy classic host, managed `kat-iphone`.
- Produces: one prepared non-serving transaction and the exact new Lightsail UDP rule for the user.

- [ ] **Step 1: Run preparation dry run and inspect every gate**

```bash
sudo awgctl obfuscation prepare \
  --mode awg31 --profile russia-ios-v1 \
  --client kat-iphone --dry-run --json
```

Require exact qualified versions, server/client consistency, Kat active/pending, no drift, no active transition, and a reported candidate port without writes.

- [ ] **Step 2: Create the non-serving prepared transaction**

```bash
sudo awgctl obfuscation prepare \
  --mode awg31 --profile russia-ios-v1 \
  --client kat-iphone --json
```

Record only transaction ID, old/new UDP ports, backup name, and required Lightsail rule. Do not expose profiles, keys, CPS, or header-protection material.

- [ ] **Step 3: Verify preparation did not alter the live tunnel**

```bash
sudo awgctl status --json
sudo awgctl health --json
sudo awgctl obfuscation show --json
systemctl is-active awg-quick@awg0.service
```

Expected: live mode remains classic on the old port; service/interface stay active; transition is `prepared`; Kat's installed profile and distribution metadata are unchanged.

- [ ] **Step 4: Hand off the two external gates without activating**

Report `Custom / UDP / NEW_PORT / 0.0.0.0/0` for Lightsail and the ten-minute activation contract. Activation requires confirmation that the new rule exists and Kat's intended iPhone is ready. Do not remove the classic port, activate, mark distributed, or delete the current delivery copy before those confirmations.

---

## Final verification checklist

- [ ] Source `main` equals `origin/main` and is clean.
- [ ] Required GitHub CI and signed beta.6 release workflow pass.
- [ ] Installed selectors resolve to beta.6 and the install manifest verifies.
- [ ] Production health has zero failures; existing warnings are reported, not hidden.
- [ ] Qualifier resources and credentials are absent after the live run.
- [ ] Root-only receipt and repository receipt contain no secrets or host identity.
- [ ] Only `("3.1.20260812", "3.1.20260812")` is allowlisted.
- [ ] Production remains classic after preparation; new port is not serving yet.
- [ ] Lightsail ingress, activation, Kat bidirectional/device acceptance, confirmation, distribution acknowledgement, old-rule removal, and delivery-copy cleanup remain explicitly external/future until proved.
