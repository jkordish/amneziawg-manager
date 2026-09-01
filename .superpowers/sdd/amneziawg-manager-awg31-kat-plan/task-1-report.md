# Task 1 report: release, diagnostics, and import security gates

## Status

Implemented and focused verification passed. No live `/opt` state was read or modified.

## Implementation

### Immutable workflow actions

- Resolved the official upstream `actions/checkout` `v7` tag with:

  ```text
  $ git ls-remote https://github.com/actions/checkout.git refs/tags/v7 'refs/tags/v7^{}'
  3d3c42e5aac5ba805825da76410c181273ba90b1 refs/tags/v7
  ```

- Pinned both CI and release checkout steps to `3d3c42e5aac5ba805825da76410c181273ba90b1` with a trailing `# v7` comment.
- Added a dependency-free workflow policy test that scans workflow `uses:` entries, permits local actions, and requires external actions to use a 40-character lowercase commit SHA plus a human-readable version comment.
- Kept the existing single tag-driven release job, permissions, build, signing, and publication behavior unchanged.

### SemVer 2.0 precedence

- Added one dependency-free repository SemVer owner in `src/awgctl/semver.py`.
- Numeric prerelease identifiers compare numerically, numeric identifiers sort below nonnumeric identifiers, nonnumeric identifiers compare lexically, longer equal-prefix prereleases sort later, and stable releases sort above prereleases.
- Rejected leading zeroes in core numeric fields and numeric prerelease identifiers, empty identifiers, repeated dots, leading `v`, trailing hyphens, build metadata, and other unsupported repository forms.
- Routed runtime release validation/ordering, signed-manifest construction, and immutable deployment directory validation through the same parser.

### Descriptor-bound diagnostics output

- `diagnose --output` no longer resolves and later reopens an output pathname.
- The selected parent is opened once with `O_DIRECTORY|O_NOFOLLOW`, validated with `fstat`, required to be owned by the effective UID, and rejected if group- or other-writable. Production runs as root, so the same boundary enforces root ownership there while remaining testable as the unprivileged test UID.
- Bundle directories use a 128-bit CSPRNG suffix and are created relative to the retained parent descriptor.
- Nested directories remain descriptor-bound; files use `O_NOFOLLOW|O_CREAT|O_EXCL`, descriptor writes, `fchown`/`fchmod`, and `fsync`.
- The final pathname is checked against the originally opened parent identity before success is reported.
- Removed the post-creation pathname-based recursive `chmod_secret_tree` call from diagnostics.
- Normal default output remains `/opt/amneziawg/diagnostics`, created by the existing protected layout setup; successful calls still return the bundle and manifest paths.

### Hardened client-profile import

- Added a single-open profile reader using `O_RDONLY|O_NOFOLLOW` and `fstat` validation of regular-file type, single link, private mode, and initial size.
- Reads are bounded during the read itself to 64 KiB and decoded strictly as UTF-8 from the validated descriptor bytes.
- The shared AWG parser now rejects duplicate keys before dictionary collapse while preserving legitimate repeated `Peer` sections and managed server `PostUp`/`PostDown` directives.
- Client-profile validation rejects extra sections, repeated Interface/Peer sections, case variants, and directives outside the profile/generation allowlists. Interface base fields are `PrivateKey`, `Address`, `DNS`, and `MTU`, plus fields in the effective managed obfuscation generation; Peer fields are exactly `PublicKey`, `PresharedKey`, `Endpoint`, `AllowedIPs`, and `PersistentKeepalive`.
- Validated fields are rendered through the canonical client renderer. The canonical bytes, not caller-supplied comments/formatting, are passed to `write_client_state`, which supplies the same canonical profile to the file and QR paths.
- Existing matching-peer identity checks, external-peer conversion behavior, dry-run no-write behavior, and normal file/QR generation paths remain intact.

## Files changed

- `.github/workflows/ci.yml`
- `.github/workflows/release.yml`
- `src/awgctl/core.py`
- `src/awgctl/diagnostics.py`
- `src/awgctl/releases.py`
- `src/awgctl/semver.py`
- `src/awginstall/deploy.py`
- `tools/build_manifest.py`
- `tests/test_workflows.py`
- `tests/test_releases.py`
- `tests/test_release_build.py`
- `tests/test_packaging.py`
- `tests/test_diagnostics.py`
- `tests/test_client_import.py`

## TDD evidence

### Primary RED

Command:

```text
python3 -m unittest -v tests.test_workflows tests.test_releases tests.test_diagnostics tests.test_client_import
```

Observed before production changes:

```text
Ran 22 tests in 0.117s
FAILED (failures=14, errors=4)
```

The expected boundary failures included mutable `actions/checkout@v7`, incorrect `beta.10` ordering, acceptance of leading-zero/empty SemVer identifiers, writable diagnostic-parent acceptance, parent substitution reaching the path-based writer, no CSPRNG allocator, raw profile preservation, last-write-wins duplicate keys, accepted lifecycle/unknown directives, and the missing descriptor-bound profile reader. Two initial errors were direct missing-feature errors for the new reader; one test-context error and one patch-target error were corrected before relying on their assertions.

### Primary GREEN

Same command after implementation:

```text
Ran 22 tests in 0.081s
OK
```

### Release sibling-bypass RED/GREEN

The sibling review found that the manifest builder and deployment directory still accepted runtime-invalid versions.

Command:

```text
python3 -m unittest -v tests.test_release_build tests.test_packaging
```

RED:

```text
Ran 5 tests in 0.464s
FAILED (failures=2)
```

GREEN after routing both consumers through the shared SemVer parser:

```text
Ran 5 tests in 0.499s
OK
```

### Canonical-persistence mutation check

After adding the command-boundary assertion, the production call was deliberately changed back to the raw supplied profile. The focused test failed by showing the untrusted comment in `profile_text`:

```text
python3 -m unittest -v tests.test_client_import.ImportProfileTests.test_import_persists_the_validated_canonical_profile
Ran 1 test in 0.008s
FAILED (failures=1)
```

Restoring `imported["profile"]` produced:

```text
Ran 1 test in 0.004s
OK
```

## Final focused verification

Command:

```text
python3 -m unittest -v tests.test_workflows tests.test_releases tests.test_release_build tests.test_packaging tests.test_diagnostics tests.test_client_import tests.test_awgctl tests.test_contracts
```

Output summary:

```text
Ran 71 tests in 0.733s
OK
```

This includes workflow pinning, runtime/builder/deployment SemVer consumers, release signature/artifact checks, diagnostic redaction and hostile filesystem tests, import reader/parser/canonical persistence, external peer and dry-run behavior, legacy adoption parsing, managed server lifecycle hooks/multiple peers, client rendering, file/QR state generation, and secret-free JSON contracts.

Additional verification:

```text
python3 -m py_compile src/awgctl/core.py src/awgctl/diagnostics.py src/awgctl/releases.py src/awgctl/semver.py src/awginstall/deploy.py tools/build_manifest.py
make build
dist/awgctl.pyz version
git diff --check
```

Observed:

```text
dist/awgctl.pyz
dist/release.json
awgctl 0.1.0-beta.4
```

All commands exited 0 and `git diff --check` was clean.

## Self-review

- Reviewed every changed release call site: workflow execution, runtime version comparison, manifest parsing, discovered/fetched tag validation, manifest generation, and immutable release-directory installation. The builder/deployment sibling bypasses were fixed rather than merely noted.
- Reviewed every shared-parser consumer: native validation, semantic drift signatures, backup restore validation, server peer lookup, and legacy server/client extraction. Duplicate keys now fail closed; multiple legitimate Peer sections and manager-owned lifecycle hooks remain accepted because directive allowlists are applied only at client-profile validation.
- Reviewed the import command from descriptor read through matching server peer, external-peer identity/name checks, dry run, canonical state write, and the existing shared file/QR generator.
- Reviewed diagnostics from CLI parent selection through protected layout setup, descriptor-relative creation, manifest creation, returned paths, audit output, and removal of the recursive pathname permission walk.
- Confirmed output errors name paths/directives but never echo supplied directive values or managed keys.

## Concerns and omitted gates

- The adoption server/client/optional-QR input path is a related pathname-based input sibling identified by the independent investigation. It remains intentionally unchanged because Task 1 was explicitly limited to client import; it should use the same descriptor-bound staging approach in its assigned task.
- A custom diagnostics parent must already exist so it can be opened and authorized before creation beneath it. The normal default remains unchanged because `ensure_layout()` creates the protected default parent.
- No live root-owned `/opt` diagnostic run, live client import, QR invocation, or release publication was performed. Root ownership is enforced by the effective-UID check and descriptor operations and was unit-tested unprivileged.
- The repository-wide suite was not run; verification was kept to the focused serial 71-test set plus compile/build/smoke checks as directed.
