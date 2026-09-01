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

## Fix Round 1

### Findings addressed

1. Reworked the workflow policy test so it enumerates both `*.yml` and `*.yaml`, detects every ordinary `uses:` mapping before parsing its value, and fails closed on empty, structured, quoted, whitespace-bearing, or otherwise unparseable values. Local `./...` actions are validated separately. Every nonlocal action is independently checked for a full 40-character commit SHA and a human-readable `v...` version comment. External reusable-workflow paths are supported. A missing `uses:` mapping set also fails closed.
2. Replaced every SemVer `\d` with ASCII `[0-9]`, added an explicit 128-digit numeric-identifier ceiling before conversion, and wrapped conversion failures as `InvalidVersion`. Runtime release validation converts that to `ReleaseError`; manifest construction and deployment continue to convert it to their existing public boundary errors.

### RED evidence

Command:

```text
python3 -m unittest -v tests.test_workflows tests.test_releases tests.test_release_build tests.test_packaging
```

Observed before validator fixes:

```text
Ran 14 tests in 0.905s
FAILED (failures=8, errors=6)
```

The multiword-comment mutable action and `.yaml` fixture returned no violations. `1٢.0.0` was accepted by runtime, builder, and deployment. The 5,000-digit core and numeric prerelease cases raised raw `ValueError`; builder stderr contained a traceback.

An additional fail-closed fixture was then added for a structured/unparseable `uses` value:

```text
python3 -m unittest -v tests.test_workflows.WorkflowSecurityTests.test_unparseable_uses_value_fails_closed
Ran 1 test in 0.002s
FAILED (failures=1)
```

The old scanner misclassified the value as a normal mutable reference instead of explicitly rejecting it as unparseable.

### GREEN evidence

Command:

```text
python3 -m unittest -v tests.test_workflows tests.test_releases tests.test_release_build tests.test_packaging
```

Observed after validator fixes:

```text
Ran 15 tests in 0.678s
OK
```

### Amended-validator self-review

- Workflow enumeration includes only regular `.yml`/`.yaml` files and counts detected mappings so an empty scan cannot silently pass.
- Comment-only lines are ignored, while step actions and job-level reusable-workflow `uses:` mappings share the same fail-closed parser.
- Local action syntax, nonlocal immutable identity, and the human version comment are separate validations. A multiword inline comment can no longer make a mutable reference disappear from coverage.
- The immutable reference grammar accepts `owner/repository@SHA` and `owner/repository/path/to/workflow.yaml@SHA`, but rejects tags, branch names, abbreviated SHAs, expressions, Docker references, and malformed structured values.
- SemVer core and prerelease numeric recognition is ASCII-only. Identifier length is checked before `int()`, and a defensive conversion wrapper prevents raw exceptions even if conversion behavior changes.
- Reviewed all shared SemVer consumers: runtime comparison/manifest/tag validation, manifest builder, and immutable deployment directory selection. Each now exposes only its documented boundary error for Unicode or oversized numeric input.

### Fix Round 1 concerns

- No new blocker. The workflow policy intentionally rejects quoted/structured `uses` scalar forms rather than attempting a dependency-free general YAML parser; repository workflows use ordinary scalar mappings.

## Fix Round 2

### Finding addressed

The Round 1 line-anchored block-mapping parser could still skip a YAML flow mapping when another valid block action made the global mapping count nonzero. A dependency-free lexical flow-map detector now identifies `uses` keys inside `{...}` collections and rejects the entire representation as unsupported. It tracks nested flow maps/sequences and YAML single/double quoted scalars, stops at comments, and ignores literal/folded block-scalar bodies so examples or shell strings do not become false mapping claims.

The self-review also added fail-closed handling for compact, quoted-key, comma-separated, nested-sequence, explicit-key, anchored-key, and tagged-key `uses` spellings. Only ordinary block `uses:` mappings proceed to the separate local-reference or immutable-SHA and human-version-comment validations.

### Required RED evidence

The regression fixture contained one valid pinned ordinary action plus one mutable flow action, with a commented flow example and a quoted command string alongside them.

Command:

```text
python3 -m unittest -v tests.test_workflows.WorkflowSecurityTests.test_flow_mapping_cannot_hide_beside_a_valid_block_action
```

Observed before the lexical flow detector:

```text
Ran 1 test in 0.001s
FAILED (failures=1)
```

The violation list was empty: the pinned block action satisfied the global count and `- { uses: actions/checkout@v7 }` was silently skipped.

### False-claim and spelling RED evidence

Adding a literal block-scalar body containing `{ uses: ... }` initially exposed an obvious false claim in the first lexical implementation:

```text
Ran 1 test in 0.010s
FAILED (failures=1)
```

It reported two unsupported mappings instead of only the real flow mapping. Tracking block-scalar indentation corrected that behavior.

Further self-review fixtures exposed skipped explicit/property key forms:

```text
python3 -m unittest -v tests.test_workflows.WorkflowSecurityTests.test_flow_mapping_uses_key_variants_fail_closed
Ran 1 test in 0.005s
FAILED (failures=3)

python3 -m unittest -v tests.test_workflows.WorkflowSecurityTests.test_unsupported_block_uses_key_variants_fail_closed
Ran 1 test in 0.003s
FAILED (failures=3)
```

The amended detector now rejects explicit `? uses`, anchored `&name uses`, tagged `!!str uses`, quoted flow keys, nested sequence maps, compact maps, and maps where `uses` follows another key.

A final comment-state mutation showed that recognizing a commented `# run: |` as a real block-scalar header could suppress a following flow action:

```text
python3 -m unittest -v tests.test_workflows.WorkflowSecurityTests.test_flow_mapping_cannot_hide_beside_a_valid_block_action
Ran 1 test in 0.002s
FAILED (failures=1)
```

Only one of two real flow mappings was reported. Comment exclusion now occurs before block-scalar header recognition, while actual block-scalar content remains excluded.

### GREEN evidence

Workflow-only command:

```text
python3 -m unittest -v tests.test_workflows
```

Output:

```text
Ran 7 tests in 0.006s
OK
```

Existing Task 1 validator set, run serially:

```text
python3 -m unittest -v tests.test_workflows tests.test_releases tests.test_release_build tests.test_packaging
```

Output:

```text
Ran 18 tests in 0.745s
OK
```

### Fix Round 2 self-review

- A real flow map is detected even when a valid pinned block action exists in the same file; mapping counts can no longer mask an unmatched flow representation.
- Compact `{uses: ...}`, quoted `{'uses': ...}`, later-key `{name: ..., uses: ...}`, nested `[{uses: ...}]`, explicit `? uses`, anchored `&key uses`, and tagged `!!str uses` forms all fail closed as unsupported.
- `# { uses: ... }`, commented block-scalar headers, quoted command contents, escaped quotes, and literal/folded block scalar bodies are excluded before mapping detection to avoid false positives or comment-driven suppression.
- Both `.yml` and `.yaml` continue through the same policy. Ordinary block external actions still receive independent full-SHA and version-comment validation; local `./...` actions retain their separate grammar.
- The SemVer implementation and tests from Fix Round 1 were untouched and remained green in the 18-test validator run.

### Fix Round 2 concerns

- No blocker. The detector remains deliberately workflow-specific and dependency-free: unsupported YAML key properties/flow collections fail closed rather than being normalized into an executable action reference.
- No workflow parser dependency or unrelated workflow behavior was introduced.

### Fix Round 2 commit

- Subject: `fix: reject flow-mapped workflow actions`

## Fix Round 3

### Findings addressed

1. YAML comment recognition is now context-sensitive: an unquoted `#` begins a comment only at the start of a scalar or after separation whitespace. Embedded plain-scalar text such as `foo#bar` remains executable content, so a later flow-map `uses` key cannot be hidden.
2. Every line is lexed into YAML content and comment text before block-scalar-header matching. `jobs: # fake: |` is evaluated as `jobs:` and cannot suppress its indented job mappings, while `run: | # real comment` remains a real protected block scalar.
3. The unsupported block-key grammar now accepts the combination of an explicit-key marker with one or more YAML properties before `uses`, so `? &action-key uses` and `? !!str uses` fail closed.

The correction remains confined to `tests/test_workflows.py`; the SemVer implementation and unrelated Task 1 boundaries were not changed.

### Required RED evidence

Command run against the Round 2 implementation:

```text
python3 -m unittest -v \
  tests.test_workflows.WorkflowSecurityTests.test_embedded_hash_in_plain_flow_scalar_does_not_hide_uses \
  tests.test_workflows.WorkflowSecurityTests.test_inline_comment_cannot_fabricate_a_block_scalar_header \
  tests.test_workflows.WorkflowSecurityTests.test_explicit_property_uses_keys_fail_closed
```

Output:

```text
Ran 3 tests in 0.004s
FAILED (failures=4)
```

- `- { name: foo#bar, uses: actions/checkout@v7 }` produced no violation because scanning stopped at the embedded hash.
- `jobs: # fake: |` suppressed all indented job mappings and returned only `no uses mappings found`.
- Both combined explicit/property variants returned no violations beside the valid pinned control action.

### Focused GREEN evidence

The same three-test command after the correction produced:

```text
Ran 3 tests in 0.003s
OK
```

All workflow-policy tests:

```text
python3 -m unittest -v tests.test_workflows
Ran 11 tests in 0.009s
OK
```

Serial Task 1 validator set:

```text
python3 -m unittest -v tests.test_workflows tests.test_releases tests.test_release_build tests.test_packaging
Ran 22 tests in 0.724s
OK
```

Additional focused gates:

```text
python3 -m py_compile tests/test_workflows.py
git diff --check
```

Both commands exited 0 with no output.

### Comment-boundary mutation evidence

The `_is_yaml_comment_start` boundary was deliberately mutated back to treating every `#` as a comment.

```text
python3 -m unittest -v tests.test_workflows.WorkflowSecurityTests.test_yaml_comment_requires_separation_whitespace
Ran 1 test in 0.001s
FAILED (failures=1)
```

The mutation incorrectly split `name: foo#bar` into content `name: foo` and comment `bar`. Restoring the separation-whitespace rule produced:

```text
Ran 1 test in 0.000s
OK
```

### Fix Round 3 self-review

- Comment lexing skips single- and double-quoted scalars and recognizes `#` only at index zero or after whitespace. Both `_split_yaml_comment` and the flow-map scanner consume the same predicate, preventing boundary drift.
- The mutation test pairs embedded `foo#bar` with separated `foo # comment`, and pairs an executable embedded-hash flow map with a real comment containing a fake flow map.
- Block-scalar recognition sees only comment-stripped YAML content. The test set covers a fake `|` inside an inline comment, a real `|` with an inline comment, literal body content containing `{ uses: ... }`, and a commented-out scalar header.
- Explicit keys with no property, a property with no explicit marker, and combined `? &anchor uses` / `? !!str uses` forms all fail closed. Flow-map explicit/property variants remain covered from Round 2.
- Ordinary pinned block actions, reusable-workflow paths, local action handling, version comments, `.yml`/`.yaml` enumeration, and the prior SemVer rejection cases stayed green.

### Fix Round 3 concerns

- No blocker. This remains a narrow dependency-free workflow-policy lexer, not a general YAML parser; the verified comment and key-property semantics are now explicit and regression-tested.
- No workflow file, production module, release behavior, or unrelated task was changed.

### Fix Round 3 commit

- Subject: `fix: honor YAML workflow comment boundaries`

## Fix Round 4

### Finding addressed

YAML comment separation now uses exactly ASCII space (`U+0020`) or horizontal tab (`U+0009`). The predicate no longer uses Python `str.isspace()`, which recognizes NBSP and other Unicode characters that YAML can retain inside a plain scalar.

The change is intentionally limited to one workflow-policy predicate plus its boundary fixtures. SemVer, workflows, and all other Task 1 code remain unchanged.

### Required RED evidence

The exact bypass fixture included a valid pinned action plus:

```text
- { name: foo\u00a0#bar, uses: actions/checkout@v7 }
```

The boundary controls cover ordinary embedded `foo#bar`, NBSP-embedded `foo\u00a0#bar`, ASCII-space `foo # comment`, and tab-separated `foo\t# comment`.

Command against the Round 3 predicate:

```text
python3 -m unittest -v \
  tests.test_workflows.WorkflowSecurityTests.test_nbsp_plain_scalar_cannot_hide_flow_uses \
  tests.test_workflows.WorkflowSecurityTests.test_yaml_comment_requires_separation_whitespace
```

Output:

```text
Ran 2 tests in 0.002s
FAILED (failures=2)
```

The executable NBSP flow map returned no violations, and `_split_yaml_comment` incorrectly normalized `foo\u00a0#bar` into content `foo` plus comment `bar`.

### GREEN evidence

The same focused command after replacing `isspace()` with `{ " ", "\t" }` produced:

```text
Ran 2 tests in 0.001s
OK
```

Workflow-policy set:

```text
python3 -m unittest -v tests.test_workflows
Ran 12 tests in 0.009s
OK
```

Serial Task 1 validator set:

```text
python3 -m unittest -v tests.test_workflows tests.test_releases tests.test_release_build tests.test_packaging
Ran 23 tests in 0.725s
OK
```

Additional focused gates:

```text
python3 -m py_compile tests/test_workflows.py
git diff --check
```

Both commands exited 0 with no output.

### Fix Round 4 self-review

- `_is_yaml_comment_start` is the single comment-boundary owner used by both full-line comment splitting and flow-map scanning.
- At index zero, `#` remains a comment. At later indices, only a preceding ASCII space or tab starts a comment.
- Ordinary embedded `foo#bar` and NBSP-embedded `foo\u00a0#bar` remain plain-scalar content; ASCII-space and tab controls still split into content and comment.
- The exact pinned-plus-NBSP flow fixture proves the global mapping count cannot mask the executable mutable action.
- A focused `rg` review found no `isspace()` use in the comment predicate or either comment-boundary consumer. Remaining `isspace()` calls govern flow formatting and invalid action-reference whitespace, not `#` semantics.
- Round 3 flow-map, inline-comment/block-scalar, and explicit/property key tests remained green, as did the prior SemVer boundary tests.

### Fix Round 4 concerns

- No blocker. This fixes the standards mismatch without broadening the dependency-free workflow lexer.
- No production code, workflow behavior, SemVer logic, or unrelated task was changed.

### Fix Round 4 commit

- Subject: `fix: restrict YAML comment separation`
