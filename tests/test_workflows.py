import pathlib
import re
import tempfile
import unittest


REPO_ROOT = pathlib.Path(__file__).parents[1]
USES_MAPPING_RE = re.compile(r"^\s*(?:-\s*)?(?:uses|['\"]uses['\"])\s*:(.*)$")
PINNED_ACTION_RE = re.compile(r"^[^/@\s]+/[^/@\s]+(?:/[^@\s]+)*@[0-9a-f]{40}$")
LOCAL_ACTION_RE = re.compile(r"^\./[^\s#]+$")
VERSION_COMMENT_RE = re.compile(
    r"^v[0-9]+(?:\.[0-9]+)*(?:[-+][0-9A-Za-z.-]+)?(?:\s+\S(?:.*\S)?)?$"
)
BLOCK_SCALAR_HEADER_RE = re.compile(
    r":\s*[|>](?:[1-9][+-]?|[+-][1-9]?)?\s*(?:#.*)?$"
)
UNSUPPORTED_BLOCK_USES_RE = re.compile(
    r"^\s*(?:-\s*)?(?:(?:[&!][^\s]+\s+)+|\?\s+)"
    r"(?:uses|['\"]uses['\"])\s*(?::.*|#.*)?$"
)


def _quoted_scalar(line: str, start: int) -> tuple[str, int]:
    quote = line[start]
    value = []
    index = start + 1
    while index < len(line):
        character = line[index]
        if quote == "'" and character == "'" and index + 1 < len(line) and line[index + 1] == "'":
            value.append("'")
            index += 2
            continue
        if quote == '"' and character == "\\" and index + 1 < len(line):
            value.append(line[index + 1])
            index += 2
            continue
        if character == quote:
            return "".join(value), index + 1
        value.append(character)
        index += 1
    return "".join(value), index


def _is_uses_key(key: str) -> bool:
    candidate = key.strip()
    if candidate.startswith("?"):
        candidate = candidate[1:].strip()
    while candidate.startswith(("&", "!")):
        _, separator, candidate = candidate.partition(" ")
        if not separator:
            return False
        candidate = candidate.strip()
    if len(candidate) >= 2 and candidate[0] in {"'", '"'} and candidate[-1] == candidate[0]:
        scalar, end = _quoted_scalar(candidate, 0)
        if end != len(candidate):
            return False
        candidate = scalar
    return candidate == "uses"


def _has_unsupported_flow_uses_mapping(line: str) -> bool:
    """Find a uses key in YAML flow maps without matching comments or strings."""
    collections: list[list[object]] = []
    index = 0
    while index < len(line):
        character = line[index]
        if character == "#":
            break
        if character in {"'", '"'}:
            scalar, next_index = _quoted_scalar(line, index)
            if collections and collections[-1][0] == "map" and collections[-1][1]:
                colon = next_index
                while colon < len(line) and line[colon].isspace():
                    colon += 1
                if colon < len(line) and line[colon] == ":":
                    collections[-1][1] = False
                    if _is_uses_key(scalar):
                        return True
                    index = colon + 1
                    continue
            index = next_index
            continue
        if character == "{":
            collections.append(["map", True])
            index += 1
            continue
        if character == "[":
            collections.append(["sequence", False])
            index += 1
            continue
        if character in {"}", "]"}:
            if collections:
                collections.pop()
            index += 1
            continue
        if character == ",":
            if collections and collections[-1][0] == "map":
                collections[-1][1] = True
            index += 1
            continue
        if collections and collections[-1][0] == "map" and collections[-1][1]:
            if character.isspace():
                index += 1
                continue
            key_start = index
            while index < len(line) and line[index] not in ":,{}[]#":
                index += 1
            key = line[key_start:index].strip()
            if index < len(line) and line[index] == ":":
                collections[-1][1] = False
                if _is_uses_key(key):
                    return True
                index += 1
                continue
            collections[-1][1] = False
            continue
        index += 1
    return False


def action_policy_violations(workflow_root: pathlib.Path) -> list[str]:
    violations = []
    mapping_count = 0
    workflows = sorted(
        path for path in workflow_root.iterdir()
        if path.is_file() and path.suffix in {".yml", ".yaml"}
    )
    for workflow in workflows:
        block_scalar_indent: int | None = None
        for number, line in enumerate(workflow.read_text(encoding="utf-8").splitlines(), start=1):
            indentation = len(line) - len(line.lstrip())
            if block_scalar_indent is not None:
                if not line.strip() or indentation > block_scalar_indent:
                    continue
                block_scalar_indent = None
            if line.lstrip().startswith("#"):
                continue
            if BLOCK_SCALAR_HEADER_RE.search(line):
                block_scalar_indent = indentation
            match = USES_MAPPING_RE.fullmatch(line)
            if not match:
                if UNSUPPORTED_BLOCK_USES_RE.fullmatch(line) or _has_unsupported_flow_uses_mapping(line):
                    mapping_count += 1
                    violations.append(f"{workflow}:{number}: unsupported uses mapping")
                continue
            mapping_count += 1
            raw_value = match.group(1).strip()
            raw_reference, marker, raw_comment = raw_value.partition("#")
            reference = raw_reference.strip()
            version_comment = raw_comment.strip() if marker else ""
            if (
                not reference
                or any(character.isspace() for character in reference)
                or reference[0:1] in {"[", "{"}
                or reference[-1:] in {"]", "}"}
                or reference[0:1] in {"'", '"'}
                or reference[-1:] in {"'", '"'}
            ):
                violations.append(f"{workflow}:{number}: unparseable uses value")
                continue
            if reference.startswith("./"):
                if not LOCAL_ACTION_RE.fullmatch(reference):
                    violations.append(f"{workflow}:{number}: unparseable local action: {reference}")
                continue
            if not PINNED_ACTION_RE.fullmatch(reference):
                violations.append(f"{workflow}:{number}: mutable external action: {reference}")
            if not VERSION_COMMENT_RE.fullmatch(version_comment):
                violations.append(f"{workflow}:{number}: missing action version comment")
    if mapping_count == 0:
        violations.append(f"{workflow_root}: no uses mappings found")
    return violations


class WorkflowSecurityTests(unittest.TestCase):
    def test_external_actions_are_commit_pinned_with_version_comments(self):
        self.assertEqual(action_policy_violations(REPO_ROOT / ".github/workflows"), [])

    def test_multiword_comment_cannot_hide_a_mutable_action(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "ci.yml").write_text(
                "steps:\n  - uses: actions/checkout@v7 # mutable reference\n",
                encoding="utf-8",
            )
            violations = action_policy_violations(root)
            self.assertTrue(any("mutable external action" in item for item in violations), violations)

    def test_yaml_extension_cannot_bypass_action_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "release.yaml").write_text(
                "steps:\n  - uses: actions/checkout@v7 # v7\n",
                encoding="utf-8",
            )
            violations = action_policy_violations(root)
            self.assertTrue(any("mutable external action" in item for item in violations), violations)

    def test_unparseable_uses_value_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "ci.yml").write_text(
                "steps:\n  - uses: [actions/checkout@v7] # v7\n",
                encoding="utf-8",
            )
            violations = action_policy_violations(root)
            self.assertTrue(any("unparseable" in item for item in violations), violations)

    def test_flow_mapping_cannot_hide_beside_a_valid_block_action(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "ci.yml").write_text(
                "steps:\n"
                "  - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7\n"
                "  # - { uses: actions/checkout@v7 }\n"
                "  - run: 'echo \"{ uses: actions/checkout@v7 }\"'\n"
                "  - run: |\n"
                "      { uses: actions/checkout@v7 }\n"
                "  # run: |\n"
                "    - { uses: actions/checkout@v7 }\n"
                "  - { uses: actions/checkout@v7 }\n",
                encoding="utf-8",
            )
            violations = action_policy_violations(root)
            self.assertEqual(sum("unsupported uses mapping" in item for item in violations), 2, violations)

    def test_flow_mapping_uses_key_variants_fail_closed(self):
        variants = (
            "- {uses: actions/checkout@v7}",
            "- { 'uses': actions/checkout@v7 }",
            "- { name: checkout, uses : actions/checkout@v7 }",
            "job: [{ uses: actions/checkout@v7 }]",
            "- { ? uses : actions/checkout@v7 }",
            "- { &action-key uses: actions/checkout@v7 }",
            "- { !!str uses: actions/checkout@v7 }",
        )
        for variant in variants:
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                (root / "ci.yaml").write_text(variant + "\n", encoding="utf-8")
                violations = action_policy_violations(root)
                self.assertTrue(any("unsupported uses mapping" in item for item in violations), violations)

    def test_unsupported_block_uses_key_variants_fail_closed(self):
        variants = (
            "? uses\n: actions/checkout@v7",
            "&action-key uses: actions/checkout@v7",
            "!!str uses: actions/checkout@v7",
        )
        for variant in variants:
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                (root / "ci.yml").write_text(
                    "steps:\n"
                    "  - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7\n"
                    f"  {variant.replace(chr(10), chr(10) + '  ')}\n",
                    encoding="utf-8",
                )
                violations = action_policy_violations(root)
                self.assertTrue(any("unsupported uses mapping" in item for item in violations), violations)


if __name__ == "__main__":
    unittest.main(verbosity=2)
