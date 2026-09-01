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


def action_policy_violations(workflow_root: pathlib.Path) -> list[str]:
    violations = []
    mapping_count = 0
    workflows = sorted(
        path for path in workflow_root.iterdir()
        if path.is_file() and path.suffix in {".yml", ".yaml"}
    )
    for workflow in workflows:
        for number, line in enumerate(workflow.read_text(encoding="utf-8").splitlines(), start=1):
            if line.lstrip().startswith("#"):
                continue
            match = USES_MAPPING_RE.fullmatch(line)
            if not match:
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
