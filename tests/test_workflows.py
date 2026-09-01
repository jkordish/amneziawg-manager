import pathlib
import re
import unittest


REPO_ROOT = pathlib.Path(__file__).parents[1]
EXTERNAL_USES_RE = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)(?:\s+#\s*(\S+))?\s*$")
PINNED_ACTION_RE = re.compile(r"^[^/@\s]+/[^/@\s]+@[0-9a-f]{40}$")


class WorkflowSecurityTests(unittest.TestCase):
    def test_external_actions_are_commit_pinned_with_version_comments(self):
        checked = []
        for workflow in sorted((REPO_ROOT / ".github/workflows").glob("*.yml")):
            for number, line in enumerate(workflow.read_text(encoding="utf-8").splitlines(), start=1):
                match = EXTERNAL_USES_RE.fullmatch(line)
                if not match or match.group(1).startswith("./"):
                    continue
                reference, version_comment = match.groups()
                checked.append((workflow.name, number, reference))
                self.assertRegex(reference, PINNED_ACTION_RE, f"{workflow}:{number}")
                self.assertRegex(version_comment or "", r"^v\d", f"{workflow}:{number}")
        self.assertTrue(checked, "no external workflow actions were checked")


if __name__ == "__main__":
    unittest.main(verbosity=2)
