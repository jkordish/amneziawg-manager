import json
import pathlib
import subprocess
import sys
import tempfile
import unittest


REPO_ROOT = pathlib.Path(__file__).parents[1]


class ReleaseBuildTests(unittest.TestCase):
    def test_manifest_builder_produces_the_runtime_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            artifact = root / "awgctl.pyz"
            artifact.write_bytes(b"artifact")
            output = root / "release.json"
            result = subprocess.run(
                [
                    sys.executable,
                    str(REPO_ROOT / "tools/build_manifest.py"),
                    "--artifact", str(artifact),
                    "--output", str(output),
                    "--version", "0.1.0-beta.1",
                ],
                cwd=REPO_ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            manifest = json.loads(output.read_text())
            self.assertEqual(manifest["tag"], "v0.1.0-beta.1")
            self.assertEqual(manifest["platform"], "ubuntu-24.04-amd64")
            self.assertEqual(manifest["installation_schema_version"], 1)
            self.assertEqual(manifest["artifact"]["name"], "awgctl.pyz")


if __name__ == "__main__":
    unittest.main(verbosity=2)
