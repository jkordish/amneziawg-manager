import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest


REPO_ROOT = pathlib.Path(__file__).parents[1]
SRC_ROOT = REPO_ROOT / "src"
sys.path.insert(0, str(SRC_ROOT))

from awgctl.version import VERSION
from awginstall.deploy import DeploymentError, active_release, install_release


class VersionedDeploymentTests(unittest.TestCase):
    def test_install_release_rejects_invalid_semver_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory) / "opt/amneziawg"
            artifact = pathlib.Path(directory) / "awgctl"
            artifact.write_bytes(b"artifact")
            with self.assertRaisesRegex(DeploymentError, "version"):
                install_release(
                    root=root,
                    artifact=artifact,
                    version="0.1.0-beta.01",
                )
            self.assertFalse((root / "releases").exists())

    def test_install_release_uses_versioned_directory_and_atomic_selector(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory) / "opt/amneziawg"
            artifact = pathlib.Path(directory) / "awgctl"
            artifact.write_bytes(b"#!/usr/bin/env python3\nprint('ok')\n")

            installed = install_release(
                root=root,
                artifact=artifact,
                version=VERSION,
                share_files={"README.md": b"operations\n"},
            )

            self.assertEqual(installed, root / "releases" / VERSION)
            self.assertEqual(active_release(root), VERSION)
            self.assertTrue((root / "bin/awgctl").is_symlink())
            self.assertEqual(
                os.readlink(root / "bin/awgctl"),
                f"../releases/{VERSION}/awgctl",
            )
            self.assertEqual((installed / "awgctl").stat().st_mode & 0o777, 0o755)
            self.assertEqual(installed.stat().st_mode & 0o777, 0o755)
            self.assertEqual((installed / "share").stat().st_mode & 0o777, 0o755)
            self.assertEqual((installed / "share/README.md").stat().st_mode & 0o777, 0o644)
            manifest = json.loads((installed / "install-manifest.json").read_text())
            self.assertEqual(manifest["version"], VERSION)
            self.assertEqual(manifest["files"], ["awgctl", "share/README.md"])

    def test_build_release_produces_executable_zipapp(self):
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory) / "awgctl"
            result = subprocess.run(
                [sys.executable, str(REPO_ROOT / "tools/build_release.py"), "--output", str(output)],
                cwd=REPO_ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(output.stat().st_mode & 0o777, 0o755)
            version = subprocess.run(
                [str(output), "--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(version.returncode, 0, version.stderr)
            self.assertEqual(version.stdout.strip(), f"awgctl {VERSION}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
