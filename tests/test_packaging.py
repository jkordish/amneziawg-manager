import json
import os
import pathlib
import subprocess
import sys
import tempfile
import tomllib
import unittest
import zipfile


REPO_ROOT = pathlib.Path(__file__).parents[1]
SRC_ROOT = REPO_ROOT / "src"
sys.path.insert(0, str(SRC_ROOT))

from awgctl.version import VERSION
from awginstall.cli import _share_files
from awginstall.deploy import DeploymentError, active_release, install_release


class VersionedDeploymentTests(unittest.TestCase):
    def test_install_release_rejects_invalid_semver_directory(self):
        invalid = {
            "leading zero": "0.1.0-beta.01",
            "unicode core digit": "1٢.0.0",
            "oversized core": f"{'9' * 5000}.0.0",
            "oversized prerelease": f"1.0.0-{'9' * 5000}",
        }
        for label, value in invalid.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory) / "opt/amneziawg"
                artifact = pathlib.Path(directory) / "awgctl"
                artifact.write_bytes(b"artifact")
                with self.assertRaisesRegex(DeploymentError, "version"):
                    install_release(root=root, artifact=artifact, version=value)
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

            with zipfile.ZipFile(output) as archive:
                shipped = set(archive.namelist())
            self.assertIn("awgctl/semver.py", shipped)
            self.assertIn("awgctl/selftest.py", shipped)
            self.assertIn("awginstall/host.py", shipped)
            self.assertIn("awginstall/settings.py", shipped)

            internal = output.with_name("awgctl-internal")
            internal.symlink_to(output)
            timeout = subprocess.run(
                [internal, "_obfuscation-timeout", "not-a-transaction-id"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertNotEqual(timeout.returncode, 0)
            self.assertIn("transaction ID", timeout.stderr)

    def test_completion_ships_expiry_and_obfuscation_lifecycle(self):
        completion = (REPO_ROOT / "awgctl-completion.bash").read_text(encoding="utf-8")
        self.assertIn("expire", completion)
        self.assertIn("obfuscation", completion)
        self.assertIn("prepare activate confirm rollback show", completion)
        self.assertIn("--mode --profile --client --dry-run --json", completion)

    def test_source_release_ships_operator_security_and_completion_contracts(self):
        shared = _share_files(REPO_ROOT)
        self.assertEqual(shared["VERSION"], (VERSION + "\n").encode())
        for name in (
            "README.md",
            "SECURITY.md",
            "CHANGELOG.md",
            "completions/awgctl.bash",
            "docs/ARCHITECTURE.md",
            "docs/INSTALL.md",
            "docs/OPERATIONS.md",
            "docs/RECOVERY.md",
            "docs/DEVELOPMENT.md",
            "docs/RELEASING.md",
        ):
            with self.subTest(name=name):
                self.assertIn(name, shared)

    def test_source_and_python_project_versions_match_the_changelog(self):
        project = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual(project["project"]["version"], VERSION.replace("-beta.", "b"))
        changelog = (REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        self.assertIn(f"## {VERSION} - ", changelog)

    def test_release_verify_uses_an_explicit_non_live_ingress_fixture(self):
        makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
        self.assertIn(
            "python3 install.py check --ingress-boundary equivalent-external-firewall",
            makefile,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
