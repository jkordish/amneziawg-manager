import json
import io
import pathlib
import platform
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


REPO_ROOT = pathlib.Path(__file__).parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from awginstall.deploy import active_release
from awginstall.cli import build_parser, main as installer_main, package_install_plan, parse_default_interface
from awginstall.installer import InstallerError, upgrade_product
from awginstall.platform import PlatformError, validate_platform


class PlatformValidationTests(unittest.TestCase):
    def test_only_ubuntu_2404_amd64_is_supported(self):
        supported = validate_platform(
            {"ID": "ubuntu", "VERSION_ID": "24.04", "VERSION_CODENAME": "noble"},
            machine="x86_64",
        )
        self.assertEqual(supported["architecture"], "amd64")

        for release, machine in (("22.04", "x86_64"), ("24.04", "aarch64")):
            with self.subTest(release=release, machine=machine), self.assertRaises(PlatformError):
                validate_platform(
                    {"ID": "ubuntu", "VERSION_ID": release, "VERSION_CODENAME": "noble"},
                    machine=machine,
                )


class UpgradeTests(unittest.TestCase):
    def make_artifact(self, directory: pathlib.Path, content: bytes = b"new executable\n") -> pathlib.Path:
        artifact = directory / "artifact"
        artifact.write_bytes(content)
        return artifact

    def test_upgrade_preserves_legacy_binary_and_activates_new_release(self):
        with tempfile.TemporaryDirectory() as directory_text:
            directory = pathlib.Path(directory_text)
            root = directory / "opt/amneziawg"
            (root / "bin").mkdir(parents=True)
            (root / "bin/awgctl").write_bytes(b"legacy executable\n")

            upgrade_product(
                root=root,
                artifact=self.make_artifact(directory),
                version="0.1.0-beta.1",
                share_files={"VERSION": b"0.1.0-beta.1\n"},
                health_check=lambda _: 0,
            )

            self.assertEqual(active_release(root), "0.1.0-beta.1")
            self.assertEqual((root / "releases/legacy-import/awgctl").read_bytes(), b"legacy executable\n")

    def test_failed_health_check_rolls_back_to_preserved_legacy_binary(self):
        with tempfile.TemporaryDirectory() as directory_text:
            directory = pathlib.Path(directory_text)
            root = directory / "opt/amneziawg"
            (root / "bin").mkdir(parents=True)
            (root / "bin/awgctl").write_bytes(b"legacy executable\n")

            with self.assertRaisesRegex(InstallerError, "health verification failed"):
                upgrade_product(
                    root=root,
                    artifact=self.make_artifact(directory),
                    version="0.1.0-beta.1",
                    health_check=lambda _: 3,
                )

            self.assertEqual(active_release(root), "legacy-import")
            self.assertEqual((root / "bin/awgctl").read_bytes(), b"legacy executable\n")

    def test_upgrade_dry_run_does_not_create_installation_root(self):
        with tempfile.TemporaryDirectory() as directory_text:
            root = pathlib.Path(directory_text) / "opt/amneziawg"
            output = io.StringIO()
            result = installer_main(
                ["upgrade", "--dry-run"],
                root=root,
                repo_root=REPO_ROOT,
                output=output,
            )
            self.assertEqual(result, 0)
            self.assertFalse(root.exists())
            self.assertIn("would install awgctl 0.1.0-beta.1", output.getvalue())

    def test_installer_parser_exposes_all_product_workflows(self):
        parser = build_parser()
        for command in ("check", "install", "adopt", "upgrade"):
            with self.subTest(command=command):
                parsed = parser.parse_args([command, "--dry-run"] if command != "check" else [command])
                self.assertEqual(parsed.command, command)

    def test_top_level_installer_help_is_runnable_without_pip(self):
        result = subprocess.run(
            [sys.executable, str(REPO_ROOT / "install.py"), "--help"],
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("install", result.stdout)
        self.assertIn("adopt", result.stdout)

    def test_fresh_package_plan_uses_official_ppa_and_running_kernel_without_a_shell(self):
        plan = package_install_plan("6.8.0-79-generic")
        self.assertIn(["add-apt-repository", "-y", "ppa:amnezia/ppa"], plan)
        self.assertTrue(any("linux-headers-6.8.0-79-generic" in command for command in plan))
        self.assertTrue(any("amneziawg" in command and command[:2] == ["apt-get", "install"] for command in plan))
        self.assertTrue(all(isinstance(command, list) for command in plan))

    def test_default_interface_parser_requires_one_unambiguous_device(self):
        self.assertEqual(parse_default_interface("default via 172.26.0.1 dev ens5 proto dhcp\n"), "ens5")
        with self.assertRaisesRegex(InstallerError, "default route"):
            parse_default_interface("")

    def test_fresh_install_dry_run_requires_no_root_and_performs_no_commands(self):
        output = io.StringIO()
        with mock.patch("awginstall.cli._run", side_effect=AssertionError("must not mutate")):
            result = installer_main(
                ["install", "--dry-run", "--endpoint", "vpn.example.com", "--external-interface", "ens5"],
                root=pathlib.Path("/opt/amneziawg"),
                repo_root=REPO_ROOT,
                output=output,
            )
        self.assertEqual(result, 0)
        self.assertIn("official Amnezia PPA", output.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
