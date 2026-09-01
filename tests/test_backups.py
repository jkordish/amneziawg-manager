import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest import mock


REPO_ROOT = pathlib.Path(__file__).parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from awgctl import core
from awgctl.backups import BackupError, create_manifest, verify_backup


class BackupManifestTests(unittest.TestCase):
    def make_backup(self, root: pathlib.Path) -> pathlib.Path:
        backup = root / "20260901T010000Z"
        (backup / "config").mkdir(parents=True, mode=0o700)
        config = backup / "config/server.json"
        config.write_text('{"schema_version": 1}\n')
        config.chmod(0o600)
        manifest = create_manifest(backup, product_version="0.1.0-beta.1", created_at="2026-09-01T01:00:00Z")
        manifest_path = backup / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        manifest_path.chmod(0o600)
        return backup

    def test_manifest_verifies_hash_size_mode_owner_and_complete_file_set(self):
        with tempfile.TemporaryDirectory() as directory:
            backup = self.make_backup(pathlib.Path(directory))
            report = verify_backup(backup, expected_uid=os.getuid(), expected_gid=os.getgid())
            self.assertTrue(report["ok"])
            self.assertEqual(report["file_count"], 1)

    def test_verification_rejects_tampering_and_unexpected_files(self):
        with tempfile.TemporaryDirectory() as directory:
            backup = self.make_backup(pathlib.Path(directory))
            (backup / "config/server.json").write_text("tampered\n")
            with self.assertRaisesRegex(BackupError, "hash mismatch"):
                verify_backup(backup, expected_uid=os.getuid(), expected_gid=os.getgid())

            backup = self.make_backup(pathlib.Path(directory) / "second")
            extra = backup / "keys/private"
            extra.parent.mkdir(mode=0o700)
            extra.write_text("unexpected")
            extra.chmod(0o600)
            with self.assertRaisesRegex(BackupError, "unexpected backup file"):
                verify_backup(backup, expected_uid=os.getuid(), expected_gid=os.getgid())

    def test_cli_supports_create_list_verify_and_restore_dry_run(self):
        parser = core.build_parser()
        self.assertIsNone(parser.parse_args(["backup"]).backup_command)
        self.assertEqual(parser.parse_args(["backup", "list"]).backup_command, "list")
        verify = parser.parse_args(["backup", "verify", "20260901T010000Z"])
        self.assertEqual(verify.backup_command, "verify")
        restore = parser.parse_args(["restore", "20260901T010000Z", "--dry-run"])
        self.assertEqual(restore.backup, pathlib.Path("20260901T010000Z"))
        self.assertTrue(restore.dry_run)

    def test_manager_created_backup_has_a_verified_manifest_and_revoked_state(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            root = pathlib.Path(directory) / "product"
            (root / "config").mkdir(parents=True)
            (root / "config/server.json").write_text("{}\n")
            (root / "revoked/old-client").mkdir(parents=True)
            (root / "revoked/old-client/metadata.json").write_text("{}\n")
            replacements = {
                "ROOT": root,
                "CONFIG_FILE": root / "config/server.json",
                "SERVER_PRIVATE": root / "keys/server/private",
                "SERVER_PUBLIC": root / "keys/server/public",
                "CLIENT_KEYS": root / "keys/clients",
                "CLIENTS": root / "clients",
                "REVOKED": root / "revoked",
                "GENERATED": root / "generated",
                "GENERATED_CONFIG": root / "generated/awg0.conf",
                "GENERATED_NFT": root / "generated/nftables.nft",
                "BACKUPS": root / "backups",
            }
            for name, value in replacements.items():
                stack.enter_context(mock.patch.object(core, name, value))
            stack.enter_context(mock.patch.object(core, "load_config", return_value={"interface": "awg0"}))
            stack.enter_context(
                mock.patch.object(
                    core,
                    "run",
                    return_value=subprocess.CompletedProcess([], 0, stdout=b"", stderr=b""),
                )
            )

            backup = core.create_backup()

            report = verify_backup(backup, expected_uid=os.getuid(), expected_gid=os.getgid())
            self.assertTrue(report["ok"])
            self.assertTrue((backup / "revoked/old-client/metadata.json").is_file())
            self.assertEqual(report["product_version"], core.VERSION)

    def test_restore_dry_run_verifies_without_creating_a_safety_backup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            backup = self.make_backup(root)
            args = SimpleNamespace(backup=backup, dry_run=True, json=False)
            with (
                mock.patch.object(core, "BACKUPS", root),
                mock.patch.object(core, "create_backup") as create,
                mock.patch("builtins.print") as output,
            ):
                result = core.cmd_restore(args)
            self.assertEqual(result, 0)
            create.assert_not_called()
            self.assertIn("Restore dry run", output.call_args_list[0].args[0])


if __name__ == "__main__":
    unittest.main(verbosity=2)
