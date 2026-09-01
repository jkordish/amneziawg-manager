import argparse
import contextlib
import io
import json
import pathlib
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock


REPO_ROOT = pathlib.Path(__file__).parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from awgctl import core


class ClientEditTests(unittest.TestCase):
    def test_parser_supports_edit_and_explicit_expiry_removal(self):
        args = core.build_parser().parse_args(["client", "edit", "kat", "--expires", "none", "--dry-run"])
        self.assertEqual(args.client_command, "edit")
        self.assertEqual(args.expires, "none")
        self.assertTrue(args.dry_run)

    def test_parser_supports_explicit_distribution_acknowledgement(self):
        args = core.build_parser().parse_args(["client", "edit", "kat", "--mark-distributed"])
        self.assertTrue(args.mark_distributed)

    def test_edit_dry_run_reports_changes_without_writing_metadata(self):
        client = {
            "schema_version": 2,
            "name": "kat",
            "status": "active",
            "management": "managed",
            "address": "10.77.42.2/32",
            "public_key": "public",
            "public_key_fingerprint": "fingerprint",
            "use_psk": True,
            "created_at": "2026-08-31T19:00:00Z",
            "updated_at": "2026-08-31T19:00:00Z",
            "owner": None,
            "device": None,
            "expires": None,
        }
        args = argparse.Namespace(client_name="kat", owner="Kat", dry_run=True, json=True)
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            with (
                mock.patch.object(core, "CLIENTS", pathlib.Path(directory)),
                mock.patch.object(core, "mutation_lock", return_value=contextlib.nullcontext()),
                mock.patch.object(core, "ensure_no_drift"),
                mock.patch.object(core, "load_clients", return_value=[client]),
                mock.patch.object(core, "atomic_json", side_effect=AssertionError("must not write")),
                mock.patch.object(core, "create_backup", side_effect=AssertionError("must not back up")),
                redirect_stdout(output),
            ):
                result = core.cmd_client_edit(args)
        self.assertEqual(result, 0)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["data"]["changes"], {"owner": {"old": None, "new": "Kat"}})

    def test_mark_distributed_records_current_profile_without_changing_identity(self):
        client = {
            "schema_version": 3,
            "name": "kat",
            "status": "active",
            "management": "managed",
            "address": "10.77.42.2/32",
            "public_key": "public",
            "public_key_fingerprint": "fingerprint",
            "use_psk": True,
            "created_at": "2026-08-31T19:00:00Z",
            "updated_at": "2026-09-01T10:00:00Z",
            "owner": "Kat",
            "device": "iPhone",
            "expires": None,
            "profile_revision": 2,
            "profile_generated_at": "2026-09-01T10:00:00Z",
            "profile_change_reason": "config:dns",
            "distribution_status": "pending",
            "distributed_at": None,
        }
        args = argparse.Namespace(client_name="kat", mark_distributed=True, dry_run=False, json=True)
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            clients_root = pathlib.Path(directory)
            (clients_root / "kat").mkdir()
            with (
                mock.patch.object(core, "CLIENTS", clients_root),
                mock.patch.object(core, "mutation_lock", return_value=contextlib.nullcontext()),
                mock.patch.object(core, "ensure_no_drift"),
                mock.patch.object(core, "load_clients", return_value=[client]),
                mock.patch.object(core, "iso_now", return_value="2026-09-01T11:00:00Z"),
                mock.patch.object(core, "create_backup", return_value=pathlib.Path("/backup")),
                mock.patch.object(core, "audit"),
                redirect_stdout(output),
            ):
                result = core.cmd_client_edit(args)
            saved = json.loads((clients_root / "kat/metadata.json").read_text())
        self.assertEqual(result, 0)
        self.assertEqual(saved["distribution_status"], "distributed")
        self.assertEqual(saved["distributed_at"], "2026-09-01T11:00:00Z")
        self.assertEqual(saved["profile_revision"], 2)
        self.assertEqual(saved["public_key"], "public")


if __name__ == "__main__":
    unittest.main(verbosity=2)
