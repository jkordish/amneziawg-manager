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


if __name__ == "__main__":
    unittest.main(verbosity=2)
