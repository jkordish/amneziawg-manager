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


class DryRunTests(unittest.TestCase):
    def test_client_add_dry_run_allocates_address_without_generating_credentials(self):
        config = {
            "subnet": "10.77.42.0/24",
            "server_address": "10.77.42.1/24",
            "interface": "awg0",
        }
        clients = [
            {
                "name": "kat",
                "address": "10.77.42.2/32",
                "public_key": "public",
            }
        ]
        output = io.StringIO()
        args = argparse.Namespace(
            client_name="kat-phone",
            owner="Kat",
            device="iPhone",
            expires="2027-08-31",
            dry_run=True,
            json=True,
        )
        with tempfile.TemporaryDirectory() as directory:
            with (
                mock.patch.object(core, "CLIENTS", pathlib.Path(directory) / "clients"),
                mock.patch.object(core, "CLIENT_KEYS", pathlib.Path(directory) / "keys"),
                mock.patch.object(core, "mutation_lock", return_value=contextlib.nullcontext()),
                mock.patch.object(core, "ensure_no_drift"),
                mock.patch.object(core, "load_config", return_value=config),
                mock.patch.object(core, "load_clients", return_value=clients),
                mock.patch.object(core, "generate_key_material", side_effect=AssertionError("must not generate")),
                mock.patch.object(core, "create_backup", side_effect=AssertionError("must not back up")),
                redirect_stdout(output),
            ):
                result = core.cmd_client_add(args)
        self.assertEqual(result, 0)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["command"], "client add")
        self.assertEqual(payload["data"]["address"], "10.77.42.3")
        self.assertEqual(payload["data"]["runtime_action"], "reload")
        self.assertTrue(payload["data"]["dry_run"])

    def test_service_dry_run_never_calls_systemd(self):
        args = argparse.Namespace(command="restart", dry_run=True, json=True)
        output = io.StringIO()
        with (
            mock.patch.object(core, "load_config", return_value={"interface": "awg0"}),
            mock.patch.object(core, "mutation_lock", return_value=contextlib.nullcontext()),
            mock.patch.object(core, "ensure_no_drift"),
            mock.patch.object(core, "service_action", side_effect=AssertionError("must not call systemd")),
            redirect_stdout(output),
        ):
            result = core.cmd_service(args)
        self.assertEqual(result, 0)
        payload = json.loads(output.getvalue())
        self.assertTrue(payload["data"]["dry_run"])
        self.assertEqual(payload["data"]["action"], "restart")

    def test_service_execution_json_uses_the_stable_envelope(self):
        args = argparse.Namespace(command="reload", dry_run=False, json=True)
        output = io.StringIO()
        with (
            mock.patch.object(core, "load_config", return_value={"interface": "awg0"}),
            mock.patch.object(core, "mutation_lock", return_value=contextlib.nullcontext()),
            mock.patch.object(core, "ensure_no_drift"),
            mock.patch.object(core, "service_action"),
            redirect_stdout(output),
        ):
            result = core.cmd_service(args)
        payload = json.loads(output.getvalue())
        self.assertEqual(result, 0)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["command"], "reload")
        self.assertEqual(payload["data"]["service"], "awg-quick@awg0.service")

    def test_revoke_dry_run_does_not_archive_backup_or_reload(self):
        client = {
            "name": "kat-phone",
            "address": "10.77.42.3/32",
            "public_key": "public",
            "management": "managed",
        }
        args = argparse.Namespace(client_name="kat-phone", dry_run=True, json=True)
        output = io.StringIO()
        with (
            mock.patch.object(core, "mutation_lock", return_value=contextlib.nullcontext()),
            mock.patch.object(core, "ensure_no_drift"),
            mock.patch.object(core, "load_config", return_value={"interface": "awg0"}),
            mock.patch.object(core, "load_clients", return_value=[client]),
            mock.patch.object(core, "create_backup", side_effect=AssertionError("must not back up")),
            mock.patch.object(core, "archive_client_copy", side_effect=AssertionError("must not archive")),
            mock.patch.object(core, "commit_server_config", side_effect=AssertionError("must not reload")),
            redirect_stdout(output),
        ):
            result = core.cmd_client_revoke(args)
        self.assertEqual(result, 0)
        payload = json.loads(output.getvalue())
        self.assertTrue(payload["data"]["dry_run"])
        self.assertEqual(payload["data"]["name"], "kat-phone")

    def test_external_client_cannot_be_rotated_without_importing_profile(self):
        client = {
            "name": "external-phone",
            "address": "10.77.42.9/32",
            "public_key": "public",
            "management": "external",
        }
        args = argparse.Namespace(client_name="external-phone", dry_run=True, json=False)
        with (
            mock.patch.object(core, "mutation_lock", return_value=contextlib.nullcontext()),
            mock.patch.object(core, "ensure_no_drift"),
            mock.patch.object(core, "load_config", return_value={"interface": "awg0"}),
            mock.patch.object(core, "load_clients", return_value=[client]),
            mock.patch.object(core, "generate_key_material", side_effect=AssertionError("must not generate")),
        ):
            with self.assertRaisesRegex(core.AwgctlError, "import its profile"):
                core.cmd_client_rotate(args)

    def test_config_set_dry_run_does_not_backup_or_write(self):
        config = {
            "endpoint": "old.example.com",
            "dns": ["1.1.1.1"],
            "mtu": 1280,
            "listen_port": 55323,
        }
        args = argparse.Namespace(key="endpoint", value="new.example.com", dry_run=True, json=True)
        output = io.StringIO()
        with (
            mock.patch.object(core, "mutation_lock", return_value=contextlib.nullcontext()),
            mock.patch.object(core, "ensure_no_drift"),
            mock.patch.object(core, "load_config", return_value=config),
            mock.patch.object(core, "validate_server_config", side_effect=lambda value: value),
            mock.patch.object(core, "load_clients", return_value=[]),
            mock.patch.object(core, "create_backup", side_effect=AssertionError("must not back up")),
            redirect_stdout(output),
        ):
            result = core.cmd_config_set(args)
        self.assertEqual(result, 0)
        payload = json.loads(output.getvalue())
        self.assertTrue(payload["data"]["dry_run"])
        self.assertEqual(payload["data"]["new"], "new.example.com")


if __name__ == "__main__":
    unittest.main(verbosity=2)
