import argparse
import contextlib
import datetime as dt
import io
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock


REPO_ROOT = pathlib.Path(__file__).parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from awgctl import core


class DryRunTests(unittest.TestCase):
    def test_public_client_expire_wraps_root_only_internal_entrypoint(self):
        args = core.build_parser().parse_args(["client", "expire", "--dry-run", "--json"])
        output = io.StringIO()
        completed = subprocess.CompletedProcess(
            [], 0, b'{"command":"client expire","ok":true}\n', b""
        )
        with (
            mock.patch.object(core, "require_root"),
            mock.patch.object(core, "run", return_value=completed) as run,
            redirect_stdout(output),
        ):
            result = core.dispatch(args)

        self.assertEqual(result, 0)
        run.assert_called_once_with(
            [str(core.INTERNAL_ENTRYPOINT), "_expire-clients", "--dry-run", "--json"],
            timeout=90,
        )
        self.assertEqual(output.getvalue(), completed.stdout.decode())

    def test_internal_expiry_dry_run_reports_due_clients_without_mutation(self):
        today = dt.datetime.now(dt.timezone.utc).date().isoformat()
        clients = [
            {"name": "due", "status": "active", "expires": today},
            {"name": "future", "status": "active", "expires": "2099-01-01"},
        ]
        args = core.build_parser(entrypoint="internal").parse_args(
            ["_expire-clients", "--dry-run", "--json"]
        )
        output = io.StringIO()
        with (
            mock.patch.object(core, "require_root"),
            mock.patch.object(core, "mutation_lock", return_value=contextlib.nullcontext()),
            mock.patch.object(core, "load_clients", return_value=clients),
            mock.patch.object(core, "atomic_json", side_effect=AssertionError("must not write metadata")),
            mock.patch.object(core, "commit_server_config", side_effect=AssertionError("must not reload")),
            redirect_stdout(output),
        ):
            result = core.dispatch(args)

        self.assertEqual(result, 0)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["data"]["due_clients"], ["due"])
        self.assertTrue(payload["data"]["dry_run"])

    def test_internal_expiry_persists_terminal_status_reloads_and_verifies_all_due_absent(self):
        today = dt.datetime.now(dt.timezone.utc).date().isoformat()
        due = {
            "name": "due",
            "status": "active",
            "expires": today,
            "public_key": "due-public",
        }
        future = {
            "name": "future",
            "status": "active",
            "expires": "2099-01-01",
            "public_key": "future-public",
        }
        args = argparse.Namespace(dry_run=False, json=True)
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            clients_root = root / "clients"
            client_dir = clients_root / "due"
            client_dir.mkdir(parents=True)
            metadata_path = client_dir / "metadata.json"
            metadata_path.write_text(json.dumps(due))
            profile_path = client_dir / "due.conf"
            profile_path.write_text("historical profile\n")
            generated = root / "generated.conf"
            runtime = root / "runtime.conf"
            generated.write_text("old server\n")
            runtime.write_text("old server\n")
            with (
                mock.patch.object(core, "CLIENTS", clients_root),
                mock.patch.object(core, "GENERATED_CONFIG", generated),
                mock.patch.object(core, "RUNTIME_CONFIG", runtime),
                mock.patch.object(core, "mutation_lock", return_value=contextlib.nullcontext()),
                mock.patch.object(core, "load_clients", return_value=[due, future]),
                mock.patch.object(core, "load_config", return_value={"interface": "awg0"}),
                mock.patch.object(core, "create_backup", return_value=root / "backup"),
                mock.patch.object(
                    core,
                    "ensure_expiry_reconcilable",
                    create=True,
                ) as reconcile,
                mock.patch.object(core, "render_current_server", return_value="filtered server\n") as render,
                mock.patch.object(core, "commit_server_config", return_value=True) as commit,
                mock.patch.object(core, "live_peers", return_value={"future-public"}),
                redirect_stdout(output),
            ):
                result = core.cmd_expire_clients(args)

            persisted = json.loads(metadata_path.read_text())
            self.assertEqual(result, 0)
            self.assertEqual(persisted["status"], "expired")
            self.assertIn("expired_at", persisted)
            self.assertEqual(profile_path.read_text(), "historical profile\n")
            reconcile.assert_called_once()
            render.assert_called_once()
            self.assertEqual(render.call_args.args[0][0]["status"], "expired")
            commit.assert_called_once_with("filtered server\n", runtime_action="reload")
            self.assertEqual(json.loads(output.getvalue())["data"]["expired_clients"], ["due"])

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
