import pathlib
import argparse
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock


REPO_ROOT = pathlib.Path(__file__).parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from awgctl import core
from awgctl.contracts import ContractError, health_envelope, json_envelope, normalize_client_metadata


class JsonContractTests(unittest.TestCase):
    def test_envelope_has_stable_shape_and_separates_warnings_from_errors(self):
        payload = json_envelope(
            "health",
            data={"service": "active"},
            warnings=[{"name": "swap", "detail": "none configured"}],
        )
        self.assertEqual(
            payload,
            {
                "schema_version": 1,
                "command": "health",
                "ok": True,
                "data": {"service": "active"},
                "warnings": [{"name": "swap", "detail": "none configured"}],
                "errors": [],
            },
        )

    def test_cli_accepts_json_before_or_after_read_only_command(self):
        parser = core.build_parser()
        self.assertTrue(parser.parse_args(["--json", "status"]).json)
        self.assertTrue(parser.parse_args(["status", "--json"]).json)
        self.assertTrue(parser.parse_args(["client", "list", "--json"]).json)

    def test_mutations_expose_dry_run_without_changing_existing_grammar(self):
        parser = core.build_parser()
        client = parser.parse_args(["client", "add", "kat-phone", "--dry-run"])
        config = parser.parse_args(["config", "set", "mtu", "1280", "--dry-run"])
        self.assertTrue(client.dry_run)
        self.assertTrue(config.dry_run)

    def test_status_json_is_structured_and_contains_no_raw_public_key(self):
        config = {
            "interface": "awg0",
            "endpoint": "vpn.example.com",
            "listen_port": 55323,
            "subnet": "10.77.42.0/24",
        }
        completed = mock.Mock(returncode=0, stdout=b"awg0 UP\n", stderr=b"")
        client = {
            "name": "kat",
            "address": "10.77.42.2/32",
            "public_key": "RAW_PUBLIC_KEY",
            "status": "active",
            "management": "managed",
        }
        output = io.StringIO()
        with (
            mock.patch.object(core, "load_config", return_value=config),
            mock.patch.object(core, "systemctl_state", return_value=("active", "enabled")),
            mock.patch.object(core, "run", return_value=completed),
            mock.patch.object(core, "imds_value", return_value="203.0.113.7"),
            mock.patch.object(core, "live_peers", return_value={"RAW_PUBLIC_KEY"}),
            mock.patch.object(core, "handshake_map", return_value={"RAW_PUBLIC_KEY": 0}),
            mock.patch.object(core, "load_clients", return_value=[client]),
            mock.patch.object(core, "nft_table_active", return_value=True),
            redirect_stdout(output),
        ):
            result = core.cmd_status(argparse.Namespace(json=True))
        self.assertEqual(result, 0)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["command"], "status")
        self.assertEqual(payload["data"]["clients"][0]["name"], "kat")
        self.assertNotIn("RAW_PUBLIC_KEY", output.getvalue())

    def test_health_envelope_marks_failures_but_not_warnings_as_broken(self):
        warning_only = health_envelope([("PASS", "service", "active"), ("WARN", "swap", "none")])
        broken = health_envelope([("FAIL", "service", "inactive")])
        self.assertTrue(warning_only["ok"])
        self.assertEqual(warning_only["data"]["summary"], {"failures": 0, "warnings": 1})
        self.assertFalse(broken["ok"])
        self.assertEqual(broken["errors"][0]["name"], "service")

    def test_client_list_json_does_not_emit_public_keys(self):
        client = {
            "name": "kat",
            "address": "10.77.42.2/32",
            "public_key": "RAW_PUBLIC_KEY",
            "status": "active",
            "management": "managed",
            "owner": "Kat",
            "device": "phone",
            "expires": None,
        }
        output = io.StringIO()
        with (
            mock.patch.object(core, "load_config", return_value={"interface": "awg0"}),
            mock.patch.object(core, "load_clients", return_value=[client]),
            mock.patch.object(core, "is_service_active", return_value=True),
            mock.patch.object(core, "handshake_map", return_value={"RAW_PUBLIC_KEY": 0}),
            redirect_stdout(output),
        ):
            result = core.cmd_client_list(argparse.Namespace(json=True))
        self.assertEqual(result, 0)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["data"]["clients"][0]["owner"], "Kat")
        self.assertNotIn("RAW_PUBLIC_KEY", output.getvalue())

    def test_version_command_does_not_require_root(self):
        output = io.StringIO()
        with mock.patch.object(core, "require_root", side_effect=AssertionError("must not be called")), redirect_stdout(output):
            result = core.main(["version", "--json"])
        self.assertEqual(result, 0)
        self.assertEqual(json.loads(output.getvalue())["data"]["version"], "0.1.0-beta.1")


class ClientMetadataTests(unittest.TestCase):
    def legacy_metadata(self):
        return {
            "schema_version": 1,
            "name": "kat",
            "status": "active",
            "address": "10.77.42.2/32",
            "public_key": "public",
            "public_key_fingerprint": "fingerprint",
            "use_psk": True,
            "created_at": "2026-08-31T19:00:00Z",
            "updated_at": "2026-08-31T19:00:00Z",
        }

    def test_schema_one_metadata_is_normalized_without_losing_identity(self):
        normalized = normalize_client_metadata(self.legacy_metadata())
        self.assertEqual(normalized["schema_version"], 2)
        self.assertEqual(normalized["management"], "managed")
        self.assertEqual(normalized["public_key"], "public")
        self.assertIsNone(normalized["owner"])
        self.assertIsNone(normalized["device"])
        self.assertIsNone(normalized["expires"])

    def test_metadata_rejects_control_characters_and_invalid_expiry(self):
        for field, value in (("owner", "Kat\nAdmin"), ("device", "x" * 65), ("expires", "31-08-2027")):
            metadata = self.legacy_metadata()
            metadata["schema_version"] = 2
            metadata.update({"management": "managed", "owner": None, "device": None, "expires": None})
            metadata[field] = value
            with self.subTest(field=field), self.assertRaises(ContractError):
                normalize_client_metadata(metadata)

    def test_new_client_state_persists_schema_two_device_metadata(self):
        with tempfile.TemporaryDirectory() as directory_text:
            root = pathlib.Path(directory_text)
            clients = root / "clients"
            keys = root / "keys"
            clients.mkdir()
            keys.mkdir()
            with (
                mock.patch.object(core, "CLIENTS", clients),
                mock.patch.object(core, "CLIENT_KEYS", keys),
                mock.patch.object(core, "server_public_key", return_value="server-public"),
                mock.patch.object(core, "render_client_config", return_value="profile\n"),
                mock.patch.object(core, "generate_qr"),
            ):
                state = core.write_client_state(
                    {},
                    "kat-phone",
                    "10.77.42.3/32",
                    "private",
                    "public",
                    "psk",
                    owner="Kat",
                    device="iPhone",
                    expires="2027-08-31",
                )
            metadata = json.loads((clients / "kat-phone/metadata.json").read_text())
            self.assertEqual(metadata["schema_version"], 2)
            self.assertEqual(metadata["management"], "managed")
            self.assertEqual(metadata["owner"], "Kat")
            self.assertEqual(metadata["device"], "iPhone")
            self.assertEqual(metadata["expires"], "2027-08-31")
            self.assertEqual(state["owner"], "Kat")


if __name__ == "__main__":
    unittest.main(verbosity=2)
