import pathlib
import argparse
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock


REPO_ROOT = pathlib.Path(__file__).parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from awgctl import core
from awgctl.contracts import (
    ContractError,
    health_envelope,
    json_envelope,
    mark_profile_regenerated,
    normalize_client_metadata,
)


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
            "profile_revision": 2,
            "distribution_status": "pending",
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
        self.assertEqual(payload["data"]["clients"][0]["profile_revision"], 2)
        self.assertEqual(payload["data"]["clients"][0]["distribution_status"], "pending")
        self.assertNotIn("RAW_PUBLIC_KEY", output.getvalue())

    def test_management_security_health_requires_installed_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = pathlib.Path(directory) / "installation.json"
            with mock.patch.object(core, "INSTALLATION_CONFIG", missing):
                checks = core.management_security_checks()
        self.assertEqual(checks, [("FAIL", "manager privilege policy", f"missing {missing}")])

    def test_version_command_does_not_require_root(self):
        output = io.StringIO()
        with mock.patch.object(core, "require_root", side_effect=AssertionError("must not be called")), redirect_stdout(output):
            result = core.main(["version", "--json"])
        self.assertEqual(result, 0)
        self.assertEqual(json.loads(output.getvalue())["data"]["version"], core.VERSION)

    def test_json_errors_use_the_same_envelope_and_not_plain_stderr(self):
        output = io.StringIO()
        errors = io.StringIO()
        with (
            mock.patch.object(core, "require_root", side_effect=core.AwgctlError("root required")),
            redirect_stdout(output),
            redirect_stderr(errors),
        ):
            result = core.main(["--json", "config", "show"])
        payload = json.loads(output.getvalue())
        self.assertEqual(result, 1)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["errors"], ["root required"])
        self.assertEqual(errors.getvalue(), "")


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
        self.assertEqual(normalized["schema_version"], 3)
        self.assertEqual(normalized["management"], "managed")
        self.assertEqual(normalized["public_key"], "public")
        self.assertIsNone(normalized["owner"])
        self.assertIsNone(normalized["device"])
        self.assertIsNone(normalized["expires"])
        self.assertEqual(normalized["profile_revision"], 1)
        self.assertEqual(normalized["profile_generated_at"], normalized["updated_at"])
        self.assertEqual(normalized["profile_change_reason"], "legacy-import")
        self.assertEqual(normalized["distribution_status"], "unknown")
        self.assertIsNone(normalized["distributed_at"])

    def test_schema_two_metadata_is_normalized_with_unknown_delivery_state(self):
        metadata = self.legacy_metadata()
        metadata.update({
            "schema_version": 2,
            "management": "managed",
            "owner": "Kat",
            "device": "iPhone",
            "expires": None,
        })
        normalized = normalize_client_metadata(metadata)
        self.assertEqual(normalized["schema_version"], 3)
        self.assertEqual(normalized["distribution_status"], "unknown")
        self.assertEqual(normalized["profile_revision"], 1)

    def test_metadata_rejects_control_characters_and_invalid_expiry(self):
        for field, value in (("owner", "Kat\nAdmin"), ("device", "x" * 65), ("expires", "31-08-2027")):
            metadata = self.legacy_metadata()
            metadata["schema_version"] = 2
            metadata.update({"management": "managed", "owner": None, "device": None, "expires": None})
            metadata[field] = value
            with self.subTest(field=field), self.assertRaises(ContractError):
                normalize_client_metadata(metadata)

    def test_new_client_state_persists_schema_three_device_and_delivery_metadata(self):
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
            self.assertEqual(metadata["schema_version"], 3)
            self.assertEqual(metadata["management"], "managed")
            self.assertEqual(metadata["owner"], "Kat")
            self.assertEqual(metadata["device"], "iPhone")
            self.assertEqual(metadata["expires"], "2027-08-31")
            self.assertEqual(metadata["profile_revision"], 1)
            self.assertEqual(metadata["profile_change_reason"], "created")
            self.assertEqual(metadata["distribution_status"], "pending")
            self.assertIsNone(metadata["distributed_at"])
            self.assertEqual(state["owner"], "Kat")

    def test_profile_regeneration_increments_revision_and_resets_delivery(self):
        metadata = normalize_client_metadata({
            **self.legacy_metadata(),
            "schema_version": 3,
            "management": "managed",
            "owner": "Kat",
            "device": "iPhone",
            "expires": None,
            "profile_revision": 2,
            "profile_generated_at": "2026-09-01T08:00:00Z",
            "profile_change_reason": "created",
            "distribution_status": "distributed",
            "distributed_at": "2026-09-01T09:00:00Z",
        })
        regenerated = mark_profile_regenerated(
            metadata,
            reason="config:dns",
            timestamp="2026-09-01T10:00:00Z",
        )
        self.assertEqual(regenerated["profile_revision"], 3)
        self.assertEqual(regenerated["profile_generated_at"], "2026-09-01T10:00:00Z")
        self.assertEqual(regenerated["profile_change_reason"], "config:dns")
        self.assertEqual(regenerated["distribution_status"], "pending")
        self.assertIsNone(regenerated["distributed_at"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
