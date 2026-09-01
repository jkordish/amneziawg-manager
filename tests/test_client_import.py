import base64
import argparse
import contextlib
import io
import json
import pathlib
import sys
import tempfile
import unittest
from unittest import mock
from contextlib import redirect_stdout


REPO_ROOT = pathlib.Path(__file__).parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from awgctl import core


def key(byte: int) -> str:
    return base64.b64encode(bytes([byte]) * 32).decode("ascii")


def config() -> dict:
    return {
        "endpoint": "vpn.example.com",
        "listen_port": 55323,
        "dns": ["1.1.1.1", "1.0.0.1"],
        "mtu": 1280,
        "keepalive": 25,
        "obfuscation": {
            "Jc": 12,
            "Jmin": 56,
            "Jmax": 852,
            "S1": 149,
            "S2": 149,
            "H1": 1603259132,
            "H2": 1601077912,
            "H3": 738660798,
            "H4": 1722938668,
        },
    }


def profile(server_public: str = key(5), endpoint: str = "vpn.example.com:55323") -> str:
    return (
        "[Interface]\n"
        f"PrivateKey = {key(4)}\n"
        "Address = 10.77.42.2/32\n"
        "DNS = 1.1.1.1, 1.0.0.1\n"
        "MTU = 1280\n"
        "Jc = 12\nJmin = 56\nJmax = 852\nS1 = 149\nS2 = 149\n"
        "H1 = 1603259132\nH2 = 1601077912\nH3 = 738660798\nH4 = 1722938668\n\n"
        "[Peer]\n"
        f"PublicKey = {server_public}\n"
        f"PresharedKey = {key(3)}\n"
        f"Endpoint = {endpoint}\n"
        "AllowedIPs = 0.0.0.0/0, ::/0\n"
        "PersistentKeepalive = 25\n"
    )


class ImportProfileTests(unittest.TestCase):
    def test_valid_profile_extracts_identity_without_printing_or_regenerating_it(self):
        imported = core.parse_import_profile(
            profile(),
            config(),
            expected_server_public=key(5),
            derive_public=lambda private: key(2) if private == key(4) else "wrong",
        )
        self.assertEqual(imported["private_key"], key(4))
        self.assertEqual(imported["public_key"], key(2))
        self.assertEqual(imported["psk"], key(3))
        self.assertEqual(imported["address"], "10.77.42.2/32")

    def test_profile_server_identity_and_endpoint_must_match_managed_state(self):
        for value in (profile(server_public=key(6)), profile(endpoint="vpn.example.com:55324")):
            with self.subTest(), self.assertRaises(core.AwgctlError):
                core.parse_import_profile(
                    value,
                    config(),
                    expected_server_public=key(5),
                    derive_public=lambda _: key(2),
                )

    def test_parser_exposes_import_with_metadata_and_dry_run(self):
        args = core.build_parser().parse_args(
            [
                "client",
                "import",
                "kat-phone",
                "--config",
                "/secure/kat-phone.conf",
                "--owner",
                "Kat",
                "--device",
                "iPhone",
                "--dry-run",
            ]
        )
        self.assertEqual(args.client_command, "import")
        self.assertEqual(args.profile, pathlib.Path("/secure/kat-phone.conf"))
        self.assertTrue(args.dry_run)

    def test_external_peer_loads_without_fabricated_private_key_or_profile(self):
        with tempfile.TemporaryDirectory() as directory_text:
            root = pathlib.Path(directory_text)
            clients = root / "clients"
            keys = root / "keys"
            (clients / "external-phone").mkdir(parents=True)
            (keys / "external-phone").mkdir(parents=True)
            metadata = {
                "schema_version": 2,
                "name": "external-phone",
                "status": "active",
                "management": "external",
                "address": "10.77.42.9/32",
                "public_key": key(2),
                "public_key_fingerprint": core.fingerprint(key(2)),
                "use_psk": True,
                "created_at": "2026-09-01T00:00:00Z",
                "updated_at": "2026-09-01T00:00:00Z",
                "owner": None,
                "device": None,
                "expires": None,
            }
            (clients / "external-phone/metadata.json").write_text(__import__("json").dumps(metadata))
            (keys / "external-phone/public").write_text(key(2) + "\n")
            (keys / "external-phone/psk").write_text(key(3) + "\n")
            with (
                mock.patch.object(core, "CLIENTS", clients),
                mock.patch.object(core, "CLIENT_KEYS", keys),
            ):
                loaded = core.load_clients(include_secrets=True)
            self.assertEqual(loaded[0]["management"], "external")
            self.assertIsNone(loaded[0]["private_key"])
            self.assertEqual(loaded[0]["psk"], key(3))
            self.assertFalse((clients / "external-phone/external-phone.conf").exists())

    def test_import_dry_run_matches_existing_server_peer_without_writing_secrets(self):
        with tempfile.TemporaryDirectory() as directory_text:
            root = pathlib.Path(directory_text)
            clients = root / "clients"
            keys = root / "keys"
            clients.mkdir()
            keys.mkdir()
            profile_path = root / "phone.conf"
            profile_path.write_text(profile())
            profile_path.chmod(0o600)
            generated = root / "awg0.conf"
            generated.write_text(
                "[Interface]\nPrivateKey = " + key(1) + "\n\n"
                "[Peer]\nPublicKey = " + key(2) + "\n"
                "PresharedKey = " + key(3) + "\nAllowedIPs = 10.77.42.2/32\n"
            )
            args = argparse.Namespace(
                client_name="kat-phone",
                profile=profile_path,
                owner="Kat",
                device="iPhone",
                expires=None,
                dry_run=True,
                json=True,
            )
            output = io.StringIO()
            imported = {
                "private_key": key(4),
                "public_key": key(2),
                "psk": key(3),
                "address": "10.77.42.2/32",
                "profile": profile(),
            }
            with (
                mock.patch.object(core, "CLIENTS", clients),
                mock.patch.object(core, "CLIENT_KEYS", keys),
                mock.patch.object(core, "GENERATED_CONFIG", generated),
                mock.patch.object(core, "mutation_lock", return_value=contextlib.nullcontext()),
                mock.patch.object(core, "ensure_no_drift"),
                mock.patch.object(core, "load_config", return_value=config()),
                mock.patch.object(core, "server_public_key", return_value=key(5)),
                mock.patch.object(core, "load_clients", return_value=[]),
                mock.patch.object(core, "parse_import_profile", return_value=imported),
                mock.patch.object(core, "write_client_state", side_effect=AssertionError("must not write")),
                mock.patch.object(core, "create_backup", side_effect=AssertionError("must not back up")),
                redirect_stdout(output),
            ):
                result = core.cmd_client_import(args)
            self.assertEqual(result, 0)
            payload = json.loads(output.getvalue())
            self.assertEqual(payload["data"]["address"], "10.77.42.2")
            self.assertEqual(payload["data"]["runtime_action"], "none")


if __name__ == "__main__":
    unittest.main(verbosity=2)
