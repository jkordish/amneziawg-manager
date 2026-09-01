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
import os


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
        self.assertEqual(imported["profile"], profile())

    def test_import_rejects_duplicate_sections_and_keys_without_echoing_values(self):
        duplicate_key = profile().replace(
            f"PrivateKey = {key(4)}\n",
            f"PrivateKey = {key(4)}\nPrivateKey = {key(6)}\n",
        )
        duplicate_section = profile() + "\n[Interface]\nAddress = 10.77.42.3/32\n"
        for value in (duplicate_key, duplicate_section):
            with self.subTest(value=value[:40]):
                with self.assertRaises(core.AwgctlError) as raised:
                    core.parse_import_profile(
                        value,
                        config(),
                        expected_server_public=key(5),
                        derive_public=lambda _: key(2),
                    )
                self.assertNotIn(key(4), str(raised.exception))
                self.assertNotIn(key(6), str(raised.exception))

    def test_import_rejects_unknown_sections_and_generation_directives(self):
        cases = (
            profile().replace("MTU = 1280\n", "MTU = 1280\nTable = off\n"),
            profile().replace("MTU = 1280\n", "MTU = 1280\nPostUp = echo unsafe\n"),
            profile().replace("[Peer]\n", "[Mystery]\nValue = yes\n\n[Peer]\n"),
            profile().replace("Endpoint =", "endpoint ="),
        )
        for value in cases:
            with self.subTest(), self.assertRaises(core.AwgctlError):
                core.parse_import_profile(
                    value,
                    config(),
                    expected_server_public=key(5),
                    derive_public=lambda _: key(2),
                )

    def test_import_canonicalizes_valid_untrusted_formatting(self):
        supplied = "# imported from another device\n" + profile().replace(
            "DNS = 1.1.1.1, 1.0.0.1",
            "DNS=1.1.1.1,1.0.0.1",
        )
        imported = core.parse_import_profile(
            supplied,
            config(),
            expected_server_public=key(5),
            derive_public=lambda _: key(2),
        )
        self.assertEqual(imported["profile"], profile())
        self.assertNotIn("imported from", imported["profile"])

    def test_profile_reader_is_descriptor_bound_and_bounded(self):
        with tempfile.TemporaryDirectory() as directory_text:
            root = pathlib.Path(directory_text)
            profile_path = root / "phone.conf"
            opened_path = root / "opened-phone.conf"
            replacement = root / "replacement.conf"
            profile_path.write_text(profile())
            profile_path.chmod(0o600)
            replacement.write_text("[Interface]\nPostUp = unsafe\n")
            replacement.chmod(0o600)
            real_open = os.open
            swapped = False

            def swap_after_open(path, flags, mode=0o777, *, dir_fd=None):
                nonlocal swapped
                fd = real_open(path, flags, mode, dir_fd=dir_fd)
                if not swapped and os.fspath(path) == os.fspath(profile_path):
                    swapped = True
                    profile_path.rename(opened_path)
                    profile_path.symlink_to(replacement)
                return fd

            with mock.patch.object(core.os, "open", side_effect=swap_after_open):
                self.assertEqual(core.read_client_profile(profile_path), profile())

            oversized = root / "oversized.conf"
            oversized.write_bytes(b"x" * (64 * 1024 + 1))
            oversized.chmod(0o600)
            with self.assertRaisesRegex(core.AwgctlError, "large"):
                core.read_client_profile(oversized)

    def test_profile_reader_rejects_symlinks_and_invalid_utf8(self):
        with tempfile.TemporaryDirectory() as directory_text:
            root = pathlib.Path(directory_text)
            target = root / "target.conf"
            target.write_text(profile())
            target.chmod(0o600)
            link = root / "link.conf"
            link.symlink_to(target)
            with self.assertRaises(core.AwgctlError):
                core.read_client_profile(link)
            invalid = root / "invalid.conf"
            invalid.write_bytes(b"\xff")
            invalid.chmod(0o600)
            with self.assertRaisesRegex(core.AwgctlError, "UTF-8"):
                core.read_client_profile(invalid)

    def test_shared_parser_keeps_legitimate_multiple_server_peers(self):
        parsed = core.parse_awg_config(
            "[Interface]\nPostUp = managed\nPostDown = managed\n\n"
            "[Peer]\nPublicKey = one\n\n[Peer]\nPublicKey = two\n"
        )
        self.assertEqual([peer["PublicKey"] for peer in parsed["Peer"]], ["one", "two"])

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

    def test_import_persists_the_validated_canonical_profile(self):
        with tempfile.TemporaryDirectory() as directory_text:
            root = pathlib.Path(directory_text)
            clients = root / "clients"
            keys = root / "keys"
            clients.mkdir()
            keys.mkdir()
            profile_path = root / "phone.conf"
            supplied = "# untrusted formatting\n" + profile()
            profile_path.write_text(supplied)
            profile_path.chmod(0o600)
            generated = root / "awg0.conf"
            generated.write_text("generated")
            args = argparse.Namespace(
                client_name="kat-phone",
                profile=profile_path,
                owner="Kat",
                device="iPhone",
                expires=None,
                dry_run=False,
                json=True,
            )
            imported = {
                "private_key": key(4),
                "public_key": key(2),
                "psk": key(3),
                "address": "10.77.42.2/32",
                "profile": profile(),
            }
            written = mock.Mock()
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
                mock.patch.object(
                    core,
                    "_server_peer_for_public",
                    return_value={"AllowedIPs": imported["address"], "PresharedKey": imported["psk"]},
                ),
                mock.patch.object(core, "create_backup", return_value=root / "backup"),
                mock.patch.object(core, "write_client_state", written),
                mock.patch.object(core, "render_current_server", return_value="generated"),
                mock.patch.object(core, "semantic_signature", return_value={}),
                mock.patch.object(core, "audit"),
                redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(core.cmd_client_import(args), 0)
            self.assertEqual(written.call_args.kwargs["profile_text"], profile())
            self.assertNotEqual(written.call_args.kwargs["profile_text"], supplied)


if __name__ == "__main__":
    unittest.main(verbosity=2)
