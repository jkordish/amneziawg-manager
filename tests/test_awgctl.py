#!/usr/bin/env python3
import argparse
import base64
import contextlib
import datetime as dt
import io
import ipaddress
import json
import os
import pathlib
import pwd
import sys
import tempfile
import unittest
from unittest import mock


BUILD_ROOT = pathlib.Path(__file__).parents[1]
sys.path.insert(0, str(BUILD_ROOT / "src"))

from awgctl import core as awgctl


class TtyStringIO(io.StringIO):
    def isatty(self):
        return True


def key(byte: int) -> str:
    return base64.b64encode(bytes([byte]) * 32).decode("ascii")


class ValidationTests(unittest.TestCase):
    def test_client_name_rejects_path_and_overlong_values(self):
        for value in ("", "../kat", "kat phone", "-kat", "a" * 33):
            with self.subTest(value=value), self.assertRaises(awgctl.AwgctlError):
                awgctl.validate_client_name(value)

    def test_client_name_accepts_device_profile_names(self):
        for value in ("kat", "kat-iphone", "Joe_iPad2"):
            with self.subTest(value=value):
                self.assertEqual(awgctl.validate_client_name(value), value)

    def test_endpoint_rejects_urls_ports_and_invalid_labels(self):
        for value in ("https://vpn.example.com", "vpn.example.com:55323", "bad name", "-bad.example"):
            with self.subTest(value=value), self.assertRaises(awgctl.AwgctlError):
                awgctl.validate_endpoint(value)

    def test_endpoint_accepts_hostname_and_ipv4(self):
        self.assertEqual(awgctl.validate_endpoint("vpn.example.com"), "vpn.example.com")
        self.assertEqual(awgctl.validate_endpoint("54.185.178.74"), "54.185.178.74")


class ClientAddWizardTests(unittest.TestCase):
    def test_confirmed_wizard_collects_profile_creation_arguments(self):
        answers = io.StringIO("Kat\niPhone\n\n2027-09-01\nyes\n")
        output = io.StringIO()

        values = awgctl.collect_client_add_wizard(answers, output)

        self.assertEqual(values, {
            "client_name": "kat-iphone",
            "owner": "Kat",
            "device": "iPhone",
            "expires": "2027-09-01",
        })
        review = output.getvalue()
        self.assertIn("Review profile", review)
        self.assertIn("Name:    kat-iphone", review)
        self.assertIn("reload the AmneziaWG server configuration", review)

    def test_invalid_profile_name_is_corrected_without_restarting_wizard(self):
        answers = io.StringIO("Kat\niPhone\n../shared\nkat-iphone\n\ny\n")
        output = io.StringIO()

        values = awgctl.collect_client_add_wizard(answers, output)

        self.assertEqual(values["client_name"], "kat-iphone")
        self.assertIn("Use 1-32 letters, numbers, underscores, or hyphens", output.getvalue())

    def test_required_recipient_fields_are_corrected_at_their_prompts(self):
        answers = io.StringIO(f"\nKat\n{'x' * 65}\niPhone\n\n\ny\n")
        output = io.StringIO()

        values = awgctl.collect_client_add_wizard(answers, output)

        self.assertEqual(values["owner"], "Kat")
        self.assertEqual(values["device"], "iPhone")
        self.assertIn("Owner is required", output.getvalue())
        self.assertIn("Device must be 1-64 printable characters", output.getvalue())

    def test_invalid_expiration_is_corrected_before_review(self):
        answers = io.StringIO("Kat\niPhone\n\n31-08-2027\n2027-09-01\ny\n")
        output = io.StringIO()

        values = awgctl.collect_client_add_wizard(answers, output)

        self.assertEqual(values["expires"], "2027-09-01")
        self.assertIn("Enter a date as YYYY-MM-DD", output.getvalue())

    def test_declined_confirmation_cancels_without_error(self):
        answers = io.StringIO("Kat\niPhone\n\n\nn\n")
        output = io.StringIO()

        values = awgctl.collect_client_add_wizard(answers, output)

        self.assertIsNone(values)
        self.assertIn("Cancelled. No changes were made.", output.getvalue())

    def test_end_of_input_cancels_instead_of_repeating_prompts(self):
        class OneShotEndOfInput(io.StringIO):
            def readline(self, *args, **kwargs):
                if self.tell() > 0:
                    raise AssertionError("wizard read again after end of input")
                self.seek(1)
                return ""

        output = io.StringIO()

        values = awgctl.collect_client_add_wizard(OneShotEndOfInput(" "), output)

        self.assertIsNone(values)
        self.assertIn("Cancelled. No changes were made.", output.getvalue())

    def test_missing_name_requires_an_interactive_terminal_before_mutation(self):
        args = argparse.Namespace(
            client_name=None,
            owner=None,
            device=None,
            expires=None,
            dry_run=False,
            json=False,
        )
        with (
            mock.patch.object(awgctl.sys, "stdin", io.StringIO()),
            mock.patch.object(awgctl.sys, "stdout", io.StringIO()),
            mock.patch.object(awgctl, "mutation_lock", side_effect=AssertionError("must not mutate")),
        ):
            with self.assertRaisesRegex(awgctl.AwgctlError, "interactive terminal"):
                awgctl.cmd_client_add(args)

    def test_json_mode_requires_explicit_name_without_prompting(self):
        args = argparse.Namespace(
            client_name=None,
            owner=None,
            device=None,
            expires=None,
            dry_run=False,
            json=True,
        )
        answers = TtyStringIO("Kat\niPhone\n\n\ny\n")
        with (
            mock.patch.object(awgctl.sys, "stdin", answers),
            mock.patch.object(awgctl.sys, "stdout", TtyStringIO()),
            mock.patch.object(awgctl, "mutation_lock", side_effect=AssertionError("must not mutate")),
        ):
            with self.assertRaisesRegex(awgctl.AwgctlError, "--json requires NAME"):
                awgctl.cmd_client_add(args)
        self.assertEqual(answers.tell(), 0)

    def test_confirmed_wizard_enters_existing_client_add_dry_run(self):
        args = argparse.Namespace(
            client_name=None,
            owner=None,
            device=None,
            expires=None,
            dry_run=True,
            json=False,
        )
        answers = TtyStringIO("Kat\niPhone\n\n2027-09-01\ny\n")
        output = TtyStringIO()
        config = {
            "subnet": "10.77.42.0/24",
            "server_address": "10.77.42.1/24",
            "interface": "awg0",
        }
        with tempfile.TemporaryDirectory() as directory:
            with (
                mock.patch.object(awgctl.sys, "stdin", answers),
                mock.patch.object(awgctl.sys, "stdout", output),
                mock.patch.object(awgctl, "CLIENTS", pathlib.Path(directory) / "clients"),
                mock.patch.object(awgctl, "CLIENT_KEYS", pathlib.Path(directory) / "keys"),
                mock.patch.object(awgctl, "mutation_lock", return_value=contextlib.nullcontext()),
                mock.patch.object(awgctl, "ensure_no_drift"),
                mock.patch.object(awgctl, "load_config", return_value=config),
                mock.patch.object(awgctl, "load_clients", return_value=[]),
                mock.patch.object(awgctl, "generate_key_material", side_effect=AssertionError("must not generate")),
                mock.patch.object(awgctl, "create_backup", side_effect=AssertionError("must not back up")),
            ):
                result = awgctl.cmd_client_add(args)

        self.assertEqual(result, 0)
        self.assertEqual(args.client_name, "kat-iphone")
        self.assertIn("Review profile", output.getvalue())
        self.assertIn("Dry run: create client kat-iphone", output.getvalue())
        self.assertIn("address: 10.77.42.2", output.getvalue())

    def test_dry_run_review_describes_a_non_mutating_preview(self):
        answers = io.StringIO("Kat\niPhone\n\n\ny\n")
        output = io.StringIO()

        values = awgctl.collect_client_add_wizard(answers, output, dry_run=True)

        self.assertEqual(values["client_name"], "kat-iphone")
        self.assertIn(
            "No credentials, backups, files, or service reloads will be created.",
            output.getvalue(),
        )

    def test_completed_wizard_prints_secure_delivery_commands(self):
        args = argparse.Namespace(
            client_name=None,
            owner=None,
            device=None,
            expires=None,
            dry_run=False,
            json=False,
        )
        answers = TtyStringIO("Kat\niPhone\n\n\ny\n")
        output = TtyStringIO()
        config = {
            "subnet": "10.77.42.0/24",
            "server_address": "10.77.42.1/24",
            "interface": "awg0",
            "use_psk": True,
        }
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            with (
                mock.patch.object(awgctl.sys, "stdin", answers),
                mock.patch.object(awgctl.sys, "stdout", output),
                mock.patch.object(awgctl, "CLIENTS", root / "clients"),
                mock.patch.object(awgctl, "CLIENT_KEYS", root / "keys"),
                mock.patch.object(awgctl, "mutation_lock", return_value=contextlib.nullcontext()),
                mock.patch.object(awgctl, "ensure_no_drift"),
                mock.patch.object(awgctl, "load_config", return_value=config),
                mock.patch.object(awgctl, "load_clients", side_effect=[[], [{"name": "kat-iphone"}]]),
                mock.patch.object(awgctl, "create_backup", return_value=root / "backups" / "before.tar"),
                mock.patch.object(awgctl, "generate_key_material", return_value=("private", "public", "psk")),
                mock.patch.object(awgctl, "write_client_state"),
                mock.patch.object(awgctl, "server_private_key", return_value="server-private"),
                mock.patch.object(awgctl, "render_server_config", return_value="server-config"),
                mock.patch.object(awgctl, "commit_server_config", return_value=True),
                mock.patch.object(awgctl, "verify_peer_state"),
                mock.patch.object(awgctl, "audit"),
            ):
                result = awgctl.cmd_client_add(args)

        self.assertEqual(result, 0)
        self.assertIn("Next steps:", output.getvalue())
        self.assertIn(
            "sudo awgctl client export kat-iphone --output /home/OPERATOR/kat-iphone.conf",
            output.getvalue(),
        )
        self.assertIn(
            "sudo awgctl client qr kat-iphone --output /home/OPERATOR/kat-iphone.png",
            output.getvalue(),
        )


class StateTests(unittest.TestCase):
    def test_next_address_uses_first_unallocated_host_after_server(self):
        address = awgctl.next_client_address(
            ipaddress.ip_network("10.77.42.0/24"),
            ipaddress.ip_interface("10.77.42.1/24"),
            {ipaddress.ip_interface("10.77.42.2/32")},
        )
        self.assertEqual(str(address), "10.77.42.3/32")

    def test_duplicate_addresses_and_public_keys_are_rejected(self):
        clients = [
            {"name": "kat", "address": "10.77.42.2/32", "public_key": key(3)},
            {"name": "phone", "address": "10.77.42.2/32", "public_key": key(3)},
        ]
        problems = awgctl.find_duplicate_client_state(clients)
        self.assertEqual(problems, [
            "duplicate client address: 10.77.42.2/32 (kat, phone)",
            "duplicate client public key (kat, phone)",
        ])

    def test_parse_legacy_config_keeps_base64_padding(self):
        parsed = awgctl.parse_awg_config(
            "[Interface]\nPrivateKey = " + key(1) + "\nJc = 12\n\n"
            "[Peer]\nPublicKey = " + key(2) + "\nAllowedIPs = 10.77.42.2/32\n"
        )
        self.assertEqual(parsed["Interface"][0]["PrivateKey"], key(1))
        self.assertEqual(parsed["Peer"][0]["PublicKey"], key(2))


class RenderingTests(unittest.TestCase):
    def setUp(self):
        self.config = {
            "interface": "awg0",
            "subnet": "10.77.42.0/24",
            "server_address": "10.77.42.1/24",
            "endpoint": "staging.honeywire.ai",
            "listen_port": 55323,
            "external_interface": "ens5",
            "dns": ["1.1.1.1", "1.0.0.1"],
            "mtu": 1280,
            "keepalive": 25,
            "use_psk": True,
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

    def test_server_render_is_manager_owned_and_has_no_saveconfig(self):
        rendered = awgctl.render_server_config(
            self.config,
            key(1),
            [{"name": "kat", "address": "10.77.42.2/32", "public_key": key(2), "psk": key(3)}],
        )
        expected = (
            "[Interface]\n"
            "Address = 10.77.42.1/24\n"
            "ListenPort = 55323\n"
            f"PrivateKey = {key(1)}\n"
            "MTU = 1280\n"
            "Jc = 12\nJmin = 56\nJmax = 852\nS1 = 149\nS2 = 149\n"
            "H1 = 1603259132\nH2 = 1601077912\nH3 = 738660798\nH4 = 1722938668\n"
            "PostUp = /opt/amneziawg/libexec/awgctl-internal _firewall up\n"
            "PostDown = /opt/amneziawg/libexec/awgctl-internal _firewall down\n\n"
            "[Peer]\n# kat\n"
            f"PublicKey = {key(2)}\nPresharedKey = {key(3)}\n"
            "AllowedIPs = 10.77.42.2/32\n"
        )
        self.assertEqual(rendered, expected)
        self.assertNotIn("SaveConfig", rendered)

    def test_server_render_excludes_peer_at_utc_start_of_expiry_date(self):
        today = dt.datetime.now(dt.timezone.utc).date().isoformat()
        rendered = awgctl.render_server_config(
            self.config,
            key(1),
            [
                {
                    "name": "due",
                    "status": "active",
                    "expires": today,
                    "address": "10.77.42.2/32",
                    "public_key": key(2),
                    "psk": key(3),
                },
                {
                    "name": "future",
                    "status": "active",
                    "expires": "2099-01-01",
                    "address": "10.77.42.3/32",
                    "public_key": key(4),
                    "psk": key(5),
                },
            ],
        )

        self.assertNotIn("# due\n", rendered)
        self.assertIn("# future\n", rendered)

    def test_client_render_inherits_stable_obfuscation(self):
        rendered = awgctl.render_client_config(self.config, key(2), key(3), key(1), "10.77.42.3/32")
        self.assertIn("Address = 10.77.42.3/32", rendered)
        self.assertIn("Endpoint = staging.honeywire.ai:55323", rendered)
        self.assertIn("PersistentKeepalive = 25", rendered)
        self.assertIn("AllowedIPs = 0.0.0.0/0, ::/0", rendered)
        self.assertIn("Jc = 12\nJmin = 56\nJmax = 852", rendered)

    def test_nft_render_blocks_private_and_metadata_before_internet_plumbing(self):
        rendered = awgctl.render_nftables_config(self.config)
        self.assertIn("table ip amneziawg_forward", rendered)
        self.assertIn("table ip amneziawg_nat", rendered)
        self.assertIn("169.254.0.0/16", rendered)
        self.assertIn("100.64.0.0/10", rendered)
        self.assertIn('iifname "awg0" oifname != "ens5"', rendered)
        self.assertIn('ip saddr 10.77.42.0/24 oifname "ens5"', rendered)
        self.assertNotIn("hook input", rendered.lower())


class AtomicWriteTests(unittest.TestCase):
    def test_atomic_write_sets_requested_mode_and_complete_content(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "state.json"
            awgctl.atomic_write(path, b'{"ok": true}\n', 0o600)
            self.assertEqual(path.read_bytes(), b'{"ok": true}\n')
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)


class OperationalContractTests(unittest.TestCase):
    def test_client_list_surfaces_due_active_metadata_as_expired(self):
        today = dt.datetime.now(dt.timezone.utc).date().isoformat()
        client = {
            "name": "due",
            "status": "active",
            "expires": today,
            "address": "10.77.42.2/32",
            "public_key": key(2),
            "management": "managed",
        }
        output = io.StringIO()
        with (
            mock.patch.object(awgctl, "load_config", return_value={"interface": "awg0"}),
            mock.patch.object(awgctl, "load_clients", return_value=[client]),
            mock.patch.object(awgctl, "is_service_active", return_value=False),
            mock.patch.object(awgctl.sys, "stdout", output),
        ):
            result = awgctl.cmd_client_list(argparse.Namespace(json=True))

        self.assertEqual(result, 0)
        self.assertEqual(json.loads(output.getvalue())["data"]["clients"][0]["status"], "expired")

    def test_cli_parser_supports_requested_simple_grammar(self):
        parser = awgctl.build_parser()
        self.assertEqual(parser.parse_args(["client", "add", "kat-iphone"]).client_name, "kat-iphone")
        self.assertIsNone(parser.parse_args(["client", "add"]).client_name)
        export = parser.parse_args(["client", "export", "kat", "--output", "/tmp/kat.conf"])
        self.assertEqual(export.output, pathlib.Path("/tmp/kat.conf"))
        qr = parser.parse_args(["client", "qr", "kat", "--output", "/secure/kat.png"])
        self.assertEqual(qr.output, pathlib.Path("/secure/kat.png"))
        self.assertEqual(parser.parse_args(["config", "set", "listen-port", "55323"]).key, "listen-port")
        self.assertEqual(parser.parse_args(["aws-rule"]).command, "aws-rule")

    def test_cli_parser_exposes_public_expiry_wrapper_and_internal_entrypoint(self):
        public = awgctl.build_parser().parse_args(["client", "expire", "--dry-run", "--json"])
        internal = awgctl.build_parser(entrypoint="internal").parse_args(
            ["_expire-clients", "--dry-run", "--json"]
        )

        self.assertEqual(public.client_command, "expire")
        self.assertTrue(public.dry_run)
        self.assertEqual(internal.command, "_expire-clients")

    def test_operator_secret_copy_is_owned_by_invoker_and_rejects_writable_parent(self):
        invoker = pwd.getpwuid(os.getuid()).pw_name
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            safe = root / "safe"
            safe.mkdir(mode=0o700)
            with mock.patch.dict(os.environ, {"SUDO_USER": invoker}):
                output = awgctl.write_operator_secret(safe / "kat.conf", b"secret\n")
            self.assertEqual(output.read_bytes(), b"secret\n")
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertEqual(output.stat().st_uid, os.getuid())

            unsafe = root / "unsafe"
            unsafe.mkdir(mode=0o777)
            unsafe.chmod(0o777)
            with mock.patch.dict(os.environ, {"SUDO_USER": invoker}):
                with self.assertRaisesRegex(awgctl.AwgctlError, "writable"):
                    awgctl.write_operator_secret(unsafe / "kat.conf", b"secret\n")

    def test_handshake_age_never_claims_contact_for_zero(self):
        self.assertEqual(awgctl.format_age(0, now=2_000_000_000), "never")
        self.assertEqual(awgctl.format_age(1_999_999_982, now=2_000_000_000), "18s ago")
        self.assertEqual(awgctl.format_age(1_999_992_800, now=2_000_000_000), "2h ago")

    def test_wildcard_listener_detection_flags_prometheus_and_ignores_loopback(self):
        sample = (
            'tcp LISTEN 0 4096 *:9100 *:* users:(("prometheus-node",pid=613,fd=3))\n'
            'tcp LISTEN 0 4096 127.0.0.1:9121 0.0.0.0:* users:(("docker-proxy",pid=1,fd=1))\n'
            'udp UNCONN 0 0 0.0.0.0:55323 0.0.0.0:*\n'
        )
        listeners = awgctl.suspicious_wildcard_listeners(sample, vpn_port=55323)
        self.assertEqual(len(listeners), 1)
        self.assertIn("9100", listeners[0])
        self.assertIn("prometheus-node", listeners[0])

    def test_listener_detection_accepts_normalized_managed_awg0_ipv4(self):
        sample = (
            'tcp LISTEN 0 4096 10.77.42.1:9090 0.0.0.0:* users:(("prometheus",pid=2,fd=3))\n'
            'tcp LISTEN 0 4096 127.0.0.1:9121 0.0.0.0:* users:(("local",pid=3,fd=4))\n'
        )
        listeners = awgctl.suspicious_wildcard_listeners(
            sample,
            vpn_port=55323,
            vpn_addresses=("10.77.42.1/24",),
        )

        self.assertEqual(len(listeners), 1)
        self.assertIn("tcp/9090", listeners[0])
        self.assertNotIn("9121", " ".join(listeners))

    def test_legacy_extraction_preserves_classic_parameters_and_psk(self):
        server = (
            "[Interface]\nAddress = 10.77.42.1/24\nListenPort = 55323\n"
            f"PrivateKey = {key(1)}\nMTU = 1280\n"
            "Jc = 12\nJmin = 56\nJmax = 852\nS1 = 149\nS2 = 149\n"
            "H1 = 1603259132\nH2 = 1601077912\nH3 = 738660798\nH4 = 1722938668\n\n"
            f"[Peer]\nPublicKey = {key(2)}\nPresharedKey = {key(3)}\nAllowedIPs = 10.77.42.2/32\n"
        )
        client = (
            f"[Interface]\nPrivateKey = {key(4)}\nAddress = 10.77.42.2/32\n"
            "DNS = 1.1.1.1, 1.0.0.1\nMTU = 1280\n"
            "Jc = 12\nJmin = 56\nJmax = 852\nS1 = 149\nS2 = 149\n"
            "H1 = 1603259132\nH2 = 1601077912\nH3 = 738660798\nH4 = 1722938668\n\n"
            f"[Peer]\nPublicKey = {key(5)}\nPresharedKey = {key(3)}\n"
            "Endpoint = staging.honeywire.ai:55323\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n"
        )
        imported = awgctl.extract_legacy_state(server, client, "ens5")
        self.assertEqual(imported["config"]["obfuscation"], self_config_obfuscation())
        self.assertEqual(imported["config"]["endpoint"], "staging.honeywire.ai")
        self.assertEqual(imported["config"]["dns"], ["1.1.1.1", "1.0.0.1"])
        self.assertEqual(imported["client_psk"], key(3))


def self_config_obfuscation():
    return {
        "Jc": 12,
        "Jmin": 56,
        "Jmax": 852,
        "S1": 149,
        "S2": 149,
        "H1": 1603259132,
        "H2": 1601077912,
        "H3": 738660798,
        "H4": 1722938668,
    }


if __name__ == "__main__":
    unittest.main(verbosity=2)
