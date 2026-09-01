#!/usr/bin/env python3
import base64
import ipaddress
import pathlib
import sys
import tempfile
import unittest


BUILD_ROOT = pathlib.Path(__file__).parents[1]
sys.path.insert(0, str(BUILD_ROOT / "src"))

from awgctl import core as awgctl


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
            "PostUp = /opt/amneziawg/bin/awgctl _firewall up\n"
            "PostDown = /opt/amneziawg/bin/awgctl _firewall down\n\n"
            "[Peer]\n# kat\n"
            f"PublicKey = {key(2)}\nPresharedKey = {key(3)}\n"
            "AllowedIPs = 10.77.42.2/32\n"
        )
        self.assertEqual(rendered, expected)
        self.assertNotIn("SaveConfig", rendered)

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
    def test_cli_parser_supports_requested_simple_grammar(self):
        parser = awgctl.build_parser()
        self.assertEqual(parser.parse_args(["client", "add", "kat-iphone"]).client_name, "kat-iphone")
        export = parser.parse_args(["client", "export", "kat", "--output", "/tmp/kat.conf"])
        self.assertEqual(export.output, pathlib.Path("/tmp/kat.conf"))
        self.assertEqual(parser.parse_args(["config", "set", "listen-port", "55323"]).key, "listen-port")
        self.assertEqual(parser.parse_args(["aws-rule"]).command, "aws-rule")

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
