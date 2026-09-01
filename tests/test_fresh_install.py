import ipaddress
import pathlib
import random
import sys
import unittest


REPO_ROOT = pathlib.Path(__file__).parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from awgctl import core


class FreshConfigurationTests(unittest.TestCase):
    def test_classic_headers_keep_independent_csprng_assignment_order(self):
        class ScriptedRandom:
            def __init__(self):
                self.values = iter((30, 40, 900, 100, 700, 300, 8))

            def randint(self, lower, upper):
                value = next(self.values)
                self.assert_in_range(value, lower, upper)
                return value

            @staticmethod
            def assert_in_range(value, lower, upper):
                if not lower <= value <= upper:
                    raise AssertionError(f"{value} is outside {lower}..{upper}")

        generated = core.generate_classic_obfuscation(ScriptedRandom())

        self.assertEqual(
            [generated[name] for name in ("H1", "H2", "H3", "H4")],
            [900, 100, 700, 300],
        )

    def test_cloudflare_malware_alias_resolves_to_filtered_ipv4_service(self):
        self.assertEqual(core.parse_dns_value("cloudflare-malware"), ["1.1.1.2", "1.0.0.2"])

    def test_custom_dns_addresses_remain_supported(self):
        self.assertEqual(core.parse_dns_value("9.9.9.9,149.112.112.112"), ["9.9.9.9", "149.112.112.112"])

    def test_fresh_configuration_is_classic_validated_and_contains_no_keys(self):
        obfuscation = core.generate_classic_obfuscation(random.Random(7))
        config = core.build_fresh_server_config(
            endpoint="vpn.example.com",
            subnet="10.77.42.0/24",
            listen_port=55323,
            external_interface="ens5",
            dns="1.1.1.1,1.0.0.1",
            mtu=1280,
            keepalive=25,
            obfuscation=obfuscation,
        )
        self.assertEqual(config["server_address"], "10.77.42.1/24")
        self.assertEqual(set(config["obfuscation"]), set(core.OBFUSCATION_FIELDS))
        self.assertNotIn("PrivateKey", repr(config))
        self.assertLessEqual(config["obfuscation"]["Jmin"], config["obfuscation"]["Jmax"])
        self.assertEqual(len({config["obfuscation"][name] for name in ("H1", "H2", "H3", "H4")}), 4)
        self.assertTrue(ipaddress.ip_interface(config["server_address"]).ip in ipaddress.ip_network(config["subnet"]))

    def test_fresh_configuration_accepts_named_dns_policy(self):
        config = core.build_fresh_server_config(
            endpoint="vpn.example.com",
            subnet="10.77.42.0/24",
            listen_port=55323,
            external_interface="ens5",
            dns="cloudflare-malware",
            mtu=1280,
            keepalive=25,
            obfuscation=core.generate_classic_obfuscation(random.Random(7)),
        )
        self.assertEqual(config["dns"], ["1.1.1.2", "1.0.0.2"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
