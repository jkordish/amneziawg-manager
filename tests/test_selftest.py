import pathlib
import sys
import unittest


REPO_ROOT = pathlib.Path(__file__).parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from awgctl.selftest import render_peer_configs


class NamespaceSelfTestTests(unittest.TestCase):
    def test_ephemeral_peer_configs_use_classic_fields_and_no_new_i_fields(self):
        key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        public = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
        psk = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC="
        obfuscation = {
            "Jc": 6, "Jmin": 8, "Jmax": 80, "S1": 25, "S2": 75,
            "H1": 101, "H2": 102, "H3": 103, "H4": 104,
        }
        server, client = render_peer_configs(
            server_private=key,
            server_public=public,
            client_private=key,
            client_public=public,
            psk=psk,
            obfuscation=obfuscation,
            port=51871,
        )
        for text in (server, client):
            self.assertTrue(text.startswith("[Interface]\n"))
            self.assertIn("Jc = 6", text)
            self.assertNotRegex(text, r"(?m)^I[1-5]\s*=")
        self.assertIn("Endpoint = 192.0.2.1:51871", client)
        self.assertIn("AllowedIPs = 10.200.0.2/32", server)


if __name__ == "__main__":
    unittest.main(verbosity=2)
