import base64
import pathlib
import random
import sys
import unittest


REPO_ROOT = pathlib.Path(__file__).parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))


class EntrypointBoundaryTests(unittest.TestCase):
    def test_only_exact_legacy_public_lifecycle_hooks_are_migration_compatible(self):
        from awgctl import core

        expected = (
            "PostUp = /opt/amneziawg/libexec/awgctl-internal _firewall up\n"
            "PostDown = /opt/amneziawg/libexec/awgctl-internal _firewall down\n"
        ).encode()
        legacy = (
            "PostUp = /opt/amneziawg/bin/awgctl _firewall up\n"
            "PostDown = /opt/amneziawg/bin/awgctl _firewall down\n"
        ).encode()
        self.assertTrue(core.legacy_lifecycle_hook_drift(expected, legacy))
        self.assertFalse(core.legacy_lifecycle_hook_drift(expected, legacy + b"# manual\n"))

    def test_public_parser_hides_initialization_and_migration_commands(self):
        from awgctl import core

        parser = core.build_parser(entrypoint="public")

        with self.assertRaises(SystemExit):
            parser.parse_args(["_initialize-fresh", "--endpoint", "vpn.example.com", "--external-interface", "ens5"])
        with self.assertRaises(SystemExit):
            parser.parse_args(["_migrate-existing"])
        compatibility = parser.parse_args(["_firewall", "up"])
        self.assertEqual(compatibility.command, "_firewall")

    def test_internal_parser_accepts_only_internal_workflows(self):
        from awgctl import core

        parser = core.build_parser(entrypoint="internal")
        firewall = parser.parse_args(["_firewall", "down"])
        fresh = parser.parse_args(["_initialize-fresh", "--endpoint", "vpn.example.com", "--external-interface", "ens5"])

        self.assertEqual(firewall.firewall_action, "down")
        self.assertEqual(fresh.command, "_initialize-fresh")
        with self.assertRaises(SystemExit):
            parser.parse_args(["client", "list"])

    def test_server_hooks_use_root_only_internal_entrypoint(self):
        from awgctl import core

        config = core.build_fresh_server_config(
            endpoint="vpn.example.com",
            subnet="10.77.42.0/24",
            listen_port=55323,
            external_interface="ens5",
            dns="1.1.1.2,1.0.0.2",
            mtu=1280,
            keepalive=25,
            obfuscation=core.generate_classic_obfuscation(random.Random(8)),
        )
        private_key = base64.b64encode(b"x" * 32).decode("ascii")
        rendered = core.render_server_config(config, private_key, [])

        self.assertIn("PostUp = /opt/amneziawg/libexec/awgctl-internal _firewall up", rendered)
        self.assertIn("PostDown = /opt/amneziawg/libexec/awgctl-internal _firewall down", rendered)
        self.assertNotIn("/opt/amneziawg/bin/awgctl _firewall", rendered)


class SystemdSandboxTests(unittest.TestCase):
    def test_conservative_sandbox_keeps_network_admin_but_blocks_unrelated_host_access(self):
        from awginstall.sandbox import render_service_hardening

        rendered = render_service_hardening("conservative")

        for directive in (
            "NoNewPrivileges=yes",
            "ProtectSystem=strict",
            "ReadWritePaths=/opt/amneziawg/generated /run/lock",
            "ProtectHome=yes",
            "PrivateDevices=yes",
            "ProtectKernelModules=yes",
            "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK",
        ):
            self.assertIn(directive, rendered)
        self.assertNotIn("CapabilityBoundingSet=", rendered)
        self.assertNotIn("ProtectKernelTunables=yes", rendered)

    def test_hardening_can_be_explicitly_disabled(self):
        from awginstall.sandbox import render_service_hardening

        self.assertEqual(render_service_hardening("off"), "")

    def test_module_load_configuration_is_narrow(self):
        from awginstall.sandbox import render_module_load

        self.assertEqual(render_module_load(), "# Managed by AmneziaWG Manager\namneziawg\n")


if __name__ == "__main__":
    unittest.main(verbosity=2)
