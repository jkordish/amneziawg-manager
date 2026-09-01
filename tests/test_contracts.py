import pathlib
import argparse
import datetime as dt
import io
import json
import sys
import tempfile
import unittest
from contextlib import nullcontext, redirect_stderr, redirect_stdout
from unittest import mock


REPO_ROOT = pathlib.Path(__file__).parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from awgctl import core
from awgctl.contracts import (
    ContractError,
    health_envelope,
    json_envelope,
    mark_profile_regenerated,
    mark_profile_rotated,
    normalize_client_metadata,
)


class JsonContractTests(unittest.TestCase):
    def test_client_expiry_health_check_names_due_clients_as_expired(self):
        today = dt.datetime.now(dt.timezone.utc).date().isoformat()
        check = core.client_expiry_health_check(
            [
                {"name": "due", "status": "active", "expires": today},
                {"name": "future", "status": "active", "expires": "2099-01-01"},
            ]
        )

        self.assertEqual(check, ("PASS", "client expiry", "expired: due"))

    def test_client_expiry_health_fails_when_terminal_peer_remains_live(self):
        with mock.patch.object(core, "live_peers", return_value={"expired-public"}):
            check = core.client_expiry_health_check(
                [
                    {
                        "name": "terminal",
                        "status": "expired",
                        "expires": "2025-01-01",
                        "public_key": "expired-public",
                    }
                ],
                interface="awg0",
                interface_active=True,
            )

        self.assertEqual(
            check,
            ("FAIL", "client expiry", "expired peers still active: terminal"),
        )

    def test_terminal_expired_status_cannot_be_resurrected_by_clock_rollback(self):
        status = core.effective_client_status(
            {"status": "expired", "expires": "2026-09-01"},
            now=dt.datetime(2026, 8, 1, tzinfo=dt.timezone.utc),
        )

        self.assertEqual(status, "expired")

    def test_expiry_boundary_changes_exactly_at_utc_midnight(self):
        client = {"status": "active", "expires": "2030-01-01"}
        boundary = dt.datetime(2030, 1, 1, tzinfo=dt.timezone.utc)

        self.assertEqual(
            core.effective_client_status(client, now=boundary - dt.timedelta(microseconds=1)),
            "active",
        )
        self.assertEqual(core.effective_client_status(client, now=boundary), "expired")

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
            "expires": dt.datetime.now(dt.timezone.utc).date().isoformat(),
            "management": "managed",
        }
        output = io.StringIO()
        with (
            mock.patch.object(
                core, "mutation_lock", return_value=nullcontext()
            ),
            mock.patch.object(core, "load_config", return_value=config),
            mock.patch.object(
                core,
                "obfuscation_status",
                return_value={"mode": "classic", "profile": "classic-v1"},
            ),
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
        self.assertEqual(payload["data"]["clients"][0]["status"], "expired")
        self.assertNotIn("RAW_PUBLIC_KEY", output.getvalue())

    def test_ingress_rule_json_names_attested_external_boundary_without_lightsail_claim(self):
        from awginstall.settings import resolve_installation_settings

        settings = resolve_installation_settings(
            sudo_user=None,
            overrides={"ingress_boundary": "equivalent-external-firewall"},
        )
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            installation = pathlib.Path(directory) / "installation.json"
            installation.write_text(json.dumps(settings.to_dict()), encoding="utf-8")
            with (
                mock.patch.object(core, "INSTALLATION_CONFIG", installation),
                redirect_stdout(output),
            ):
                core.cmd_aws_rule({"listen_port": 55323}, as_json=True)

        payload = json.loads(output.getvalue())
        self.assertEqual(
            payload["data"].get("ingress_boundary"),
            "equivalent-external-firewall",
        )
        self.assertNotIn("lightsail", output.getvalue().lower())

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

    def test_management_health_fails_missing_ingress_attestation_with_configure_path(self):
        from awginstall.settings import resolve_installation_settings

        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            installation = root / "installation.json"
            installation.write_text(
                json.dumps(resolve_installation_settings(sudo_user=None).to_dict()),
                encoding="utf-8",
            )
            with (
                mock.patch.object(core, "INSTALLATION_CONFIG", installation),
                mock.patch.object(core, "SUDOERS_CONFIG", root / "sudoers"),
                mock.patch.object(core, "SERVICE_HARDENING", root / "hardening"),
                mock.patch.object(core, "MODULE_LOAD_CONFIG", root / "modules"),
                mock.patch.object(core, "PUBLIC_ENTRYPOINT", root / "public"),
                mock.patch.object(core, "INTERNAL_ENTRYPOINT", root / "internal"),
                mock.patch.object(core, "permission_problem", return_value=None),
                mock.patch.object(
                    core,
                    "run",
                    return_value=mock.Mock(returncode=4, stdout=b"", stderr=b""),
                ),
            ):
                checks = core.management_security_checks()

        self.assertIn(
            (
                "FAIL",
                "ingress boundary attestation",
                "missing; run install.py configure --ingress-boundary VALUE --yes",
            ),
            checks,
        )

    def test_expiry_host_health_accepts_only_exact_units_and_enabled_active_timer(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            product_root = root / "opt/amneziawg"
            service = root / "etc/systemd/system/amneziawg-client-expiry.service"
            timer = root / "etc/systemd/system/amneziawg-client-expiry.timer"
            service.parent.mkdir(parents=True)
            service.write_text(
                "# Managed by AmneziaWG Manager\n"
                "[Unit]\n"
                "Description=Expire due AmneziaWG clients\n"
                "After=awg-quick@awg0.service\n\n"
                "[Service]\n"
                "Type=oneshot\n"
                f"ExecStart={product_root / 'libexec/awgctl-internal'} _expire-clients\n"
                "User=root\n"
                "Group=root\n"
                "UMask=0077\n"
            )
            timer.write_text(
                "# Managed by AmneziaWG Manager\n"
                "[Unit]\n"
                "Description=Run AmneziaWG client expiry daily\n\n"
                "[Timer]\n"
                "OnCalendar=*-*-* 00:00:00 UTC\n"
                "Persistent=true\n"
                "Unit=amneziawg-client-expiry.service\n\n"
                "[Install]\n"
                "WantedBy=timers.target\n"
            )
            commands = []

            def runner(argv, **kwargs):
                commands.append((tuple(argv), kwargs))
                stdout = b"enabled\n" if argv[1] == "is-enabled" else b"active\n"
                return mock.Mock(returncode=0, stdout=stdout, stderr=b"")

            checks = core.expiry_host_asset_checks(
                product_root=product_root,
                service_path=service,
                timer_path=timer,
                permission_checker=lambda _path, _mode: None,
                command_runner=runner,
            )

        self.assertEqual(
            checks,
            [
                ("PASS", "client expiry service unit", "root:root 0644 and canonical content"),
                ("PASS", "client expiry timer unit", "root:root 0644 and canonical content"),
                ("PASS", "client expiry timer enablement", "enabled"),
                ("PASS", "client expiry timer activity", "active"),
            ],
        )
        self.assertEqual(
            commands,
            [
                (("systemctl", "is-enabled", "amneziawg-client-expiry.timer"), {"check": False}),
                (("systemctl", "is-active", "amneziawg-client-expiry.timer"), {"check": False}),
            ],
        )

    def test_expiry_host_health_rejects_missing_stale_or_wrong_mode_units_without_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            product_root = root / "opt/amneziawg"
            service = root / "expiry.service"
            timer = root / "expiry.timer"
            missing_checks = core.expiry_host_asset_checks(
                product_root=product_root,
                service_path=service,
                timer_path=timer,
                permission_checker=lambda path, _mode: f"missing {path}",
                command_runner=lambda _argv, **_kwargs: mock.Mock(
                    returncode=4, stdout=b"", stderr=b""
                ),
            )
            self.assertFalse(service.exists())
            self.assertFalse(timer.exists())

            service.write_text("stale service\n")
            timer.write_text("stale timer\n")
            stale_checks = core.expiry_host_asset_checks(
                product_root=product_root,
                service_path=service,
                timer_path=timer,
                permission_checker=lambda _path, _mode: None,
                command_runner=lambda _argv, **_kwargs: mock.Mock(
                    returncode=0, stdout=b"", stderr=b""
                ),
            )
            wrong_mode_checks = core.expiry_host_asset_checks(
                product_root=product_root,
                service_path=service,
                timer_path=timer,
                permission_checker=lambda path, _mode: (
                    f"{path} mode is 0666, expected 0644" if path == service else None
                ),
                command_runner=lambda _argv, **_kwargs: mock.Mock(
                    returncode=0, stdout=b"", stderr=b""
                ),
            )

        self.assertEqual([check[0] for check in missing_checks[:2]], ["FAIL", "FAIL"])
        self.assertIn("missing", missing_checks[0][2])
        self.assertEqual([check[2] for check in stale_checks[:2]], ["content drift", "content drift"])
        self.assertEqual(wrong_mode_checks[0][0], "FAIL")
        self.assertIn("0666", wrong_mode_checks[0][2])

    def test_expiry_host_health_rejects_disabled_or_inactive_timer(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            product_root = root / "opt/amneziawg"
            service = root / "expiry.service"
            timer = root / "expiry.timer"
            service.write_text("stale but permissions are independently controlled\n")
            timer.write_text("stale but permissions are independently controlled\n")
            def states(enabled_code, active_code):
                def runner(argv, **_kwargs):
                    stdout = (
                        b"enabled\n" if argv[1] == "is-enabled" and enabled_code == 0
                        else b"disabled\n" if argv[1] == "is-enabled"
                        else b"active\n" if active_code == 0
                        else b"inactive\n"
                    )
                    return mock.Mock(
                        returncode=enabled_code if argv[1] == "is-enabled" else active_code,
                        stdout=stdout,
                        stderr=b"",
                    )

                return core.expiry_host_asset_checks(
                    product_root=product_root,
                    service_path=service,
                    timer_path=timer,
                    permission_checker=lambda _path, _mode: None,
                    command_runner=runner,
                )

            disabled = states(1, 0)
            inactive = states(0, 3)

        self.assertEqual(
            disabled[2],
            (
                "FAIL",
                "client expiry timer enablement",
                "expected persistent enabled state; textual state did not match (exit 1)",
            ),
        )
        self.assertEqual(
            inactive[3],
            (
                "FAIL",
                "client expiry timer activity",
                "expected active state; textual state did not match (exit 3)",
            ),
        )

    def test_expiry_host_health_rejects_runtime_enablement_and_malformed_states(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            service = root / "expiry.service"
            timer = root / "expiry.timer"
            service.write_text("stale but state checks remain observable\n")
            timer.write_text("stale but state checks remain observable\n")

            def checks(enabled_stdout, active_stdout=b"active\n"):
                def runner(argv, **_kwargs):
                    stdout = enabled_stdout if argv[1] == "is-enabled" else active_stdout
                    return mock.Mock(returncode=0, stdout=stdout, stderr=b"")

                return core.expiry_host_asset_checks(
                    product_root=root / "opt/amneziawg",
                    service_path=service,
                    timer_path=timer,
                    permission_checker=lambda _path, _mode: None,
                    command_runner=runner,
                )

            runtime = checks(b"enabled-runtime\n")
            alias = checks(b"alias\n")
            malformed = checks(b"enabled\nextra\n")
            malformed_active = checks(b"enabled\n", b"activating\n")

        for result in (runtime, alias, malformed):
            self.assertEqual(result[2][0], "FAIL")
            self.assertEqual(result[2][1], "client expiry timer enablement")
        self.assertEqual(malformed_active[3][0], "FAIL")
        self.assertEqual(malformed_active[3][1], "client expiry timer activity")

    def test_management_health_rejects_primary_gid_operator_member(self):
        from types import SimpleNamespace

        from awginstall.settings import resolve_installation_settings

        settings = resolve_installation_settings(
            sudo_user=None,
            overrides={"operators": ["ubuntu"]},
        )
        with tempfile.TemporaryDirectory() as directory:
            test_root = pathlib.Path(directory)
            installation = test_root / "installation.json"
            installation.write_text(json.dumps(settings.to_dict()), encoding="utf-8")
            installation.chmod(0o600)
            staging_user = SimpleNamespace(
                pw_name="awgctl", pw_uid=450, pw_gid=451,
                pw_dir="/var/lib/amneziawg-manager", pw_shell="/usr/sbin/nologin",
            )
            accounts = [
                staging_user,
                SimpleNamespace(pw_name="ubuntu", pw_uid=1000, pw_gid=1000),
                SimpleNamespace(pw_name="stale-primary", pw_uid=1001, pw_gid=452),
            ]
            groups = {
                "awgctl": SimpleNamespace(gr_name="awgctl", gr_gid=451, gr_mem=[]),
                "awgctl-admin": SimpleNamespace(
                    gr_name="awgctl-admin", gr_gid=452, gr_mem=["ubuntu"]
                ),
            }
            completed = mock.Mock(returncode=0, stdout=b"awgctl L\n", stderr=b"")
            with (
                mock.patch.object(core, "INSTALLATION_CONFIG", installation),
                mock.patch.object(core, "SUDOERS_CONFIG", test_root / "sudoers"),
                mock.patch.object(core, "SERVICE_HARDENING", test_root / "hardening.conf"),
                mock.patch.object(core, "MODULE_LOAD_CONFIG", test_root / "modules.conf"),
                mock.patch.object(core, "PUBLIC_ENTRYPOINT", test_root / "public-awgctl"),
                mock.patch.object(core, "INTERNAL_ENTRYPOINT", test_root / "internal-awgctl"),
                mock.patch.object(core, "permission_problem", return_value=None),
                mock.patch.object(core.pwd, "getpwnam", return_value=staging_user),
                mock.patch.object(core.pwd, "getpwall", return_value=accounts),
                mock.patch.object(core.grp, "getgrnam", side_effect=groups.__getitem__),
                mock.patch.object(core.grp, "getgrall", return_value=list(groups.values())),
                mock.patch.object(core, "run", return_value=completed),
            ):
                checks = core.management_security_checks()

        self.assertIn(
            ("FAIL", "operator group", "undeclared members: stale-primary"),
            checks,
        )

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
                mock.patch.object(core, "header_protection_key_for_config", return_value=None),
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

    def test_profile_rotation_preserves_recipient_metadata_and_increments_revision(self):
        previous = normalize_client_metadata({
            **self.legacy_metadata(),
            "schema_version": 3,
            "management": "managed",
            "owner": "Kat",
            "device": "iPhone",
            "expires": "2027-09-01",
            "profile_revision": 4,
            "profile_generated_at": "2026-09-01T08:00:00Z",
            "profile_change_reason": "config:dns",
            "distribution_status": "distributed",
            "distributed_at": "2026-09-01T09:00:00Z",
        })
        replacement = dict(previous)
        replacement.update({
            "public_key": "replacement-public",
            "public_key_fingerprint": "replacement-fingerprint",
            "owner": None,
            "device": None,
            "expires": None,
            "profile_revision": 1,
            "profile_generated_at": "2026-09-01T10:00:00Z",
            "profile_change_reason": "created",
            "distribution_status": "pending",
            "distributed_at": None,
        })
        rotated = mark_profile_rotated(
            previous,
            replacement,
            timestamp="2026-09-01T10:00:00Z",
        )
        self.assertEqual(rotated["public_key"], "replacement-public")
        self.assertEqual(rotated["profile_revision"], 5)
        self.assertEqual(rotated["profile_change_reason"], "rotated")
        self.assertEqual(rotated["distribution_status"], "pending")
        self.assertIsNone(rotated["distributed_at"])
        self.assertEqual(
            (rotated["owner"], rotated["device"], rotated["expires"]),
            ("Kat", "iPhone", "2027-09-01"),
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
