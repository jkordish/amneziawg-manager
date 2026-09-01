"""Repository-only acceptance checks for the AWG 3.1 release boundary."""

from __future__ import annotations

import argparse
import base64
import contextlib
import datetime as dt
import io
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


REPO_ROOT = pathlib.Path(__file__).parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from awgctl import core
from awginstall import cli as install_cli


TRANSACTION_ID = "0123456789abcdef0123456789abcdef"


def key(byte: int) -> str:
    return base64.b64encode(bytes([byte]) * 32).decode("ascii")


def schema_one_classic() -> dict[str, object]:
    return {
        "schema_version": 1,
        "interface": "awg0",
        "subnet": "10.77.42.0/24",
        "server_address": "10.77.42.1/24",
        "endpoint": "vpn.example.com",
        "listen_port": 55323,
        "external_interface": "ens5",
        "dns": ["1.1.1.2", "1.0.0.2"],
        "mtu": 1280,
        "keepalive": 25,
        "use_psk": True,
        "obfuscation": {
            "Jc": 8,
            "Jmin": 8,
            "Jmax": 80,
            "S1": 31,
            "S2": 92,
            "H1": 101,
            "H2": 102,
            "H3": 103,
            "H4": 104,
        },
        "blocked_forward_ipv4": list(core.BLOCKED_FORWARD_IPV4),
        "paths": {
            "runtime_config": str(core.RUNTIME_CONFIG),
            "generated_config": str(core.GENERATED_CONFIG),
            "server_private_key": str(core.SERVER_PRIVATE),
            "server_public_key": str(core.SERVER_PUBLIC),
            "clients": str(core.CLIENTS),
            "client_keys": str(core.CLIENT_KEYS),
            "revoked": str(core.REVOKED),
            "backups": str(core.BACKUPS),
        },
    }


def managed_kat() -> dict[str, object]:
    return {
        "schema_version": 3,
        "name": "kat-iphone",
        "status": "active",
        "management": "managed",
        "address": "10.77.42.2/32",
        "public_key": key(3),
        "public_key_fingerprint": core.fingerprint(key(3)),
        "use_psk": True,
        "created_at": "2026-09-01T09:00:00Z",
        "updated_at": "2026-09-01T09:00:00Z",
        "owner": "Kat",
        "device": "iPhone",
        "expires": None,
        "profile_revision": 3,
        "profile_generated_at": "2026-09-01T09:00:00Z",
        "profile_change_reason": "created",
        "distribution_status": "distributed",
        "distributed_at": "2026-09-01T09:00:00Z",
    }


class RepositoryDryRunAcceptanceTests(unittest.TestCase):
    def test_fresh_classic_dry_run_and_schema_one_normalization_remain_compatible(self):
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory) / "opt/amneziawg"
            with (
                mock.patch.object(
                    install_cli,
                    "validate_platform",
                    return_value={"version": "24.04", "architecture": "amd64"},
                ),
                mock.patch.object(
                    install_cli,
                    "_run",
                    side_effect=AssertionError("fresh dry run must not run host commands"),
                ),
            ):
                result = install_cli.main(
                    [
                        "install",
                        "--dry-run",
                        "--json",
                        "--endpoint",
                        "vpn.example.com",
                        "--external-interface",
                        "ens5",
                        "--ingress-boundary",
                        "lightsail",
                    ],
                    root=root,
                    repo_root=REPO_ROOT,
                    output=output,
                )

            self.assertEqual(result, 0)
            self.assertFalse(root.exists())
            payload = json.loads(output.getvalue())
            self.assertTrue(payload["dry_run"])
            self.assertEqual(payload["settings"]["network"]["ingress_boundary"], "lightsail")

        legacy = schema_one_classic()
        normalized = core.normalize_server_config(legacy)
        self.assertEqual(normalized["schema_version"], 2)
        self.assertEqual(normalized["obfuscation"]["mode"], "classic")
        self.assertEqual(
            normalized["obfuscation"]["profile"]["parameters"],
            legacy["obfuscation"],
        )
        self.assertEqual(legacy["schema_version"], 1)

    def test_awg31_prepare_dry_run_is_nonmutating_secret_free_and_qualified(self):
        config = core.normalize_server_config(schema_one_classic())
        args = core.build_parser().parse_args(
            [
                "obfuscation",
                "prepare",
                "--mode",
                "awg31",
                "--profile",
                "russia-ios-v1",
                "--client",
                "kat-iphone",
                "--dry-run",
                "--json",
            ]
        )
        output = io.StringIO()
        capability = {
            "policy_version": core.AWG31_QUALIFICATION_POLICY_VERSION,
            "tools_version": "qualified-test-tools",
            "module_version": "qualified-test-module",
        }
        with (
            mock.patch.object(core, "load_transition_document", return_value=None),
            mock.patch.object(core, "load_config", return_value=config),
            mock.patch.object(core, "load_clients", return_value=[managed_kat()]),
            mock.patch.object(core, "ingress_boundary_attestation", return_value="lightsail"),
            mock.patch.object(core, "require_awg31_capability", return_value=capability),
            mock.patch.object(
                core,
                "mutation_lock",
                side_effect=AssertionError("prepare dry run must not acquire the mutation lock"),
            ),
            mock.patch.object(
                core,
                "create_backup",
                side_effect=AssertionError("prepare dry run must not create a backup"),
            ),
            mock.patch.object(
                core,
                "atomic_write",
                side_effect=AssertionError("prepare dry run must not write files"),
            ),
            mock.patch.object(
                core,
                "run",
                side_effect=AssertionError("prepare dry run must not invoke systemd or nft"),
            ),
            mock.patch.object(
                core,
                "apply_firewall",
                side_effect=AssertionError("prepare dry run must not mutate nftables"),
            ),
            mock.patch.object(core, "require_root"),
            contextlib.redirect_stdout(output),
        ):
            result = core.dispatch(args)

        self.assertEqual(result, 0)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["data"]["runtime_action"], "none")
        self.assertEqual(payload["data"]["required_ingress"]["port"], "selected-at-execution")
        self.assertNotIn("private", output.getvalue().lower())
        self.assertNotIn(key(3), output.getvalue())
        self.assertEqual(
            core.AWG31_QUALIFIED_PAIRS_V1,
            frozenset({("3.1.20260812", "3.1.20260812")}),
        )

    def test_activation_failure_invokes_synchronous_classic_rollback(self):
        document = {
            "transaction_id": TRANSACTION_ID,
            "state": "prepared",
            "backup_name": "20260901T090000Z",
            "prestate_sha256": "ab" * 32,
            "ingress_boundary": "lightsail",
            "capability": {
                "policy_version": core.AWG31_QUALIFICATION_POLICY_VERSION,
                "tools_version": "qualified-test-tools",
                "module_version": "qualified-test-module",
            },
            "new_port": 4242,
            "client_name": "kat-iphone",
        }
        config = core.normalize_server_config(schema_one_classic())
        client = managed_kat()
        reservation = mock.Mock()
        restore = mock.Mock()
        complete = mock.Mock()
        patches = (
            mock.patch.object(core, "mutation_lock", return_value=contextlib.nullcontext()),
            mock.patch.object(core, "load_transition_document", return_value=document),
            mock.patch.object(core, "load_config", return_value=config),
            mock.patch.object(core, "ensure_no_drift"),
            mock.patch.object(core, "verify_transition_backup_precondition"),
            mock.patch.object(core, "managed_transition_prestate_digest", return_value="ab" * 32),
            mock.patch.object(core, "ingress_boundary_attestation", return_value="lightsail"),
            mock.patch.object(core, "require_awg31_capability", return_value=document["capability"]),
            mock.patch.object(core, "udp_port_is_listening", return_value=False),
            mock.patch.object(core, "is_service_active", return_value=True),
            mock.patch.object(core, "acquire_udp_port_reservation", return_value=reservation),
            mock.patch.object(core, "load_clients", return_value=[client]),
            mock.patch.object(core, "ensure_activation_window"),
            mock.patch.object(core, "validate_pending_transition_artifacts", return_value=mock.Mock()),
            mock.patch.object(core, "verify_pending_snapshot_activation_time"),
            mock.patch.object(
                core,
                "_install_active_transition",
                side_effect=core.AwgctlError("synthetic reload failure"),
            ),
            mock.patch.object(core, "restore_obfuscation_backup", restore),
            mock.patch.object(core, "complete_transition_document", complete),
            mock.patch.object(core, "delete_activation_journal"),
            mock.patch.object(core, "cancel_transition_timeout"),
            mock.patch.object(core, "audit"),
            mock.patch.object(core, "require_root"),
            mock.patch.object(
                core,
                "run",
                side_effect=AssertionError("mocked activation must not invoke systemd"),
            ),
            mock.patch.object(
                core,
                "apply_firewall",
                side_effect=AssertionError("mocked activation must not mutate nftables"),
            ),
        )
        with contextlib.ExitStack() as stack:
            for patcher in patches:
                stack.enter_context(patcher)
            with self.assertRaisesRegex(core.AwgctlError, "classic state restored"):
                core.dispatch(
                    core.build_parser().parse_args(
                        [
                            "obfuscation",
                            "activate",
                            TRANSACTION_ID,
                            "--ingress-ready",
                            "--timeout",
                            "10m",
                            "--json",
                        ]
                    )
                )

        restore.assert_called_once()
        complete.assert_called_once()
        self.assertGreaterEqual(reservation.release.call_count, 1)

    def test_timeout_rollback_uses_exact_internal_entrypoint_and_deadline(self):
        deadline = "2026-09-01T10:11:00Z"
        epoch = int(
            dt.datetime(2026, 9, 1, 10, 11, tzinfo=dt.timezone.utc).timestamp()
        )

        def run_systemd(argv, **kwargs):
            if argv[:3] == ["systemctl", "show", "--no-pager"]:
                return subprocess.CompletedProcess(
                    argv,
                    0,
                    (
                        "ActiveState=active\nUnitFileState=enabled\n"
                        f"NextElapseUSecRealtime=@{epoch}\n"
                    ).encode(),
                    b"",
                )
            return subprocess.CompletedProcess(argv, 0, b"", b"")

        with tempfile.TemporaryDirectory() as directory:
            unit_dir = pathlib.Path(directory) / "systemd"
            with (
                mock.patch.object(core, "run", side_effect=run_systemd) as runner,
                mock.patch.object(core, "SYSTEMD_UNIT_DIR", unit_dir),
                mock.patch.object(
                    core,
                    "INTERNAL_ENTRYPOINT",
                    pathlib.Path("/opt/amneziawg/libexec/awgctl-internal"),
                ),
                mock.patch.object(
                    core,
                    "_systemd_unit_is_root_owned",
                    return_value=True,
                ),
            ):
                core.schedule_transition_timeout(
                    TRANSACTION_ID,
                    "10m",
                    deadline_at=deadline,
                )

            base = f"awgctl-obfuscation-rollback-{TRANSACTION_ID}"
            service = (unit_dir / f"{base}.service").read_text()
            timer = (unit_dir / f"{base}.timer").read_text()
            self.assertIn(
                f"_obfuscation-timeout {TRANSACTION_ID} --origin final",
                service,
            )
            self.assertIn("OnCalendar=2026-09-01 10:11:00 UTC", timer)
            self.assertIn("Persistent=true", timer)
            self.assertIn("StartLimitIntervalSec=0", service)
            self.assertIn("Restart=on-failure", service)
            self.assertIn("RestartSec=5s", service)
            commands = [call.args[0] for call in runner.call_args_list]
            self.assertIn(["systemctl", "enable", f"{base}.timer"], commands)
            self.assertIn(["systemctl", "restart", f"{base}.timer"], commands)
            self.assertFalse(any(command[0] == "systemd-run" for command in commands))

    def test_confirmation_rejects_a_fresh_handshake_without_transfer_data(self):
        now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        document = {
            "transaction_id": TRANSACTION_ID,
            "state": "active",
            "activated_at": (now - dt.timedelta(minutes=1)).isoformat(),
            "deadline_at": (now + dt.timedelta(minutes=5)).isoformat(),
            "profile_name": "russia-ios-v1",
            "new_port": 4242,
            "client_name": "kat-iphone",
            "pre_handshake": 0,
            "pre_rx": 100,
            "pre_tx": 200,
            "pending": {"profiles": [{"name": "kat-iphone", "current_revision": 3}]},
        }
        config = core.normalize_server_config(schema_one_classic())
        config["listen_port"] = 4242
        config["obfuscation"] = core.build_russia_ios_obfuscation(
            core.HEADER_PROTECTION_KEY,
            random_source=mock.Mock(
                randint=mock.Mock(side_effect=[9, 30, 100, 40, 20])
            ),
            token_bytes=lambda count: b"\xa5" * count,
            mtu=1280,
        )
        client = managed_kat()
        snapshot = mock.Mock(server_config=b"redacted server config")
        with (
            mock.patch.object(core, "mutation_lock", return_value=contextlib.nullcontext()),
            mock.patch.object(core, "load_transition_document", return_value=document),
            mock.patch.object(core, "load_transition_outcome", return_value=None),
            mock.patch.object(core, "load_config", return_value=config),
            mock.patch.object(core, "load_clients", return_value=[client]),
            mock.patch.object(core, "_prepare_transition_clients", return_value=(client, [client])),
            mock.patch.object(core, "is_service_active", return_value=True),
            mock.patch.object(core, "validate_pending_transition_artifacts", return_value=snapshot),
            mock.patch.object(core, "verify_active_transition_postcondition"),
            mock.patch.object(core, "handshake_map", return_value={key(3): int(now.timestamp())}),
            mock.patch.object(core, "transfer_map", return_value={}),
            mock.patch.object(core, "require_root"),
            mock.patch.object(
                core,
                "run",
                side_effect=AssertionError("failed confirmation must not invoke systemd"),
            ),
            mock.patch.object(
                core,
                "apply_firewall",
                side_effect=AssertionError("failed confirmation must not mutate nftables"),
            ),
        ):
            with self.assertRaisesRegex(core.AwgctlError, "transfer counters"):
                core.dispatch(
                    core.build_parser().parse_args(
                        ["obfuscation", "confirm", TRANSACTION_ID, "--json"]
                    )
                )

    def test_status_diagnostics_and_json_never_expose_awg31_material(self):
        raw_public = key(3)
        raw_header = key(9)
        raw_cps = "<b 0xdeadbeef><r 24>"
        diagnostic = core.redact_diagnostic_text(
            "PrivateKey = "
            + key(1)
            + "\nPublicKey = "
            + raw_public
            + "\nPresharedKey = "
            + key(5)
            + "\nHeaderProtectionKey = "
            + raw_header
            + "\nI1 = \""
            + raw_cps
            + "\"\n"
        )
        for secret in (key(1), raw_public, key(5), raw_header, raw_cps):
            self.assertNotIn(secret, diagnostic)

        config = core.normalize_server_config(schema_one_classic())
        client = {**managed_kat(), "public_key": raw_public}
        safe_obfuscation = {
            "mode": "awg31",
            "profile": "russia-ios-v1",
            "header_protection_key_fingerprint": "123456789abc",
        }
        safe_summary = {
            "mode": "awg31",
            "profile": "russia-ios-v1",
            "profile_revisions": {"kat-iphone": 3},
            "server_client_consistency": True,
            "transition": {
                "client": "kat-iphone",
                "deadline_at": None,
                "state": "prepared",
                "transaction_id": TRANSACTION_ID,
            },
            "versions": {
                "policy_version": 1,
                "tools_version": "unqualified-test-tools",
                "module_version": "unqualified-test-module",
            },
        }
        output = io.StringIO()
        completed = subprocess.CompletedProcess(["ip"], 1, b"", b"")
        with (
            mock.patch.object(core, "load_config", return_value=config),
            mock.patch.object(core, "obfuscation_status", return_value=safe_obfuscation),
            mock.patch.object(core, "_obfuscation_summary_locked", return_value=safe_summary),
            mock.patch.object(core, "ingress_boundary_attestation", return_value="lightsail"),
            mock.patch.object(core, "systemctl_state", return_value=(False, True)),
            mock.patch.object(core, "run", return_value=completed),
            mock.patch.object(core, "imds_value", return_value="203.0.113.7"),
            mock.patch.object(core, "load_clients", return_value=[client]),
            mock.patch.object(core, "nft_table_active", return_value=True),
            mock.patch.object(pathlib.Path, "read_text", return_value="1"),
            mock.patch.object(core, "mutation_lock", return_value=contextlib.nullcontext()),
            mock.patch.object(core, "require_root"),
            mock.patch.object(
                core,
                "apply_firewall",
                side_effect=AssertionError("status must not mutate nftables"),
            ),
            contextlib.redirect_stdout(output),
        ):
            self.assertEqual(
                core.dispatch(core.build_parser().parse_args(["status", "--json"])),
                0,
            )

        payload = json.loads(output.getvalue())
        self.assertEqual(payload["data"]["mode"], "awg31")
        self.assertEqual(
            payload["data"]["obfuscation"]["header_protection_key_fingerprint"],
            "123456789abc",
        )
        serialized = output.getvalue()
        for secret in (raw_public, raw_header, raw_cps):
            self.assertNotIn(secret, serialized)


if __name__ == "__main__":
    unittest.main(verbosity=2)
