import contextlib
import dataclasses
import importlib.util
import io
import json
import os
import pathlib
import signal
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


REPO_ROOT = pathlib.Path(__file__).parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

QUALIFICATION_PATH = REPO_ROOT / "tools" / "qualify_awg31_host.py"
SPEC = importlib.util.spec_from_file_location("qualify_awg31_host", QUALIFICATION_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load the AWG 3.1 qualification tool")
qualification = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = qualification
SPEC.loader.exec_module(qualification)


REQUIRED_CHECKS = (
    "version_parsing",
    "native_validation",
    "classic_traffic",
    "classic_recreation",
    "awg31_traffic",
    "awg31_counters",
    "awg31_recreation",
    "classic_rollback",
    "cleanup",
    "production_invariants",
)


class QualificationContractTests(unittest.TestCase):
    def build_valid_receipt(self):
        return qualification.build_receipt(
            source_commit="a" * 40,
            dirty_worktree=False,
            os_version="24.04",
            architecture="amd64",
            kernel="7.0.0-1011-aws",
            versions=qualification.VersionEvidence(
                tools="3.1.20260812",
                loaded_module="3.1.20260812",
                packaged_module="3.1.20260812",
                dkms="3.1.20260812",
            ),
            checks={name: True for name in REQUIRED_CHECKS},
            started_at="2026-09-01T20:00:00Z",
            completed_at="2026-09-01T20:01:00Z",
        )

    def test_receipt_is_bounded_and_names_absent_evidence(self):
        receipt = self.build_valid_receipt()

        self.assertEqual(
            set(receipt),
            {
                "schema_version",
                "policy_version",
                "started_at",
                "completed_at",
                "source",
                "platform",
                "versions",
                "checks",
                "evidence",
            },
        )
        self.assertEqual(
            receipt["evidence"],
            {
                "disposable_host": False,
                "package_upgrade_test": False,
                "future_kernel_test": False,
                "russia_network": False,
                "physical_device": False,
            },
        )
        serialized = json.dumps(receipt).lower()
        self.assertNotIn("namespace", serialized)
        self.assertNotIn("privatekey", serialized)
        self.assertNotIn("headerprotectionkey", serialized)

    def test_receipt_rejects_missing_extra_or_failed_checks(self):
        valid = {name: True for name in REQUIRED_CHECKS}
        invalid_checks = (
            {name: value for name, value in valid.items() if name != "cleanup"},
            {**valid, "unexpected": True},
            {**valid, "awg31_traffic": False},
            {**valid, "awg31_traffic": 1},
        )

        for checks in invalid_checks:
            with self.subTest(checks=checks), self.assertRaises(
                qualification.QualificationError
            ):
                qualification.build_receipt(
                    source_commit="a" * 40,
                    dirty_worktree=False,
                    os_version="24.04",
                    architecture="amd64",
                    kernel="7.0.0-1011-aws",
                    versions=qualification.VersionEvidence(
                        tools="3.1.20260812",
                        loaded_module="3.1.20260812",
                        packaged_module="3.1.20260812",
                        dkms="3.1.20260812",
                    ),
                    checks=checks,
                    started_at="2026-09-01T20:00:00Z",
                    completed_at="2026-09-01T20:01:00Z",
                )

    def test_receipt_rejects_malformed_public_metadata(self):
        cases = (
            {"source_commit": "not-a-commit"},
            {"dirty_worktree": 0},
            {"os_version": ""},
            {"architecture": "amd64\nsecret"},
            {"kernel": "x" * 129},
            {"started_at": "yesterday"},
            {"completed_at": "tomorrow"},
        )
        defaults = {
            "source_commit": "a" * 40,
            "dirty_worktree": False,
            "os_version": "24.04",
            "architecture": "amd64",
            "kernel": "7.0.0-1011-aws",
            "started_at": "2026-09-01T20:00:00Z",
            "completed_at": "2026-09-01T20:01:00Z",
        }

        for changed in cases:
            with self.subTest(changed=changed), self.assertRaises(
                qualification.QualificationError
            ):
                qualification.build_receipt(
                    **{**defaults, **changed},
                    versions=qualification.VersionEvidence(
                        tools="3.1.20260812",
                        loaded_module="3.1.20260812",
                        packaged_module="3.1.20260812",
                        dkms="3.1.20260812",
                    ),
                    checks={name: True for name in REQUIRED_CHECKS},
                )

    def test_public_error_redacts_keys_cps_and_bare_key_material(self):
        secret = "A" * 43 + "="
        error = qualification.safe_error(
            "PrivateKey = "
            f"{secret}\nHeaderProtectionKey = {secret}\n"
            "I1 = <b 0xdeadbeef>\n"
            f"bare={secret}"
        )

        self.assertNotIn(secret, error)
        self.assertNotIn("deadbeef", error)
        self.assertNotRegex(error, qualification.KEY_SHAPED_BASE64)

    def test_run_command_returns_bytes_without_a_shell(self):
        result = qualification.run_command(
            [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'safe')"]
        )

        self.assertEqual(result.stdout, b"safe")
        self.assertEqual(result.stderr, b"")

    def test_run_command_rejects_invalid_argv_and_timeout(self):
        invalid = (
            [],
            [""],
            [sys.executable, ""],
            [sys.executable, 3],
        )
        for argv in invalid:
            with self.subTest(argv=argv), self.assertRaises(
                qualification.QualificationError
            ):
                qualification.run_command(argv)

        with self.assertRaisesRegex(
            qualification.QualificationError, "timed out"
        ):
            qualification.run_command(
                [sys.executable, "-c", "import time; time.sleep(1)"],
                timeout=0.01,
            )

    def test_run_command_redacts_failed_stderr(self):
        secret = "B" * 43 + "="
        with self.assertRaises(qualification.QualificationError) as raised:
            qualification.run_command(
                [
                    sys.executable,
                    "-c",
                    f"import sys; sys.stderr.write('PrivateKey = {secret}'); sys.exit(2)",
                ]
            )

        self.assertNotIn(secret, str(raised.exception))
        self.assertNotRegex(
            str(raised.exception), qualification.KEY_SHAPED_BASE64
        )

    def test_atomic_receipt_is_private_complete_and_exclusive(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = pathlib.Path(directory)
            parent.chmod(0o700)
            output_dir = parent / "qualification"

            written = qualification.atomic_write_receipt(
                self.build_valid_receipt(), output_dir, "receipt.json"
            )

            self.assertEqual(written, output_dir / "receipt.json")
            self.assertEqual(stat.S_IMODE(output_dir.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(written.stat().st_mode), 0o600)
            self.assertEqual(json.loads(written.read_text()), self.build_valid_receipt())
            self.assertEqual(
                [path.name for path in output_dir.iterdir()], ["receipt.json"]
            )
            with self.assertRaises(qualification.QualificationError):
                qualification.atomic_write_receipt(
                    self.build_valid_receipt(), output_dir, "receipt.json"
                )

    def test_atomic_receipt_refuses_writable_parent_and_symlink_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            writable = root / "writable"
            writable.mkdir(mode=0o700)
            writable.chmod(0o770)
            with self.assertRaisesRegex(
                qualification.QualificationError, "writable"
            ):
                qualification.atomic_write_receipt(
                    self.build_valid_receipt(),
                    writable / "qualification",
                    "receipt.json",
                )

            safe_parent = root / "safe"
            safe_parent.mkdir(mode=0o700)
            sink = root / "sink"
            sink.mkdir(mode=0o700)
            (safe_parent / "qualification").symlink_to(
                sink, target_is_directory=True
            )
            with self.assertRaises(qualification.QualificationError):
                qualification.atomic_write_receipt(
                    self.build_valid_receipt(),
                    safe_parent / "qualification",
                    "receipt.json",
                )
            self.assertEqual(list(sink.iterdir()), [])


def classic_obfuscation():
    return {
        "Jc": 6,
        "Jmin": 8,
        "Jmax": 80,
        "S1": 25,
        "S2": 75,
        "H1": 101,
        "H2": 102,
        "H3": 103,
        "H4": 104,
    }


def awg31_obfuscation():
    return {
        "mode": "awg31",
        "profile": {
            "schema_version": 1,
            "name": "russia-ios-v1",
            "parameters": {
                "Jc": 9,
                "Jmin": 8,
                "Jmax": 80,
                "S1": 30,
                "S2": 100,
                "S3": 40,
                "S4": 20,
                "H1": 1,
                "H2": 2,
                "H3": 3,
                "H4": 4,
                "I1": "<b 0x01020304>",
                "I2": None,
                "I3": None,
                "I4": None,
                "I5": None,
                "ContentPaddingAddition": {"min": 0, "max": 64},
                "RekeyAfterTime": {"min": 105, "max": 135},
                "RekeyTimeout": {"min": 4, "max": 7},
                "RejectAfterTime": {"min": 165, "max": 195},
                "KeepaliveTimeout": {"min": 8, "max": 12},
                "MaxHandshakeAttempts": {"min": 15, "max": 21},
                "RandomTrailers": False,
                "DisableCookies": True,
            },
            "header_protection_key_path": "/opt/amneziawg/keys/server/header-protection",
        },
    }


class ScriptedRunner:
    def __init__(self, *, fail_when=None, fail_ping_target=None, counters=b"peer\t10\t20\n"):
        self.fail_when = fail_when
        self.fail_ping_target = fail_ping_target
        self.counters = counters
        self.failed_once = False
        self.argv = []
        self.input_data = []
        self.namespaces = {"customer-production"}
        self.root_links = {"customer0"}
        self.deleted_namespaces = []
        self.config_paths = []

    @property
    def flattened_argv(self):
        return [argument for command in self.argv for argument in command]

    def __call__(self, argv, *, input_data=None, timeout=20):
        command = tuple(argv)
        self.argv.append(command)
        self.input_data.append(input_data)
        if (
            self.fail_when is not None
            and not self.failed_once
            and self.fail_when(command)
        ):
            self.failed_once = True
            raise qualification.QualificationError("injected command failure")

        if command == ("ip", "netns", "list"):
            output = "".join(f"{name}\n" for name in sorted(self.namespaces)).encode()
            return subprocess.CompletedProcess(command, 0, output, b"")
        if command == ("ip", "-j", "link", "show"):
            output = json.dumps(
                [{"ifname": name} for name in sorted(self.root_links)]
            ).encode()
            return subprocess.CompletedProcess(command, 0, output, b"")
        if command[:3] == ("ip", "netns", "add"):
            self.namespaces.add(command[3])
        elif command[:3] == ("ip", "netns", "delete"):
            self.namespaces.discard(command[3])
            self.deleted_namespaces.append(command[3])
        elif len(command) >= 4 and command[:3] == ("ip", "link", "add") and "peer" in command:
            self.root_links.add(command[3])
            self.root_links.add(command[-1])
        elif command[:3] == ("ip", "link", "set") and "netns" in command:
            self.root_links.discard(command[3])
        elif command[:3] == ("ip", "link", "delete"):
            self.root_links.discard(command[3])
        elif len(command) >= 5 and command[:3] == ("ip", "netns", "exec"):
            if len(command) >= 7 and command[4:7] == ("awg", "setconf", "awgt"):
                self.config_paths.append(pathlib.Path(command[7]))
            if command[4:7] == ("awg", "show", "awgt") and command[7:] == (
                "transfer",
            ):
                return subprocess.CompletedProcess(command, 0, self.counters, b"")
            if command[4] == "ping" and command[-1] == self.fail_ping_target:
                raise qualification.QualificationError("injected ping failure")

        if command == ("awg", "genkey"):
            return subprocess.CompletedProcess(command, 0, b"A" * 43 + b"=\n", b"")
        if command == ("awg", "genpsk"):
            return subprocess.CompletedProcess(command, 0, b"C" * 43 + b"=\n", b"")
        if command == ("awg", "pubkey"):
            return subprocess.CompletedProcess(command, 0, b"B" * 43 + b"=\n", b"")
        return subprocess.CompletedProcess(command, 0, b"", b"")


class NamespaceQualificationTests(unittest.TestCase):
    def test_failure_cleans_only_current_owned_resources_in_reverse_order(self):
        runner = ScriptedRunner(
            fail_when=lambda argv: argv[-3:] == ("set", "awgt", "up")
        )
        qualifier = qualification.NamespaceQualifier(
            runner=runner, token="a1b2c3", sleeper=lambda _: None
        )

        with self.assertRaises(qualification.QualificationError):
            qualifier.qualify(
                classic_obfuscation(), awg31_obfuscation(), b"h" * 32
            )

        self.assertEqual(
            runner.deleted_namespaces,
            ["awgq-c-a1b2c3", "awgq-s-a1b2c3"],
        )
        self.assertIn("customer-production", runner.namespaces)
        self.assertIn("customer0", runner.root_links)
        self.assertNotIn("awg0", runner.flattened_argv)

    def test_awg31_requires_nonzero_counters_in_both_directions_for_both_peers(self):
        invalid = (
            (b"peer\t0\t10\n", b"peer\t10\t10\n"),
            (b"peer\t10\t0\n", b"peer\t10\t10\n"),
            (b"peer\t10\t10\n", b"peer\t0\t10\n"),
            (b"peer\t10\t10\n", b"peer\t10\t0\n"),
        )
        for server, client in invalid:
            with self.subTest(server=server, client=client), self.assertRaises(
                qualification.QualificationError
            ):
                qualification.require_bidirectional_counters(server, client)

        self.assertEqual(
            qualification.require_bidirectional_counters(
                b"peer\t10\t20\n", b"peer\t30\t40\n"
            ),
            ((10, 20), (30, 40)),
        )

    def test_both_ping_directions_are_required_with_bounded_attempts(self):
        runner = ScriptedRunner(fail_ping_target="10.200.0.2")
        qualifier = qualification.NamespaceQualifier(
            runner=runner, token="d4e5f6", sleeper=lambda _: None
        )

        with self.assertRaises(qualification.QualificationError):
            qualifier.qualify(
                classic_obfuscation(), awg31_obfuscation(), b"h" * 32
            )

        ping_commands = [command for command in runner.argv if "ping" in command]
        self.assertTrue(any(command[-1] == "10.200.0.1" for command in ping_commands))
        self.assertEqual(
            sum(command[-1] == "10.200.0.2" for command in ping_commands), 5
        )
        self.assertEqual(
            runner.deleted_namespaces,
            ["awgq-c-d4e5f6", "awgq-s-d4e5f6"],
        )

    def test_success_recreates_each_mode_rolls_back_and_erases_configs(self):
        runner = ScriptedRunner()
        qualifier = qualification.NamespaceQualifier(
            runner=runner, token="112233", sleeper=lambda _: None
        )

        checks = qualifier.qualify(
            classic_obfuscation(), awg31_obfuscation(), b"h" * 32
        )

        self.assertEqual(
            checks,
            {
                "native_validation": True,
                "classic_traffic": True,
                "classic_recreation": True,
                "awg31_traffic": True,
                "awg31_counters": True,
                "awg31_recreation": True,
                "classic_rollback": True,
                "cleanup": True,
            },
        )
        tunnel_creations = [
            command
            for command in runner.argv
            if command[-5:] == ("link", "add", "awgt", "type", "amneziawg")
        ]
        self.assertEqual(len(tunnel_creations), 10)
        self.assertFalse(any(path.exists() for path in runner.config_paths))
        self.assertFalse(
            any(
                argument in {"I1", "I2", "I3", "I4", "I5"}
                for argument in runner.flattened_argv
            )
        )
        self.assertEqual(
            runner.deleted_namespaces,
            ["awgq-c-112233", "awgq-s-112233"],
        )

    def test_signals_remain_blocked_until_created_resources_are_journaled(self):
        runner = ScriptedRunner()
        qualifier = qualification.NamespaceQualifier(
            runner=runner, token="445566", sleeper=lambda _: None
        )
        restored_masks = []

        def observe_mask(how, mask):
            if how == signal.SIG_BLOCK:
                return frozenset()
            self.assertEqual(how, signal.SIG_SETMASK)
            restored_masks.append(mask)
            created_namespaces = {
                name for name in runner.namespaces if name.startswith("awgq-")
            }
            created_links = {
                name for name in runner.root_links if name.startswith("awgq-")
            }
            self.assertLessEqual(
                created_namespaces, set(qualifier.resources.namespaces)
            )
            self.assertLessEqual(created_links, set(qualifier.resources.host_links))
            return frozenset()

        with mock.patch.object(signal, "pthread_sigmask", side_effect=observe_mask):
            qualifier.qualify(
                classic_obfuscation(), awg31_obfuscation(), b"h" * 32
            )

        self.assertEqual(len(restored_masks), 3)


class StaticProtectedReader:
    def __init__(self, digest="f" * 64, module="3.1.20260812\n"):
        self.value = digest
        self.module = module

    def digest_paths(self, paths):
        return self.value

    def read_text(self, path):
        values = {
            pathlib.Path("/etc/os-release"): 'ID=ubuntu\nVERSION_ID="24.04"\n',
            pathlib.Path("/sys/module/amneziawg/version"): self.module,
        }
        return values[path]


class MappingRunner:
    def __init__(self, outputs):
        self.outputs = dict(outputs)
        self.argv = []

    def __call__(self, argv, *, input_data=None, timeout=20):
        command = tuple(argv)
        self.argv.append(command)
        if command not in self.outputs:
            raise AssertionError(f"unexpected command: {command!r}")
        output = self.outputs[command]
        if isinstance(output, Exception):
            raise output
        return subprocess.CompletedProcess(command, 0, output, b"")


def healthy_document():
    return {
        "schema_version": 1,
        "ok": True,
        "errors": [],
        "warnings": [],
        "data": {
            "mode": "classic",
            "summary": {"failures": 0, "warnings": 0},
            "transition": {"state": "none"},
        },
    }


def status_document():
    return {
        "schema_version": 1,
        "ok": True,
        "errors": [],
        "warnings": [],
        "data": {
            "boot": "enabled",
            "endpoint": {"host": "vpn.example.com", "port": 55323},
            "interface": {"name": "awg0", "up": True},
            "mode": "classic",
            "obfuscation": {"mode": "classic", "profile": "classic-v1"},
            "service": "active",
            "transition": {"state": "none"},
        },
    }


def stable_live_awg_outputs(*, allowed_ips=b"peer\t10.77.42.2/32\n"):
    peer = b"A" * 43 + b"="
    return {
        ("awg", "show", "awg0", "public-key"): peer + b"\n",
        ("awg", "show", "awg0", "private-key"): b"B" * 43 + b"=\n",
        ("awg", "show", "awg0", "listen-port"): b"55323\n",
        ("awg", "show", "awg0", "fwmark"): b"off\n",
        ("awg", "show", "awg0", "peers"): peer + b"\n",
        ("awg", "show", "awg0", "preshared-keys"): peer + b"\t" + b"C" * 43 + b"=\n",
        ("awg", "show", "awg0", "endpoints"): peer + b"\t(none)\n",
        ("awg", "show", "awg0", "allowed-ips"): allowed_ips,
        ("awg", "show", "awg0", "persistent-keepalive"): peer + b"\toff\n",
    }


class QualificationCliTests(unittest.TestCase):
    def valid_host_documents(self):
        return {
            "effective_uid": 0,
            "git_status": b"",
            "head": b"a" * 40 + b"\n",
            "origin_main": b"a" * 40 + b"\n",
            "health": json.dumps(healthy_document()).encode(),
            "status": json.dumps(status_document()).encode(),
            "service_state": b"active\n",
            "boot_state": b"enabled\n",
            "os_release": 'ID=ubuntu\nVERSION_ID="24.04"\n',
            "architecture": b"amd64\n",
            "namespace_inventory": b"customer-production\n",
            "link_inventory": b'[{"ifname":"customer0"}]\n',
            "listeners": b"UNCONN 0 0 0.0.0.0:55323 0.0.0.0:*\n",
            "orphaned_temporary_roots": (),
        }

    def test_host_preflight_rejects_every_production_safety_violation(self):
        cases = (
            ("non-root", {"effective_uid": 1000}),
            ("dirty", {"git_status": b" M src/awgctl/core.py\n"}),
            ("source", {"origin_main": b"b" * 40 + b"\n"}),
            (
                "health",
                {
                    "health": json.dumps(
                        {
                            **healthy_document(),
                            "data": {
                                **healthy_document()["data"],
                                "summary": {"failures": 1, "warnings": 0},
                            },
                        }
                    ).encode()
                },
            ),
            (
                "classic",
                {
                    "status": json.dumps(
                        {
                            **status_document(),
                            "data": {**status_document()["data"], "mode": "awg31"},
                        }
                    ).encode()
                },
            ),
            (
                "transition",
                {
                    "status": json.dumps(
                        {
                            **status_document(),
                            "data": {
                                **status_document()["data"],
                                "transition": {"state": "prepared"},
                            },
                        }
                    ).encode()
                },
            ),
            ("service", {"service_state": b"inactive\n"}),
            ("boot", {"boot_state": b"disabled\n"}),
            ("platform", {"architecture": b"arm64\n"}),
            ("platform", {"os_release": 'ID=ubuntu\nVERSION_ID="22.04"\n'}),
            ("resource", {"namespace_inventory": b"awgq-s-a1b2c3\n"}),
            ("resource", {"link_inventory": b'[{"ifname":"awgq-vs-a1b2c3"}]'}),
            ("resource", {"orphaned_temporary_roots": ("awgq-config-stale",)}),
            ("listener", {"listeners": b"UNCONN 0 0 0.0.0.0:9999 0.0.0.0:*\n"}),
        )

        for expected, changed in cases:
            with self.subTest(changed=changed), self.assertRaisesRegex(
                qualification.QualificationError, expected
            ):
                qualification.validate_host_preflight(
                    **{**self.valid_host_documents(), **changed}
                )

    def test_version_preflight_binds_exact_native_pair_and_current_dkms(self):
        runner = MappingRunner(
            {
                ("awg", "--version"): b"amneziawg-tools v3.1.20260812 - https://amnezia.org\n",
                ("modinfo", "-F", "version", "amneziawg"): b"3.1.20260812\n",
                ("uname", "-r"): b"7.0.0-1011-aws\n",
                ("dkms", "status"): b"amneziawg/1.0.0, 7.0.0-1011-aws, x86_64: installed\n",
            }
        )

        versions = qualification.verify_preflight(
            expected_tools="3.1.20260812",
            expected_module="3.1.20260812",
            command_runner=runner,
            loaded_version_reader=lambda: "3.1.20260812\n",
        )

        self.assertEqual(
            versions,
            qualification.VersionEvidence(
                tools="3.1.20260812",
                loaded_module="3.1.20260812",
                packaged_module="3.1.20260812",
                dkms="1.0.0",
            ),
        )

    def test_version_preflight_rejects_expected_pair_mismatch(self):
        runner = MappingRunner(
            {
                ("awg", "--version"): b"amneziawg-tools v3.1.20260811 - https://amnezia.org\n",
                ("modinfo", "-F", "version", "amneziawg"): b"3.1.20260812\n",
            }
        )
        with self.assertRaisesRegex(
            qualification.QualificationError, "expected"
        ):
            qualification.verify_preflight(
                expected_tools="3.1.20260812",
                expected_module="3.1.20260812",
                command_runner=runner,
                loaded_version_reader=lambda: "3.1.20260812\n",
            )

    def test_live_preflight_rejects_non_root_before_running_commands(self):
        runner = mock.Mock(side_effect=AssertionError("must not run"))
        adapters = qualification.LiveAdapters(
            command_runner=runner,
            protected_reader=StaticProtectedReader(),
            effective_uid=lambda: 1000,
        )

        with self.assertRaisesRegex(
            qualification.QualificationError, "non-root"
        ):
            adapters.verify_preflight(
                expected_tools="3.1.20260812",
                expected_module="3.1.20260812",
            )

        runner.assert_not_called()

    def test_snapshot_normalizes_only_volatile_handshakes_and_nft_counters(self):
        peer = b"A" * 43 + b"="
        common = {
            **stable_live_awg_outputs(),
            ("ip", "-j", "address", "show", "dev", "awg0"): b'[{"ifname":"awg0","ifindex":9,"addr_info":[{"local":"10.77.42.1","valid_life_time":100}]}]',
            ("awg", "show", "awg0", "peers"): peer + b"\n",
            ("awg", "showconf", "awg0"): b"[Interface]\nPrivateKey = hidden\n\n[Peer]\nAllowedIPs = 10.77.42.2/32\n",
            ("awg", "show", "awg0", "listen-port"): b"55323\n",
            ("ss", "-H", "-lunp"): b"UNCONN 0 0 0.0.0.0:55323 0.0.0.0:*\n",
            ("systemctl", "is-active", "awg-quick@awg0.service"): b"active\n",
            ("systemctl", "is-enabled", "awg-quick@awg0.service"): b"enabled\n",
            (
                "dpkg-query",
                "-W",
                "-f=${Package}\\t${Version}\\n",
                "amneziawg",
                "amneziawg-tools",
                "amneziawg-dkms",
            ): b"amneziawg\t1\namneziawg-tools\t1\namneziawg-dkms\t1\n",
            ("dkms", "status"): b"amneziawg/1.0.0, kernel, x86_64: installed\n",
        }
        first = MappingRunner(
            {
                **common,
                ("awg", "show", "awg0", "latest-handshakes"): peer + b"\t0\n",
                ("nft", "-j", "list", "ruleset"): b'{"nftables":[{"counter":{"packets":1,"bytes":2}}]}',
            }
        )
        second = MappingRunner(
            {
                **common,
                ("awg", "show", "awg0", "latest-handshakes"): peer + b"\t1788292800\n",
                ("nft", "-j", "list", "ruleset"): b'{"nftables":[{"counter":{"packets":99,"bytes":999}}]}',
            }
        )

        before = qualification.capture_production_snapshot(
            first, StaticProtectedReader()
        )
        after = qualification.capture_production_snapshot(
            second, StaticProtectedReader()
        )

        self.assertEqual(before, after)

    def test_snapshot_detects_any_complete_live_awg_configuration_change(self):
        peer = b"A" * 43 + b"="
        common = {
            **stable_live_awg_outputs(),
            ("ip", "-j", "address", "show", "dev", "awg0"): b'[{"ifname":"awg0","addr_info":[{"local":"10.77.42.1"}]}]',
            ("awg", "show", "awg0", "peers"): peer + b"\n",
            ("awg", "show", "awg0", "latest-handshakes"): peer + b"\t0\n",
            ("awg", "show", "awg0", "listen-port"): b"55323\n",
            ("ss", "-H", "-lunp"): b"UNCONN 0 0 0.0.0.0:55323 0.0.0.0:*\n",
            ("nft", "-j", "list", "ruleset"): b'{"nftables":[]}',
            ("systemctl", "is-active", "awg-quick@awg0.service"): b"active\n",
            ("systemctl", "is-enabled", "awg-quick@awg0.service"): b"enabled\n",
            (
                "dpkg-query",
                "-W",
                "-f=${Package}\\t${Version}\\n",
                "amneziawg",
                "amneziawg-tools",
                "amneziawg-dkms",
            ): b"packages\n",
            ("dkms", "status"): b"dkms\n",
        }
        before = MappingRunner(
            {
                **common,
                **stable_live_awg_outputs(
                    allowed_ips=b"peer\t10.77.42.2/32\n"
                ),
                ("awg", "showconf", "awg0"): b"same\n",
            }
        )
        after = MappingRunner(
            {
                **common,
                **stable_live_awg_outputs(
                    allowed_ips=b"peer\t10.77.42.99/32\n"
                ),
                ("awg", "showconf", "awg0"): b"same\n",
            }
        )

        first = qualification.capture_production_snapshot(
            before, StaticProtectedReader()
        )
        second = qualification.capture_production_snapshot(
            after, StaticProtectedReader()
        )

        self.assertNotEqual(first.interface_sha256, second.interface_sha256)

    def test_snapshot_uses_only_closed_safe_awg_selectors(self):
        outputs = {
            **stable_live_awg_outputs(),
            ("awg", "showconf", "awg0"): b"unsafe enumerating output\n",
            ("ip", "-j", "address", "show", "dev", "awg0"): b'[{"ifname":"awg0"}]',
            ("awg", "show", "awg0", "latest-handshakes"): b"A" * 43 + b"=\t0\n",
            ("ss", "-H", "-lunp"): b"UNCONN 0 0 0.0.0.0:55323 0.0.0.0:*\n",
            ("nft", "-j", "list", "ruleset"): b'{"nftables":[]}',
            ("systemctl", "is-active", "awg-quick@awg0.service"): b"active\n",
            ("systemctl", "is-enabled", "awg-quick@awg0.service"): b"enabled\n",
            (
                "dpkg-query",
                "-W",
                "-f=${Package}\\t${Version}\\n",
                "amneziawg",
                "amneziawg-tools",
                "amneziawg-dkms",
            ): b"packages\n",
            ("dkms", "status"): b"dkms\n",
        }
        runner = MappingRunner(outputs)

        qualification.capture_production_snapshot(
            runner, StaticProtectedReader()
        )

        self.assertNotIn(("awg", "showconf", "awg0"), runner.argv)

    def test_snapshot_binds_the_loaded_module_identity(self):
        outputs = {
            **stable_live_awg_outputs(),
            ("awg", "showconf", "awg0"): b"same\n",
            ("ip", "-j", "address", "show", "dev", "awg0"): b'[{"ifname":"awg0"}]',
            ("awg", "show", "awg0", "latest-handshakes"): b"A" * 43 + b"=\t0\n",
            ("ss", "-H", "-lunp"): b"UNCONN 0 0 0.0.0.0:55323 0.0.0.0:*\n",
            ("nft", "-j", "list", "ruleset"): b'{"nftables":[]}',
            ("systemctl", "is-active", "awg-quick@awg0.service"): b"active\n",
            ("systemctl", "is-enabled", "awg-quick@awg0.service"): b"enabled\n",
            (
                "dpkg-query",
                "-W",
                "-f=${Package}\\t${Version}\\n",
                "amneziawg",
                "amneziawg-tools",
                "amneziawg-dkms",
            ): b"packages\n",
            ("dkms", "status"): b"dkms\n",
        }

        before = qualification.capture_production_snapshot(
            MappingRunner(outputs),
            StaticProtectedReader(module="3.1.20260812\n"),
        )
        after = qualification.capture_production_snapshot(
            MappingRunner(outputs),
            StaticProtectedReader(module="3.1.20260813\n"),
        )

        self.assertNotEqual(before.package_sha256, after.package_sha256)

    def test_snapshot_turns_malformed_native_json_into_a_bounded_error(self):
        runner = MappingRunner(
            {
                ("ip", "-j", "address", "show", "dev", "awg0"): b"not-json",
            }
        )

        with self.assertRaises(qualification.QualificationError):
            qualification.capture_production_snapshot(
                runner, StaticProtectedReader()
            )

    def test_snapshot_mismatch_blocks_receipt_without_repair(self):
        before = qualification.ProductionSnapshot(
            protected_tree_sha256="a" * 64,
            interface_sha256="b" * 64,
            listener_sha256="c" * 64,
            nftables_sha256="d" * 64,
            service_state=("active", "enabled"),
            package_sha256="e" * 64,
        )
        after = dataclasses.replace(before, nftables_sha256="b" * 64)
        writer = mock.Mock()
        adapters = mock.Mock(spec=qualification.LiveAdapters)
        adapters.mutation_exclusion.return_value = contextlib.nullcontext()
        adapters.capture_snapshot.side_effect = (before, after)

        with self.assertRaisesRegex(
            qualification.QualificationError, "production invariants"
        ):
            qualification.execute_qualification(
                expected_tools="3.1.20260812",
                expected_module="3.1.20260812",
                adapters=adapters,
                receipt_writer=writer,
            )

        writer.assert_not_called()

    def test_shared_mutation_exclusion_spans_preflight_snapshots_and_receipt(self):
        events = []
        snapshot = qualification.ProductionSnapshot(
            protected_tree_sha256="a" * 64,
            interface_sha256="b" * 64,
            listener_sha256="c" * 64,
            nftables_sha256="d" * 64,
            service_state=("active", "enabled"),
            package_sha256="e" * 64,
        )

        class RecordingAdapters:
            def now(self):
                return "2026-09-01T20:00:00Z"

            @contextlib.contextmanager
            def mutation_exclusion(self):
                events.append("lock-enter")
                try:
                    yield
                finally:
                    events.append("lock-exit")

            def verify_preflight(self, **_kwargs):
                events.append("preflight")
                return qualification.PreflightEvidence(
                    source_commit="a" * 40,
                    dirty_worktree=False,
                    os_version="24.04",
                    architecture="amd64",
                    kernel="7.0.0-1011-aws",
                    versions=qualification.VersionEvidence(
                        tools="3.1.20260812",
                        loaded_module="3.1.20260812",
                        packaged_module="3.1.20260812",
                        dkms="1.0.0",
                    ),
                )

            def verify_locked_state(self, **_kwargs):
                events.append("locked-preflight")

            def capture_snapshot(self):
                events.append("snapshot")
                return snapshot

            def qualify_namespaces(self):
                events.append("qualify")
                return {
                    "native_validation": True,
                    "classic_traffic": True,
                    "classic_recreation": True,
                    "awg31_traffic": True,
                    "awg31_counters": True,
                    "awg31_recreation": True,
                    "classic_rollback": True,
                    "cleanup": True,
                }

        def writer(_receipt):
            events.append("receipt")
            return pathlib.Path("/receipt.json")

        qualification.execute_qualification(
            expected_tools="3.1.20260812",
            expected_module="3.1.20260812",
            adapters=RecordingAdapters(),
            receipt_writer=writer,
        )

        self.assertEqual(
            events,
            [
                "preflight",
                "lock-enter",
                "locked-preflight",
                "snapshot",
                "qualify",
                "snapshot",
                "receipt",
                "lock-exit",
            ],
        )

    def test_success_stdout_contains_only_receipt_path_and_nonsecret_summary(self):
        output = io.StringIO()
        with mock.patch.object(
            qualification,
            "execute_qualification",
            return_value=pathlib.Path(
                "/opt/amneziawg/qualification/receipt.json"
            ),
        ):
            result = qualification.main(
                [
                    "--expected-tools",
                    "3.1.20260812",
                    "--expected-module",
                    "3.1.20260812",
                ],
                stdout=output,
            )

        self.assertEqual(result, 0)
        envelope = json.loads(output.getvalue())
        self.assertTrue(envelope["ok"])
        self.assertEqual(
            envelope["receipt"],
            "/opt/amneziawg/qualification/receipt.json",
        )
        self.assertNotRegex(output.getvalue(), qualification.KEY_SHAPED_BASE64)
        self.assertNotIn("I1", output.getvalue())

    def test_operational_exception_returns_one_generic_json_failure(self):
        output = io.StringIO()
        secret = "D" * 43 + "="
        with mock.patch.object(
            qualification,
            "execute_qualification",
            side_effect=OSError(
                f"disk failed: PrivateKey = {secret}; I1 = <b 0xdeadbeef>; awgq-s-abcdef"
            ),
        ):
            result = qualification.main(
                [
                    "--expected-tools",
                    "3.1.20260812",
                    "--expected-module",
                    "3.1.20260812",
                ],
                stdout=output,
            )

        self.assertEqual(result, 1)
        envelope = json.loads(output.getvalue())
        self.assertFalse(envelope["ok"])
        self.assertNotIn(secret, output.getvalue())
        self.assertNotIn("deadbeef", output.getvalue())
        self.assertNotIn("awgq-", output.getvalue())
        self.assertNotIn("Traceback", output.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
