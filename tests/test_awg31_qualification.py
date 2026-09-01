import importlib.util
import json
import os
import pathlib
import stat
import subprocess
import sys
import tempfile
import unittest


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


if __name__ == "__main__":
    unittest.main(verbosity=2)
