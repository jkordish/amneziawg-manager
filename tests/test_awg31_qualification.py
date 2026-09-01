import importlib.util
import json
import os
import pathlib
import stat
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
