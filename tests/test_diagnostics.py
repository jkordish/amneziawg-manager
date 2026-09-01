import json
import os
import pathlib
import stat
import sys
import tempfile
import unittest
from unittest import mock


REPO_ROOT = pathlib.Path(__file__).parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from awgctl.diagnostics import DiagnosticsError, create_bundle, redact_awg_config


class DiagnosticsTests(unittest.TestCase):
    def test_key_material_is_replaced_with_fingerprints(self):
        private = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        public = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
        psk = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC="
        source = f"PrivateKey = {private}\nPublicKey = {public}\nPresharedKey = {psk}\nAddress = 10.77.42.1/24\n"
        redacted = redact_awg_config(source)
        self.assertNotIn(private, redacted)
        self.assertNotIn(public, redacted)
        self.assertNotIn(psk, redacted)
        self.assertIn("PrivateKey = [redacted sha256:", redacted)
        self.assertIn("Address = 10.77.42.1/24", redacted)

    def test_bundle_is_private_manifested_and_contains_no_supplied_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            secret = "super-secret-material"
            bundle = create_bundle(
                root,
                product_version="0.1.0-beta.1",
                created_at="2026-09-01T02:00:00Z",
                files={"summary.json": b'{"ok": true}\n', "system/status.txt": b"active\n"},
            )
            self.assertEqual(stat.S_IMODE(bundle.stat().st_mode), 0o700)
            manifest = json.loads((bundle / "manifest.json").read_text())
            self.assertEqual(manifest["file_count"], 2)
            for path in bundle.rglob("*"):
                if path.is_file():
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                    self.assertNotIn(secret.encode(), path.read_bytes())
            self.assertEqual(bundle.stat().st_uid, os.getuid())

    def test_bundle_rejects_a_parent_writable_by_group_or_other(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = pathlib.Path(directory) / "writable"
            parent.mkdir(mode=0o700)
            parent.chmod(0o770)
            with self.assertRaisesRegex(DiagnosticsError, "writable"):
                create_bundle(
                    parent,
                    product_version="0.1.0-beta.1",
                    created_at="2026-09-01T02:00:00Z",
                    files={"summary.txt": b"safe\n"},
                )
            self.assertEqual(list(parent.iterdir()), [])

    def test_parent_path_substitution_cannot_reach_the_replacement_sink(self):
        with tempfile.TemporaryDirectory() as directory:
            base = pathlib.Path(directory)
            parent = base / "output"
            original = base / "opened-output"
            sink = base / "attacker-sink"
            parent.mkdir(mode=0o700)
            sink.mkdir(mode=0o700)
            real_open = os.open
            swapped = False

            def swap_after_parent_open(path, flags, mode=0o777, *, dir_fd=None):
                nonlocal swapped
                fd = real_open(path, flags, mode, dir_fd=dir_fd)
                if not swapped and dir_fd is None and os.fspath(path) == os.fspath(parent):
                    swapped = True
                    parent.rename(original)
                    parent.symlink_to(sink, target_is_directory=True)
                return fd

            with mock.patch("awgctl.diagnostics.os.open", side_effect=swap_after_parent_open):
                with self.assertRaisesRegex(DiagnosticsError, "changed"):
                    create_bundle(
                        parent,
                        product_version="0.1.0-beta.1",
                        created_at="2026-09-01T02:00:00Z",
                        files={"system/status.txt": b"active\n"},
                    )
            self.assertEqual(list(sink.iterdir()), [])
            self.assertEqual(list(original.iterdir()), [])

    def test_incomplete_bundle_is_removed_after_write_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = pathlib.Path(directory)
            with (
                mock.patch(
                    "awgctl.diagnostics.os.write",
                    side_effect=OSError("injected disk full"),
                ),
                self.assertRaisesRegex(OSError, "disk full"),
            ):
                create_bundle(
                    parent,
                    product_version="0.1.0-beta.1",
                    created_at="2026-09-01T02:00:00Z",
                    files={"system/status.txt": b"active\n"},
                )

            self.assertEqual(list(parent.iterdir()), [])

    def test_preexisting_candidate_symlink_cannot_reach_its_sink(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = pathlib.Path(directory) / "output"
            sink = pathlib.Path(directory) / "attacker-sink"
            parent.mkdir(mode=0o700)
            sink.mkdir(mode=0o700)
            first_name = "20260901T020000Z-" + "a" * 32
            (parent / first_name).symlink_to(sink, target_is_directory=True)
            with mock.patch("secrets.token_hex", side_effect=["a" * 32, "b" * 32]):
                bundle = create_bundle(
                    parent,
                    product_version="0.1.0-beta.1",
                    created_at="2026-09-01T02:00:00Z",
                    files={"system/status.txt": b"active\n"},
                )
            self.assertEqual(bundle.name, "20260901T020000Z-" + "b" * 32)
            self.assertEqual(list(sink.iterdir()), [])
            self.assertEqual((bundle / "system/status.txt").read_bytes(), b"active\n")


if __name__ == "__main__":
    unittest.main(verbosity=2)
