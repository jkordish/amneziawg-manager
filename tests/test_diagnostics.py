import json
import os
import pathlib
import stat
import sys
import tempfile
import unittest


REPO_ROOT = pathlib.Path(__file__).parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from awgctl.diagnostics import create_bundle, redact_awg_config


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


if __name__ == "__main__":
    unittest.main(verbosity=2)
