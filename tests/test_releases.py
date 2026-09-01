import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest


REPO_ROOT = pathlib.Path(__file__).parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from awgctl.releases import ReleaseError, parse_manifest, verify_artifact, verify_ssh_signature


class ReleaseVerificationTests(unittest.TestCase):
    def manifest(self, artifact: bytes = b"zipapp") -> bytes:
        value = {
            "schema_version": 1,
            "version": "0.1.0-beta.1",
            "tag": "v0.1.0-beta.1",
            "channel": "beta",
            "platform": "ubuntu-24.04-amd64",
            "artifact": {
                "name": "awgctl.pyz",
                "sha256": hashlib.sha256(artifact).hexdigest(),
                "size": len(artifact),
            },
        }
        return (json.dumps(value, sort_keys=True) + "\n").encode()

    def test_manifest_and_artifact_must_match_platform_version_size_and_hash(self):
        artifact = b"zipapp"
        manifest = parse_manifest(self.manifest(artifact), expected_platform="ubuntu-24.04-amd64")
        verify_artifact(manifest, artifact)
        with self.assertRaisesRegex(ReleaseError, "hash"):
            verify_artifact(manifest, b"zippap")
        with self.assertRaisesRegex(ReleaseError, "platform"):
            parse_manifest(self.manifest(), expected_platform="ubuntu-22.04-amd64")

    def test_openssh_signature_verification_rejects_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            key = root / "key"
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
            public_key = key.with_suffix(".pub").read_text().strip()
            manifest = self.manifest()
            manifest_path = root / "release.json"
            manifest_path.write_bytes(manifest)
            subprocess.run(["ssh-keygen", "-Y", "sign", "-q", "-f", str(key), "-n", "file", str(manifest_path)], check=True)
            signature = (root / "release.json.sig").read_bytes()
            verify_ssh_signature(manifest, signature, public_key=public_key)
            with self.assertRaisesRegex(ReleaseError, "signature"):
                verify_ssh_signature(manifest + b"tampered", signature, public_key=public_key)


if __name__ == "__main__":
    unittest.main(verbosity=2)
