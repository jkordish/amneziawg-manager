import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


REPO_ROOT = pathlib.Path(__file__).parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from awgctl.releases import (
    RELEASE_PUBLIC_KEY,
    ReleaseError,
    discover_release_tag,
    parse_manifest,
    verify_artifact,
    verify_ssh_signature,
    version_key,
)
from awgctl.semver import InvalidVersion, precedence_key


class ReleaseVerificationTests(unittest.TestCase):
    def test_semver_prerelease_identifiers_follow_semver_precedence(self):
        ordered = [
            "0.1.0-beta.4",
            "0.1.0-beta.10",
            "0.1.0-beta.10.1",
            "0.1.0-beta.alpha",
            "0.1.0-rc.1",
            "0.1.0",
        ]
        self.assertEqual(sorted(reversed(ordered), key=version_key), ordered)

    def test_invalid_semver_versions_are_rejected(self):
        for value in (
            "01.2.3",
            "1.02.3",
            "1.2.03",
            "1.2.3-beta.01",
            "1.2.3-beta..1",
            "1.2.3-",
            "v1.2.3",
            "1.2.3+build",
        ):
            with self.subTest(value=value), self.assertRaises(ReleaseError):
                version_key(value)

    def test_unicode_and_oversized_numeric_versions_raise_boundary_errors(self):
        invalid = {
            "unicode core digit": "1٢.0.0",
            "oversized core": f"{'9' * 5000}.0.0",
            "oversized numeric prerelease": f"1.0.0-{'9' * 5000}",
        }
        for label, value in invalid.items():
            with self.subTest(parser=label), self.assertRaises(InvalidVersion):
                precedence_key(value)
            with self.subTest(release=label), self.assertRaises(ReleaseError):
                version_key(value)

    def test_committed_and_embedded_release_public_keys_match(self):
        self.assertEqual((REPO_ROOT / "release-signing-key.pub").read_text().strip(), RELEASE_PUBLIC_KEY)

    def manifest(
        self,
        artifact: bytes = b"zipapp",
        *,
        version: str = "0.1.0-beta.1",
        channel: str = "beta",
    ) -> bytes:
        value = {
            "schema_version": 1,
            "version": version,
            "tag": f"v{version}",
            "channel": channel,
            "platform": "ubuntu-24.04-amd64",
            "installation_schema_version": 1,
            "artifact": {
                "name": "awgctl.pyz",
                "sha256": hashlib.sha256(artifact).hexdigest(),
                "size": len(artifact),
            },
        }
        return (json.dumps(value, sort_keys=True) + "\n").encode()

    def test_stable_discovery_does_not_trust_false_github_prerelease_metadata(self):
        releases = [
            {"draft": False, "prerelease": False, "tag_name": "v0.2.0-beta.1"},
            {"draft": False, "prerelease": False, "tag_name": "v0.1.0"},
        ]
        with mock.patch(
            "awgctl.releases.fetch_bytes",
            return_value=json.dumps(releases).encode(),
        ):
            self.assertEqual(discover_release_tag(channel="stable"), "v0.1.0")

    def test_signed_manifest_channel_and_tag_prerelease_must_match_request(self):
        cases = (
            ("stable", "0.1.0-beta.1", "stable"),
            ("stable", "0.1.0", "beta"),
            ("beta", "0.1.0", "beta"),
            ("beta", "0.1.0-beta.1", "stable"),
        )
        for requested, version, signed in cases:
            with self.subTest(requested=requested, version=version, signed=signed):
                with self.assertRaisesRegex(ReleaseError, "channel"):
                    parse_manifest(
                        self.manifest(version=version, channel=signed),
                        expected_platform="ubuntu-24.04-amd64",
                        expected_channel=requested,
                    )

    def test_manifest_and_artifact_must_match_platform_version_size_and_hash(self):
        artifact = b"zipapp"
        manifest = parse_manifest(self.manifest(artifact), expected_platform="ubuntu-24.04-amd64")
        self.assertEqual(manifest["installation_schema_version"], 1)
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
