import base64
import copy
import json
import os
import pathlib
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


REPO_ROOT = pathlib.Path(__file__).parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from awgctl import core
from awgctl import diagnostics
from awgctl.selftest import render_peer_configs


def key(byte: int) -> str:
    return base64.b64encode(bytes([byte]) * 32).decode("ascii")


def schema_one_config() -> dict:
    return {
        "schema_version": 1,
        "interface": "awg0",
        "subnet": "10.77.42.0/24",
        "server_address": "10.77.42.1/24",
        "endpoint": "vpn.example.com",
        "listen_port": 55323,
        "external_interface": "ens5",
        "dns": ["1.1.1.1", "1.0.0.1"],
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


def awg31_config() -> tuple[dict, bytes]:
    source = mock.Mock(randint=mock.Mock(side_effect=(9, 30, 100, 40, 20)))
    config = core.normalize_server_config(schema_one_config())
    material = bytes(range(32))
    config["obfuscation"] = core.build_russia_ios_obfuscation(
        core.HEADER_PROTECTION_KEY,
        random_source=source,
        token_bytes=lambda count: b"\xa5" * count,
        mtu=config["mtu"],
    )
    return config, material


class ServerSchemaTwoTests(unittest.TestCase):
    def test_schema_one_normalizes_to_classic_schema_two_without_changing_nine_values(self):
        legacy = schema_one_config()
        expected_values = copy.deepcopy(legacy["obfuscation"])

        normalized = core.normalize_server_config(legacy)

        self.assertEqual(normalized["schema_version"], 2)
        self.assertEqual(normalized["obfuscation"]["mode"], "classic")
        self.assertEqual(normalized["obfuscation"]["profile"]["schema_version"], 1)
        self.assertEqual(normalized["obfuscation"]["profile"]["name"], "classic-v1")
        self.assertEqual(normalized["obfuscation"]["profile"]["parameters"], expected_values)
        self.assertEqual(legacy["schema_version"], 1)
        self.assertEqual(legacy["obfuscation"], expected_values)

    def test_unknown_fields_are_rejected_at_each_server_model_layer(self):
        normalized = core.normalize_server_config(schema_one_config())
        mutations = (
            (normalized, "top-level", lambda value: value.update(mystery=True)),
            (normalized, "obfuscation", lambda value: value["obfuscation"].update(mystery=True)),
            (normalized, "profile", lambda value: value["obfuscation"]["profile"].update(mystery=True)),
            (
                normalized,
                "parameters",
                lambda value: value["obfuscation"]["profile"]["parameters"].update(mystery=1),
            ),
        )
        for original, layer, mutate in mutations:
            value = copy.deepcopy(original)
            mutate(value)
            with self.subTest(layer=layer), self.assertRaisesRegex(core.AwgctlError, "unexpected"):
                core.normalize_server_config(value)

    def test_classic_rejects_bool_integer_range_overlap_and_ambiguous_packet_lengths(self):
        cases = []
        boolean = schema_one_config()
        boolean["obfuscation"]["Jc"] = True
        cases.append(boolean)
        bad_junk_range = schema_one_config()
        bad_junk_range["obfuscation"].update(Jmin=81, Jmax=80)
        cases.append(bad_junk_range)
        overlap = schema_one_config()
        overlap["obfuscation"]["H2"] = overlap["obfuscation"]["H1"]
        cases.append(overlap)
        ambiguous_lengths = schema_one_config()
        ambiguous_lengths["obfuscation"].update(S1=36, S2=92)
        cases.append(ambiguous_lengths)

        for value in cases:
            with self.subTest(obfuscation=value["obfuscation"]), self.assertRaises(core.AwgctlError):
                core.normalize_server_config(value)

    def test_classic_rejects_awg31_only_state(self):
        normalized = core.normalize_server_config(schema_one_config())
        normalized["obfuscation"]["profile"]["header_protection_key_path"] = "/private/key"
        with self.assertRaises(core.AwgctlError):
            core.normalize_server_config(normalized)

    def test_server_contract_rejects_wrong_container_and_scalar_types_without_raw_errors(self):
        mutations = (
            ("subnet", 0),
            ("server_address", True),
            ("dns", "1.1.1.1"),
            ("dns", [1]),
            ("blocked_forward_ipv4", "0.0.0.0/8"),
            ("paths", []),
        )
        for field, replacement in mutations:
            value = schema_one_config()
            value[field] = replacement
            with self.subTest(field=field), self.assertRaises(core.AwgctlError):
                core.normalize_server_config(value)


class Awg31ModelTests(unittest.TestCase):
    def test_cps_accepts_only_exact_supported_tags_and_bounds_rendered_packet(self):
        value = "<b 0x0102><t><r 3><rc 4><rd 5>"
        self.assertEqual(core.validate_cps(value, field="I1", mtu=64), value)

        rejected = (
            "<x 1>",
            "<b 0x0>",
            "<b 0x>",
            "<t 1>",
            "<r>",
            "<r 0>",
            "<rc 1001>",
            "<rd 01>",
            " <t>",
            "<t>junk",
        )
        for candidate in rejected:
            with self.subTest(candidate=candidate), self.assertRaises(core.AwgctlError) as raised:
                core.validate_cps(candidate, field="I1", mtu=1280)
            self.assertNotIn(candidate, str(raised.exception))

        with self.assertRaisesRegex(core.AwgctlError, "MTU"):
            core.validate_cps("<r 64>", field="I1", mtu=64)

    def test_header_ranges_are_closed_nonoverlapping_and_reject_unknown_fields(self):
        self.assertEqual(core.normalize_closed_range(7, field="H1", maximum=0xFFFFFFFF), 7)
        self.assertEqual(
            core.normalize_closed_range(
                {"min": 7, "max": 9}, field="H1", maximum=0xFFFFFFFF
            ),
            {"min": 7, "max": 9},
        )
        for candidate in (
            True,
            -1,
            {"min": 9, "max": 7},
            {"min": 7, "max": 9, "step": 1},
            {"min": 7, "max": False},
        ):
            with self.subTest(candidate=candidate), self.assertRaises(core.AwgctlError):
                core.normalize_closed_range(candidate, field="H1", maximum=0xFFFFFFFF)

        with self.assertRaisesRegex(core.AwgctlError, "overlap"):
            core.validate_header_ranges(
                {"H1": {"min": 1, "max": 3}, "H2": 3, "H3": 4, "H4": 5}
            )

    def test_russia_ios_profile_uses_exact_defaults_and_dns_response_shape(self):
        class ScriptedRandom:
            def __init__(self):
                self.values = iter((9, 30, 100, 40, 20))

            def randint(self, lower, upper):
                value = next(self.values)
                self.test_case.assertLessEqual(lower, value)
                self.test_case.assertLessEqual(value, upper)
                return value

        source = ScriptedRandom()
        source.test_case = self
        random_bytes = bytes(range(1, 33))
        obfuscation = core.build_russia_ios_obfuscation(
            pathlib.Path("/opt/amneziawg/keys/server/header-protection"),
            random_source=source,
            token_bytes=lambda count: random_bytes[:count],
            mtu=1280,
        )
        profile = obfuscation["profile"]
        parameters = profile["parameters"]

        self.assertEqual(obfuscation["mode"], "awg31")
        self.assertEqual(profile["schema_version"], 1)
        self.assertEqual(profile["name"], "russia-ios-v1")
        self.assertEqual((parameters["Jc"], parameters["Jmin"], parameters["Jmax"]), (9, 8, 80))
        self.assertEqual((parameters["S1"], parameters["S2"], parameters["S3"], parameters["S4"]), (30, 100, 40, 20))
        self.assertEqual([parameters[f"H{index}"] for index in range(1, 5)], [1, 2, 3, 4])
        self.assertEqual(parameters["ContentPaddingAddition"], {"min": 0, "max": 64})
        self.assertEqual(parameters["RekeyAfterTime"], {"min": 105, "max": 135})
        self.assertEqual(parameters["RekeyTimeout"], {"min": 4, "max": 7})
        self.assertEqual(parameters["RejectAfterTime"], {"min": 165, "max": 195})
        self.assertEqual(parameters["KeepaliveTimeout"], {"min": 8, "max": 12})
        self.assertEqual(parameters["MaxHandshakeAttempts"], {"min": 15, "max": 21})
        self.assertFalse(parameters["RandomTrailers"])
        self.assertTrue(parameters["DisableCookies"])
        self.assertRegex(parameters["I1"], r"^<b 0x[0-9a-f]+>$")
        dns_packet = bytes.fromhex(parameters["I1"][5:-1])
        self.assertEqual(dns_packet[2:4], b"\x81\x80")
        self.assertEqual(dns_packet[4:8], b"\x00\x01\x00\x01")
        self.assertEqual(dns_packet[-4:], random_bytes[-4:])
        self.assertEqual([parameters[f"I{index}"] for index in range(2, 6)], [None] * 4)

    def test_awg31_requires_nonempty_i1_and_rejects_mode_incompatible_parameters(self):
        obfuscation = core.build_russia_ios_obfuscation(
            pathlib.Path("/opt/amneziawg/keys/server/header-protection"),
            random_source=mock.Mock(randint=mock.Mock(side_effect=(9, 30, 100, 40, 20))),
            token_bytes=lambda count: bytes(range(count)),
            mtu=1280,
        )
        config = core.normalize_server_config(schema_one_config())
        config["obfuscation"] = obfuscation
        core.normalize_server_config(config)

        closed_singletons = copy.deepcopy(config)
        for index in range(1, 5):
            closed_singletons["obfuscation"]["profile"]["parameters"][f"H{index}"] = {
                "min": index,
                "max": index,
            }
        normalized_singletons = core.normalize_server_config(closed_singletons)
        self.assertEqual(
            normalized_singletons["obfuscation"]["profile"]["parameters"]["H1"],
            {"min": 1, "max": 1},
        )

        missing_i1 = copy.deepcopy(config)
        missing_i1["obfuscation"]["profile"]["parameters"]["I1"] = None
        with self.assertRaisesRegex(core.AwgctlError, "I1"):
            core.normalize_server_config(missing_i1)

        unexpected = copy.deepcopy(config)
        unexpected["obfuscation"]["profile"]["parameters"]["classic_only"] = 1
        with self.assertRaisesRegex(core.AwgctlError, "unexpected"):
            core.normalize_server_config(unexpected)

        mutations = (
            ("Jc", 13),
            ("Jmin", 9),
            ("S1", 19),
            ("S3", 61),
            ("H1", {"min": 1, "max": 2}),
            ("I2", "<t>"),
            ("ContentPaddingAddition", {"min": 0, "max": 63}),
            ("RekeyAfterTime", {"min": 104, "max": 135}),
        )
        for field, replacement in mutations:
            incompatible = copy.deepcopy(config)
            incompatible["obfuscation"]["profile"]["parameters"][field] = replacement
            with self.subTest(field=field), self.assertRaises(core.AwgctlError):
                core.normalize_server_config(incompatible)

        ambiguous = copy.deepcopy(config)
        ambiguous["obfuscation"]["profile"]["parameters"].update(S1=20, S2=76)
        with self.assertRaisesRegex(core.AwgctlError, "ambiguous"):
            core.normalize_server_config(ambiguous)


class HeaderProtectionKeyTests(unittest.TestCase):
    def test_key_generation_writes_only_32_csprng_bytes_to_a_private_owned_file(self):
        material = bytes(range(32))
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "header-protection"
            fingerprint = core.write_header_protection_key(
                path,
                token_bytes=lambda count: material if count == 32 else b"",
                owner_uid=os.getuid(),
                owner_gid=os.getgid(),
            )

            self.assertEqual(path.read_bytes(), material)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(fingerprint, core.header_protection_fingerprint(material))
            self.assertRegex(fingerprint, r"^[0-9a-f]{12}$")
            self.assertNotIn(base64.b64encode(material).decode("ascii"), fingerprint)

    def test_key_generation_rejects_symlink_or_writable_parent_directory(self):
        material = b"z" * 32
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            safe = root / "safe"
            safe.mkdir(mode=0o700)
            linked = root / "linked"
            linked.symlink_to(safe, target_is_directory=True)
            writable = root / "writable"
            writable.mkdir(mode=0o700)
            writable.chmod(0o770)

            for parent in (linked, writable):
                with self.subTest(parent=parent.name), self.assertRaises(core.AwgctlError):
                    core.write_header_protection_key(
                        parent / "key",
                        token_bytes=lambda count: material,
                        owner_uid=os.getuid(),
                        owner_gid=os.getgid(),
                    )
                self.assertFalse((safe / "key").exists())

    def test_key_read_boundary_rejects_symlink_mode_owner_type_links_and_wrong_size(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            good = root / "good"
            good.write_bytes(b"k" * 32)
            good.chmod(0o600)
            expected = {"expected_uid": os.getuid(), "expected_gid": os.getgid()}
            self.assertEqual(core.read_header_protection_key(good, **expected), b"k" * 32)

            link = root / "link"
            link.symlink_to(good)
            open_mode = root / "open-mode"
            open_mode.write_bytes(b"m" * 32)
            open_mode.chmod(0o640)
            directory_key = root / "directory"
            directory_key.mkdir()
            wrong_size = root / "wrong-size"
            wrong_size.write_bytes(b"s" * 31)
            wrong_size.chmod(0o600)
            hard_link = root / "hard-link"
            os.link(good, hard_link)

            for candidate in (link, open_mode, directory_key, wrong_size, hard_link):
                with self.subTest(candidate=candidate.name), self.assertRaises(core.AwgctlError) as raised:
                    core.read_header_protection_key(candidate, **expected)
                self.assertNotIn("kkkk", str(raised.exception))

            owner_check = root / "owner-check"
            owner_check.write_bytes(b"u" * 32)
            owner_check.chmod(0o600)
            with self.assertRaisesRegex(core.AwgctlError, "ownership"):
                core.read_header_protection_key(
                    owner_check, expected_uid=os.getuid() + 1, expected_gid=os.getgid()
                )

    def test_key_reader_stays_bound_to_open_descriptor_during_path_swap(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            path = root / "key"
            opened = root / "opened"
            replacement = root / "replacement"
            original = b"o" * 32
            path.write_bytes(original)
            path.chmod(0o600)
            replacement.write_bytes(b"r" * 32)
            replacement.chmod(0o600)
            real_open = os.open
            swapped = False

            def swap_after_open(target, flags, mode=0o777, *, dir_fd=None):
                nonlocal swapped
                descriptor = real_open(target, flags, mode, dir_fd=dir_fd)
                if not swapped and os.fspath(target) == os.fspath(path):
                    swapped = True
                    path.rename(opened)
                    path.symlink_to(replacement)
                return descriptor

            with mock.patch.object(core.os, "open", side_effect=swap_after_open):
                value = core.read_header_protection_key(
                    path, expected_uid=os.getuid(), expected_gid=os.getgid()
                )
            self.assertEqual(value, original)

    def test_awg31_preparation_checks_qualification_before_generating_or_writing(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "header-protection"
            with self.assertRaisesRegex(core.AwgctlError, "unqualified"):
                core.prepare_awg31_profile(
                    key_path=path,
                    mtu=1280,
                    capability_checker=lambda: (_ for _ in ()).throw(
                        core.AwgctlError("unqualified fixture")
                    ),
                    key_token_bytes=lambda count: (_ for _ in ()).throw(
                        AssertionError("must not generate")
                    ),
                )
            self.assertFalse(path.exists())

    def test_restore_stage_accepts_matching_header_key_and_rejects_drift(self):
        config, rendered_material = awg31_config()
        with tempfile.TemporaryDirectory() as directory:
            stage = pathlib.Path(directory)
            for relative in ("config", "keys/server", "generated"):
                (stage / relative).mkdir(parents=True, exist_ok=True)
            (stage / "config/server.json").write_text(json.dumps(config), encoding="utf-8")
            (stage / "keys/server/private").write_text(key(1) + "\n", encoding="ascii")
            (stage / "keys/server/public").write_text(key(2) + "\n", encoding="ascii")
            protected = stage / "keys/server/header-protection"
            protected.write_bytes(rendered_material)
            protected.chmod(0o600)
            (stage / "generated/awg0.conf").write_text(
                core.render_server_config(
                    config,
                    key(1),
                    [],
                    header_protection_key=rendered_material,
                ),
                encoding="utf-8",
            )
            (stage / "generated/nftables.nft").write_text("managed nft fixture\n", encoding="utf-8")
            derived = subprocess.CompletedProcess(["awg", "pubkey"], 0, key(2).encode(), b"")

            with mock.patch.object(core, "run", return_value=derived), mock.patch.object(
                core, "validate_native_server"
            ), mock.patch.object(core, "validate_nftables_text"):
                self.assertEqual(core.validate_restore_stage(stage), config)
                protected.write_bytes(b"different-protected-material!!"[:32].ljust(32, b"!"))
                with self.assertRaisesRegex(core.AwgctlError, "header-protection"):
                    core.validate_restore_stage(stage)


class Awg31CapabilityTests(unittest.TestCase):
    @staticmethod
    def runner_for(tools_version: str, packaged_module_version: str):
        def runner(argv, **kwargs):
            if list(argv) == ["awg", "--version"]:
                stdout = f"amneziawg-tools v{tools_version} - https://amnezia.org\n".encode()
            elif list(argv) == ["modinfo", "-F", "version", "amneziawg"]:
                stdout = f"{packaged_module_version}\n".encode()
            else:
                raise AssertionError(f"unexpected command: {argv}")
            return subprocess.CompletedProcess(argv, 0, stdout, b"")

        return runner

    def test_exact_qualified_fixture_pair_passes_only_when_loaded_and_packaged_module_match(self):
        tools_version, module_version = core.AWG31_TEST_FIXTURE_PAIR
        result = core.require_awg31_capability(
            command_runner=self.runner_for(tools_version, module_version),
            loaded_version_reader=lambda: module_version,
            qualified_pairs={core.AWG31_TEST_FIXTURE_PAIR},
        )
        self.assertEqual(
            result,
            {
                "policy_version": 1,
                "tools_version": tools_version,
                "module_version": module_version,
                "qualified": True,
            },
        )

    def test_capability_gate_fails_closed_for_absent_unparsable_mismatch_or_unqualified(self):
        tools_version, module_version = core.AWG31_TEST_FIXTURE_PAIR

        def absent(argv, **kwargs):
            raise core.AwgctlError("required command not found: awg")

        cases = (
            (absent, lambda: module_version, {core.AWG31_TEST_FIXTURE_PAIR}),
            (
                lambda argv, **kwargs: subprocess.CompletedProcess(
                    argv,
                    1,
                    (
                        f"amneziawg-tools v{tools_version} - https://amnezia.org\n"
                        if list(argv) == ["awg", "--version"]
                        else f"{module_version}\n"
                    ).encode(),
                    b"failed",
                ),
                lambda: module_version,
                {core.AWG31_TEST_FIXTURE_PAIR},
            ),
            (
                lambda argv, **kwargs: subprocess.CompletedProcess(argv, 0, b"version-ish\n", b""),
                lambda: module_version,
                {core.AWG31_TEST_FIXTURE_PAIR},
            ),
            (
                self.runner_for(tools_version, module_version),
                lambda: "3.1.20000101",
                {core.AWG31_TEST_FIXTURE_PAIR},
            ),
            (
                self.runner_for("3.1.20260812", "3.1.20260812"),
                lambda: "3.1.20260812",
                {core.AWG31_TEST_FIXTURE_PAIR},
            ),
        )
        for runner, reader, policy in cases:
            with self.subTest(runner=runner), self.assertRaises(core.AwgctlError):
                core.require_awg31_capability(
                    command_runner=runner,
                    loaded_version_reader=reader,
                    qualified_pairs=policy,
                )

    def test_native_version_parsers_require_the_exact_expected_output(self):
        self.assertEqual(
            core.parse_awg_tools_version(
                "amneziawg-tools v3.1.20260812 - https://amnezia.org\n"
            ),
            "3.1.20260812",
        )
        self.assertEqual(core.parse_awg_module_version("3.1.20260812\n"), "3.1.20260812")
        for candidate in (
            "amneziawg-tools 3.1.20260812",
            "prefix amneziawg-tools v3.1.20260812 - https://amnezia.org",
            "3.1.20260812 extra",
            "v3.1.20260812",
        ):
            with self.subTest(candidate=candidate), self.assertRaises(core.AwgctlError):
                if "amneziawg-tools" in candidate:
                    core.parse_awg_tools_version(candidate)
                else:
                    core.parse_awg_module_version(candidate)


class Awg31RenderingTests(unittest.TestCase):
    def test_server_and_client_share_one_canonical_effective_awg31_block(self):
        config, material = awg31_config()
        server = core.render_server_config(
            config,
            key(1),
            [{"name": "kat", "address": "10.77.42.2/32", "public_key": key(2), "psk": key(3)}],
            header_protection_key=material,
        )
        client = core.render_client_config(
            config,
            key(4),
            key(3),
            key(1),
            "10.77.42.2/32",
            header_protection_key=material,
        )
        expected_lines = (
            "Jc = 9",
            "Jmin = 8",
            "Jmax = 80",
            "S1 = 30",
            "S2 = 100",
            "S3 = 40",
            "S4 = 20",
            "H1 = 1",
            "H2 = 2",
            "H3 = 3",
            "H4 = 4",
            f"I1 = {config['obfuscation']['profile']['parameters']['I1']}",
            f"HeaderProtectionKey = {base64.b64encode(material).decode('ascii')}",
            "ContentPaddingAddition = 0-64",
            "RekeyAfterTime = 105-135",
            "RekeyTimeout = 4-7",
            "RejectAfterTime = 165-195",
            "KeepaliveTimeout = 8-12",
            "MaxHandshakeAttempts = 15-21",
            "RandomTrailers = off",
            "DisableCookies = on",
        )
        for line in expected_lines:
            with self.subTest(line=line):
                self.assertEqual(server.count(line + "\n"), 1)
                self.assertEqual(client.count(line + "\n"), 1)
        for text in (server, client):
            self.assertNotRegex(text, r"(?m)^I[2-5] =")

        server_block = [line for line in server.splitlines() if line in expected_lines]
        client_block = [line for line in client.splitlines() if line in expected_lines]
        self.assertEqual(server_block, list(expected_lines))
        self.assertEqual(client_block, list(expected_lines))

    def test_renderers_require_explicit_awg31_key_and_reject_one_in_classic_mode(self):
        config, material = awg31_config()
        with self.assertRaisesRegex(core.AwgctlError, "explicit"):
            core.render_server_config(config, key(1), [])
        with self.assertRaisesRegex(core.AwgctlError, "explicit"):
            core.render_client_config(config, key(4), key(3), key(1), "10.77.42.2/32")

        classic = core.normalize_server_config(schema_one_config())
        with self.assertRaisesRegex(core.AwgctlError, "classic"):
            core.render_server_config(classic, key(1), [], header_protection_key=material)

    def test_import_accepts_only_the_awg31_directives_matching_effective_server_state(self):
        config, material = awg31_config()
        rendered = core.render_client_config(
            config,
            key(4),
            key(3),
            key(1),
            "10.77.42.2/32",
            header_protection_key=material,
        )
        imported = core.parse_import_profile(
            rendered,
            config,
            expected_server_public=key(1),
            derive_public=lambda _: key(2),
            header_protection_key=material,
        )
        self.assertEqual(imported["profile"], rendered)

        for supplied in (
            rendered.replace("S3 = 40\n", "S3 = 40\nUnknownAwg31 = 1\n"),
            rendered.replace("S3 = 40\n", "S3 = 40\nS3 = 41\n"),
        ):
            with self.subTest(), self.assertRaises(core.AwgctlError):
                core.parse_import_profile(
                    supplied,
                    config,
                    expected_server_public=key(1),
                    derive_public=lambda _: key(2),
                    header_protection_key=material,
                )

    def test_classic_import_allowlist_does_not_accept_awg31_directives(self):
        classic = schema_one_config()
        rendered = core.render_client_config(classic, key(4), key(3), key(1), "10.77.42.2/32")
        injected = rendered.replace("S2 = 92\n", "S2 = 92\nS3 = 40\n")
        with self.assertRaisesRegex(core.AwgctlError, "unsupported"):
            core.parse_import_profile(
                injected,
                classic,
                expected_server_public=key(1),
                derive_public=lambda _: key(2),
            )

    def test_namespace_renderer_supports_awg31_without_querying_or_rendering_unset_i_fields(self):
        config, material = awg31_config()
        server, client = render_peer_configs(
            server_private=key(1),
            server_public=key(2),
            client_private=key(3),
            client_public=key(4),
            psk=key(5),
            obfuscation=config["obfuscation"],
            header_protection_key=material,
            port=51871,
        )
        for text in (server, client):
            self.assertIn("HeaderProtectionKey =", text)
            self.assertIn("I1 = <b 0x", text)
            self.assertNotRegex(text, r"(?m)^I[2-5] =")
        self.assertNotIn("show", server + client)

    def test_status_metadata_and_diagnostics_expose_only_twelve_hex_key_fingerprint(self):
        config, material = awg31_config()
        serialized_state = json.dumps(config, sort_keys=True)
        self.assertNotIn(base64.b64encode(material).decode("ascii"), serialized_state)
        self.assertNotIn(material.hex(), serialized_state)
        with mock.patch.object(core, "read_header_protection_key", return_value=material):
            status = core.obfuscation_status(config)
        encoded = base64.b64encode(material).decode("ascii")
        self.assertEqual(
            status,
            {
                "mode": "awg31",
                "profile": "russia-ios-v1",
                "header_protection_key_fingerprint": core.header_protection_fingerprint(material),
            },
        )
        self.assertNotIn(encoded, repr(status))

        redacted = diagnostics.redact_awg_config(f"HeaderProtectionKey = {encoded}\n")
        self.assertEqual(
            redacted,
            "HeaderProtectionKey = "
            f"[redacted sha256:{core.header_protection_fingerprint(material)}]\n",
        )
        self.assertNotIn(encoded, redacted)

    def test_classic_status_does_not_inspect_awg31_capability_or_key(self):
        config = core.normalize_server_config(schema_one_config())
        with (
            mock.patch.object(core, "require_awg31_capability", side_effect=AssertionError("no gate")),
            mock.patch.object(core, "read_header_protection_key", side_effect=AssertionError("no key")),
        ):
            self.assertEqual(
                core.obfuscation_status(config),
                {"mode": "classic", "profile": "classic-v1"},
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
