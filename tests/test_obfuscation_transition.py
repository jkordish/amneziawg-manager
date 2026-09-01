import contextlib
import copy
import argparse
import json
import datetime as dt
import subprocess
import io
import pathlib
import sys
import tempfile
import unittest
from unittest import mock
import base64


REPO_ROOT = pathlib.Path(__file__).parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from awgctl import core


TRANSACTION_ID = "0123456789abcdef0123456789abcdef"


def key(byte):
    return base64.b64encode(bytes([byte]) * 32).decode("ascii")


@contextlib.contextmanager
def patched_layout(root):
    values = {
        "ROOT": root,
        "CONFIG_FILE": root / "config/server.json",
        "INSTALLATION_CONFIG": root / "config/installation.json",
        "SERVER_PRIVATE": root / "keys/server/private",
        "SERVER_PUBLIC": root / "keys/server/public",
        "HEADER_PROTECTION_KEY": root / "keys/server/header-protection",
        "CLIENT_KEYS": root / "keys/clients",
        "CLIENTS": root / "clients",
        "REVOKED": root / "revoked",
        "GENERATED": root / "generated",
        "GENERATED_CONFIG": root / "generated/awg0.conf",
        "GENERATED_NFT": root / "generated/nftables.nft",
        "BACKUPS": root / "backups",
        "TRANSITIONS": root / "transitions",
        "PENDING_TRANSITIONS": root / "pending/obfuscation",
        "TRANSITION_FILE": root / "transitions/obfuscation.json",
        "TRANSITION_OUTCOME_FILE": root / "transitions/obfuscation-outcome.json",
        "RUNTIME_CONFIG": root / "runtime/awg0.conf",
        "LOCK_FILE": root / "run/awgctl.lock",
    }
    with mock.patch.multiple(core, **values):
        yield values


def classic_state():
    config = {
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
    config = core.normalize_server_config(config)
    timestamp = "2026-09-01T09:00:00Z"
    metadata = {
        "schema_version": 3,
        "name": "kat-iphone",
        "status": "active",
        "management": "managed",
        "address": "10.77.42.2/32",
        "public_key": key(3),
        "public_key_fingerprint": core.fingerprint(key(3)),
        "use_psk": True,
        "created_at": timestamp,
        "updated_at": timestamp,
        "owner": "Kat",
        "device": "iPhone",
        "expires": None,
        "profile_revision": 3,
        "profile_generated_at": timestamp,
        "profile_change_reason": "created",
        "distribution_status": "distributed",
        "distributed_at": timestamp,
    }
    client = {**metadata, "private_key": key(4), "psk": key(5)}
    core.atomic_json(core.CONFIG_FILE, config, 0o600)
    core.atomic_write(core.SERVER_PRIVATE, key(1) + "\n", 0o600)
    core.atomic_write(core.SERVER_PUBLIC, key(2) + "\n", 0o600)
    core.atomic_json(core.CLIENTS / "kat-iphone/metadata.json", metadata, 0o600)
    core.atomic_write(core.CLIENT_KEYS / "kat-iphone/private", key(4) + "\n", 0o600)
    core.atomic_write(core.CLIENT_KEYS / "kat-iphone/public", key(3) + "\n", 0o600)
    core.atomic_write(core.CLIENT_KEYS / "kat-iphone/psk", key(5) + "\n", 0o600)
    profile = core.render_client_config(config, key(4), key(5), key(2), "10.77.42.2/32")
    core.atomic_write(core.CLIENTS / "kat-iphone/kat-iphone.conf", profile, 0o600)
    core.atomic_write(core.CLIENTS / "kat-iphone/kat-iphone.png", b"classic qr", 0o600)
    server = core.render_server_config(config, key(1), [client])
    core.atomic_write(core.GENERATED_CONFIG, server, 0o600)
    core.atomic_write(core.RUNTIME_CONFIG, server, 0o600)
    core.atomic_write(core.GENERATED_NFT, "managed nft\n", 0o600)
    return config, client


def prepared_state():
    config, client = classic_state()
    pending_root = core.PENDING_TRANSITIONS / TRANSACTION_ID
    (pending_root / "clients/kat-iphone").mkdir(parents=True, mode=0o700)
    header_material = b"\xb6" * 32
    core.atomic_write(pending_root / "header-protection", header_material, 0o600)
    new_config = copy.deepcopy(config)
    new_config["listen_port"] = 4242
    new_config["obfuscation"] = core.build_russia_ios_obfuscation(
        core.HEADER_PROTECTION_KEY,
        random_source=mock.Mock(
            randint=mock.Mock(side_effect=[9, 30, 100, 40, 20])
        ),
        token_bytes=lambda count: b"\xa5" * count,
        mtu=1280,
    )
    new_config = core.validate_server_config(new_config)
    server = core.render_server_config(
        new_config,
        key(1),
        [client],
        now=dt.datetime(2026, 9, 1, 10, 0, tzinfo=dt.timezone.utc),
        header_protection_key=header_material,
    )
    profile = core.render_client_config(
        new_config,
        key(4),
        key(5),
        key(2),
        "10.77.42.2/32",
        header_protection_key=header_material,
    )
    core.atomic_json(pending_root / "server.json", new_config, 0o600)
    core.atomic_write(pending_root / "awg0.conf", server, 0o600)
    core.atomic_write(
        pending_root / "clients/kat-iphone/kat-iphone.conf", profile, 0o600
    )
    core.atomic_write(
        pending_root / "clients/kat-iphone/kat-iphone.png", b"pending qr", 0o600
    )
    backup = core.BACKUPS / "20260901T100000Z"
    backup.mkdir(parents=True, mode=0o700)
    document = transition_document(pending_base=core.PENDING_TRANSITIONS)
    document["prestate_sha256"] = "ab" * 32
    document["pending_sha256"] = core.pending_transition_artifact_digest(pending_root)
    core.compare_and_swap_transition(
        document,
        expected_transaction_id=None,
        expected_state=None,
    )
    return document, config, client, new_config, server, profile, backup


def active_state():
    document, classic, client, awg31, server, profile, backup = prepared_state()
    core.atomic_json(core.CONFIG_FILE, awg31, 0o600)
    core.atomic_write(core.HEADER_PROTECTION_KEY, b"\xb6" * 32, 0o600)
    core.atomic_write(core.GENERATED_CONFIG, server, 0o600)
    core.atomic_write(core.RUNTIME_CONFIG, server, 0o600)
    core.atomic_write(core.CLIENTS / "kat-iphone/kat-iphone.conf", profile, 0o600)
    core.atomic_write(
        core.CLIENTS / "kat-iphone/kat-iphone.png", b"pending qr", 0o600
    )
    active = copy.deepcopy(document)
    active.update(
        state="active",
        activated_at="2026-09-01T10:01:00Z",
        deadline_at="2026-09-01T10:11:00Z",
        pre_rx=100,
        pre_tx=200,
    )
    core.compare_and_swap_transition(
        active,
        expected_transaction_id=TRANSACTION_ID,
        expected_state="prepared",
    )
    return active, classic, client, awg31, server, profile, backup


def transition_document(state="prepared", pending_base=None):
    pending_base = pending_base or pathlib.Path("/opt/amneziawg/pending/obfuscation")
    root = pending_base / TRANSACTION_ID
    activated = "2026-09-01T10:01:00Z" if state == "active" else None
    deadline = "2026-09-01T10:11:00Z" if state == "active" else None
    counter = 12 if state == "active" else None
    return {
        "schema_version": 1,
        "transaction_id": TRANSACTION_ID,
        "state": state,
        "mode": "awg31",
        "profile_name": "russia-ios-v1",
        "client_name": "kat-iphone",
        "old_port": 55323,
        "new_port": 4242,
        "backup_name": "20260901T100000Z",
        "pending": {
            "root": str(root),
            "server_state": str(root / "server.json"),
            "server_config": str(root / "awg0.conf"),
            "header_key": str(root / "header-protection"),
            "profiles": [
                {
                    "name": "kat-iphone",
                    "config": str(root / "clients/kat-iphone/kat-iphone.conf"),
                    "qr": str(root / "clients/kat-iphone/kat-iphone.png"),
                    "current_revision": 3,
                }
            ],
        },
        "ingress_boundary": "lightsail",
        "capability": {
            "policy_version": 1,
            "tools_version": "3.1.20990101",
            "module_version": "3.1.20990102",
            "qualified": True,
        },
        "prepared_at": "2026-09-01T10:00:00Z",
        "activated_at": activated,
        "deadline_at": deadline,
        "pre_rx": counter,
        "pre_tx": counter + 1 if counter is not None else None,
        "prestate_sha256": "ab" * 32,
        "pending_sha256": "cd" * 32,
    }


class ObfuscationGrammarTests(unittest.TestCase):
    def test_public_and_internal_transition_grammars_are_separated(self):
        parser = core.build_parser()
        try:
            prepare = parser.parse_args(
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
        except SystemExit:
            self.fail("public obfuscation prepare grammar is missing")
        self.assertEqual(prepare.obfuscation_command, "prepare")
        self.assertEqual(prepare.mode, "awg31")
        self.assertEqual(prepare.profile, "russia-ios-v1")
        self.assertEqual(prepare.client, "kat-iphone")
        self.assertTrue(prepare.dry_run)
        self.assertTrue(prepare.json)

        activate = parser.parse_args(
            [
                "obfuscation",
                "activate",
                "0123456789abcdef0123456789abcdef",
                "--ingress-ready",
                "--timeout",
                "10m",
            ]
        )
        self.assertEqual(activate.transaction_id, "0123456789abcdef0123456789abcdef")
        self.assertTrue(activate.ingress_ready)
        self.assertEqual(activate.timeout, "10m")
        for command in ("confirm", "rollback"):
            parsed = parser.parse_args(
                ["obfuscation", command, "0123456789abcdef0123456789abcdef"]
            )
            self.assertEqual(parsed.obfuscation_command, command)
            self.assertEqual(parsed.transaction_id, "0123456789abcdef0123456789abcdef")
        self.assertEqual(
            parser.parse_args(["obfuscation", "show"]).obfuscation_command,
            "show",
        )
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            parser.parse_args(["_obfuscation-timeout", "0123456789abcdef0123456789abcdef"])

        internal = core.build_parser(entrypoint="internal")
        timeout = internal.parse_args(
            ["_obfuscation-timeout", "0123456789abcdef0123456789abcdef"]
        )
        self.assertEqual(timeout.command, "_obfuscation-timeout")
        self.assertEqual(timeout.transaction_id, "0123456789abcdef0123456789abcdef")
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            internal.parse_args(["obfuscation", "show"])

    def test_transaction_ids_are_bounded_at_every_parser_and_handlers_dispatch(self):
        parser = core.build_parser()
        internal = core.build_parser(entrypoint="internal")
        for invalid in ("a" * 31, "A" * 32, "0" * 33, "../" + "0" * 29):
            with self.subTest(invalid=invalid):
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    parser.parse_args(["obfuscation", "rollback", invalid])
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    internal.parse_args(["_obfuscation-timeout", invalid])

        public_args = parser.parse_args(["obfuscation", "show"])
        internal_args = internal.parse_args(["_obfuscation-timeout", TRANSACTION_ID])
        with (
            mock.patch.object(core, "require_root"),
            mock.patch.object(core, "cmd_obfuscation_show", return_value=27) as show,
            mock.patch.object(core, "cmd_obfuscation_timeout", return_value=28) as timeout,
        ):
            try:
                public_result = core.dispatch(public_args)
                internal_result = core.dispatch(internal_args)
            except core.AwgctlError as exc:
                self.fail(f"obfuscation dispatch is incomplete: {exc}")
        self.assertEqual((public_result, internal_result), (27, 28))
        show.assert_called_once_with(public_args)
        timeout.assert_called_once_with(internal_args)


class TransitionDocumentTests(unittest.TestCase):
    def test_completed_outcome_is_strict_bounded_and_nonsecret(self):
        outcome = {
            "schema_version": 1,
            "transaction_id": TRANSACTION_ID,
            "outcome": "rolled_back",
            "reason": "operator",
            "completed_at": "2026-09-01T10:03:00Z",
            "client_name": "kat-iphone",
            "profile_name": "russia-ios-v1",
            "old_port": 55323,
            "new_port": 4242,
        }
        self.assertEqual(core.normalize_transition_outcome(outcome), outcome)
        invalid = copy.deepcopy(outcome)
        invalid["new_port"] = 10000
        with self.assertRaises(core.AwgctlError):
            core.normalize_transition_outcome(invalid)
        unknown = copy.deepcopy(outcome)
        unknown["pending_secret"] = "/secret"
        with self.assertRaises(core.AwgctlError):
            core.normalize_transition_outcome(unknown)

    def test_transition_document_is_strict_and_paths_are_fixed(self):
        self.assertTrue(
            hasattr(core, "normalize_transition_document"),
            "strict transition document validator is missing",
        )
        prepared = transition_document()
        try:
            normalized_prepared = core.normalize_transition_document(prepared)
        except core.AwgctlError as exc:
            self.fail(f"strict pending artifact digest is unsupported: {exc}")
        self.assertEqual(normalized_prepared, prepared)
        active = transition_document("active")
        self.assertEqual(core.normalize_transition_document(active), active)

        invalid_documents = []
        unknown = copy.deepcopy(prepared)
        unknown["unexpected"] = "accepted"
        invalid_documents.append(unknown)
        boolean_port = copy.deepcopy(prepared)
        boolean_port["new_port"] = True
        invalid_documents.append(boolean_port)
        inconsistent = copy.deepcopy(prepared)
        inconsistent["pre_rx"] = 0
        invalid_documents.append(inconsistent)
        escaped = copy.deepcopy(prepared)
        escaped["pending"]["header_key"] = "/tmp/header-protection"
        invalid_documents.append(escaped)
        traversal = copy.deepcopy(prepared)
        traversal["pending"]["profiles"][0]["config"] = str(
            pathlib.Path(prepared["pending"]["root"]) / "clients/kat-iphone/../../stolen"
        )
        invalid_documents.append(traversal)
        stale_id = copy.deepcopy(prepared)
        stale_id["transaction_id"] = "A" * 32
        invalid_documents.append(stale_id)
        for document in invalid_documents:
            with self.subTest(document=document), self.assertRaises(core.AwgctlError):
                core.normalize_transition_document(document)

    def test_transition_file_is_protected_and_compare_and_swap_rejects_stale_state(self):
        self.assertTrue(
            hasattr(core, "compare_and_swap_transition"),
            "transition compare-and-swap storage is missing",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            transitions = root / "transitions"
            pending = root / "pending/obfuscation"
            transition_file = transitions / "obfuscation.json"
            outcome_file = transitions / "outcome.json"
            prepared = transition_document(pending_base=pending)
            active = transition_document("active", pending_base=pending)
            with (
                mock.patch.object(core, "TRANSITIONS", transitions),
                mock.patch.object(core, "PENDING_TRANSITIONS", pending),
                mock.patch.object(core, "TRANSITION_FILE", transition_file),
                mock.patch.object(core, "TRANSITION_OUTCOME_FILE", outcome_file),
            ):
                core.compare_and_swap_transition(
                    prepared,
                    expected_transaction_id=None,
                    expected_state=None,
                )
                self.assertEqual(core.load_transition_document(), prepared)
                changed_prepared = copy.deepcopy(prepared)
                changed_prepared["prestate_sha256"] = "ef" * 32
                core.atomic_json(transition_file, changed_prepared, 0o600)
                with self.assertRaises(core.AwgctlError):
                    core.compare_and_swap_transition(
                        active,
                        expected_transaction_id=TRANSACTION_ID,
                        expected_state="prepared",
                    )
                self.assertEqual(core.load_transition_document(), changed_prepared)
                core.atomic_json(transition_file, prepared, 0o600)
                core.compare_and_swap_transition(
                    active,
                    expected_transaction_id=TRANSACTION_ID,
                    expected_state="prepared",
                )
                self.assertEqual(core.load_transition_document(), active)
                with self.assertRaises(core.AwgctlError):
                    core.compare_and_swap_transition(
                        prepared,
                        expected_transaction_id="fedcba9876543210fedcba9876543210",
                        expected_state="active",
                    )
                self.assertEqual(core.load_transition_document(), active)

                transition_file.chmod(0o644)
                with self.assertRaises(core.AwgctlError):
                    core.load_transition_document()
                transition_file.chmod(0o600)
                real = transitions / "real.json"
                transition_file.replace(real)
                transition_file.symlink_to(real)
                with self.assertRaises(core.AwgctlError):
                    core.load_transition_document()


class TransitionPortTests(unittest.TestCase):
    def test_port_selection_uses_unbiased_sampling_and_rejects_every_conflict_class(self):
        self.assertTrue(
            hasattr(core, "select_transition_port"),
            "transition UDP port selector is missing",
        )
        draws = mock.Mock(side_effect=[8976, 0, 1, 2, 3, 4])
        listening_checks = []
        bind_checks = []

        def listening(port):
            listening_checks.append(port)
            return port == 1026

        def bind_available(port):
            bind_checks.append(port)
            return port != 1027

        selected = core.select_transition_port(
            current_port=1024,
            managed_ports={1025},
            randbits=draws,
            listening_checker=listening,
            bind_checker=bind_available,
        )

        self.assertEqual(selected, 1028)
        self.assertEqual(draws.call_args_list, [mock.call(14)] * 6)
        self.assertEqual(listening_checks, [1026, 1027, 1028])
        self.assertEqual(bind_checks, [1027, 1028])


class ObfuscationPrepareTests(unittest.TestCase):
    def test_prepare_dry_run_performs_nonsecret_gates_without_any_mutation_or_randomness(self):
        self.assertTrue(
            hasattr(core, "cmd_obfuscation_prepare"),
            "obfuscation prepare handler is missing",
        )
        config = {
            "interface": "awg0",
            "listen_port": 55323,
            "obfuscation": {"mode": "classic", "profile": {"name": "classic-v1"}},
        }
        client = {
            "name": "kat-iphone",
            "status": "active",
            "management": "managed",
            "expires": None,
        }
        capability = {
            "policy_version": 1,
            "tools_version": "3.1.20990101",
            "module_version": "3.1.20990102",
            "qualified": True,
        }
        args = argparse.Namespace(
            mode="awg31",
            profile="russia-ios-v1",
            client="kat-iphone",
            dry_run=True,
            json=True,
        )
        output = io.StringIO()
        with (
            mock.patch.object(core, "load_config", return_value=config),
            mock.patch.object(core, "load_clients", return_value=[client]),
            mock.patch.object(core, "load_transition_document", return_value=None),
            mock.patch.object(core, "ingress_boundary_attestation", return_value="lightsail"),
            mock.patch.object(core, "require_awg31_capability", return_value=capability) as gate,
            mock.patch.object(
                core, "mutation_lock", side_effect=AssertionError("dry-run must not create a lock")
            ),
            mock.patch.object(
                core, "select_transition_port", side_effect=AssertionError("dry-run must not select a port")
            ),
            mock.patch.object(
                core, "create_backup", side_effect=AssertionError("dry-run must not create a backup")
            ),
            mock.patch.object(
                core, "write_header_protection_key", side_effect=AssertionError("dry-run must not create a key")
            ),
            mock.patch.object(
                core, "atomic_json", side_effect=AssertionError("dry-run must not write state")
            ),
            contextlib.redirect_stdout(output),
        ):
            result = core.cmd_obfuscation_prepare(args)

        self.assertEqual(result, 0)
        gate.assert_called_once_with()
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["command"], "obfuscation prepare")
        self.assertEqual(
            payload["data"],
            {
                "client": "kat-iphone",
                "dry_run": True,
                "ingress_boundary": "lightsail",
                "mode": "awg31",
                "planned_checks": [
                    "exact managed client eligibility",
                    "qualified tools/module pair",
                    "persisted ingress attestation",
                    "unused UDP port 1024..9999 at execution",
                    "complete managed profile set",
                ],
                "profile": "russia-ios-v1",
                "required_ingress": {
                    "port": "selected-at-execution",
                    "protocol": "UDP",
                    "source": "0.0.0.0/0",
                    "type": "Custom",
                },
                "runtime_action": "none",
            },
        )

    def test_prepare_gates_before_entropy_and_writes_only_complete_pending_artifacts(self):
        class PrepareClock(dt.datetime):
            calls = 0

            @classmethod
            def now(cls, tz=None):
                cls.calls += 1
                return cls(2026, 9, 1, 10, 0, tzinfo=dt.timezone.utc)

        events = []
        capability = {
            "policy_version": 1,
            "tools_version": "3.1.20990101",
            "module_version": "3.1.20990102",
            "qualified": True,
        }
        args = argparse.Namespace(
            mode="awg31",
            profile="russia-ios-v1",
            client="kat-iphone",
            dry_run=False,
            json=True,
        )
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            with patched_layout(root):
                classic_state()
                active_paths = [
                    core.CONFIG_FILE,
                    core.GENERATED_CONFIG,
                    core.RUNTIME_CONFIG,
                    core.CLIENTS / "kat-iphone/metadata.json",
                    core.CLIENTS / "kat-iphone/kat-iphone.conf",
                    core.CLIENTS / "kat-iphone/kat-iphone.png",
                ]
                active_before = {path: path.read_bytes() for path in active_paths}
                backup = core.BACKUPS / "20260901T100000Z"
                original_header_writer = core.write_header_protection_key
                original_builder = core.build_russia_ios_obfuscation

                def gate():
                    events.append("capability")
                    return capability

                def token_hex(count):
                    events.append("transaction entropy")
                    self.assertEqual(count, 16)
                    return TRANSACTION_ID

                def choose_port(**kwargs):
                    events.append("port entropy")
                    self.assertEqual(kwargs["current_port"], 55323)
                    return 4242

                def create_backup():
                    events.append("backup write")
                    backup.mkdir(parents=True, mode=0o700)
                    return backup

                def build_profile(*args, **kwargs):
                    events.append("profile entropy")
                    kwargs["random_source"] = mock.Mock(
                        randint=mock.Mock(side_effect=[9, 30, 100, 40, 20])
                    )
                    kwargs["token_bytes"] = lambda count: b"\xa5" * count
                    return original_builder(*args, **kwargs)

                def write_header(path, **kwargs):
                    events.append("key write")
                    return original_header_writer(
                        path,
                        token_bytes=lambda count: b"\xb6" * count,
                        owner_uid=1000,
                        owner_gid=1000,
                    )

                def write_qr(profile, path):
                    core.atomic_write(path, b"pending qr", 0o600)

                @contextlib.contextmanager
                def locked():
                    self.assertEqual(
                        PrepareClock.calls,
                        0,
                        "execution clock must be captured only after acquiring the lock",
                    )
                    yield

                with (
                    mock.patch.object(core.dt, "datetime", PrepareClock),
                    mock.patch.object(core, "mutation_lock", side_effect=locked),
                    mock.patch.object(core, "ensure_no_drift") as drift,
                    mock.patch.object(core, "ingress_boundary_attestation", return_value="lightsail"),
                    mock.patch.object(core, "require_awg31_capability", side_effect=gate),
                    mock.patch.object(core.secrets, "token_hex", side_effect=token_hex),
                    mock.patch.object(core, "select_transition_port", side_effect=choose_port),
                    mock.patch.object(core, "create_backup", side_effect=create_backup),
                    mock.patch.object(core, "build_russia_ios_obfuscation", side_effect=build_profile),
                    mock.patch.object(core, "write_header_protection_key", side_effect=write_header),
                    mock.patch.object(core, "generate_qr", side_effect=write_qr),
                    mock.patch.object(core, "validate_native_server"),
                    mock.patch.object(
                        core,
                        "managed_transition_prestate_digest",
                        return_value="ab" * 32,
                        create=True,
                    ),
                    mock.patch.object(core, "audit"),
                    contextlib.redirect_stdout(output),
                ):
                    try:
                        result = core.cmd_obfuscation_prepare(args)
                    except core.AwgctlError as exc:
                        self.fail(f"prepare execution is incomplete: {exc}")

                self.assertEqual(result, 0)
                self.assertEqual(PrepareClock.calls, 1)
                drift.assert_called_once_with(
                    now=dt.datetime(2026, 9, 1, 10, 0, tzinfo=dt.timezone.utc)
                )
                self.assertEqual(events[0], "capability")
                self.assertEqual(
                    {path: path.read_bytes() for path in active_paths},
                    active_before,
                )
                self.assertFalse(core.HEADER_PROTECTION_KEY.exists())
                document = core.load_transition_document()
                self.assertEqual(document["transaction_id"], TRANSACTION_ID)
                self.assertEqual(document["new_port"], 4242)
                self.assertEqual(
                    [item["name"] for item in document["pending"]["profiles"]],
                    ["kat-iphone"],
                )
                pending_root = pathlib.Path(document["pending"]["root"])
                self.assertTrue((pending_root / "server.json").is_file())
                self.assertTrue((pending_root / "awg0.conf").is_file())
                self.assertTrue((pending_root / "header-protection").is_file())
                self.assertTrue(
                    (pending_root / "clients/kat-iphone/kat-iphone.conf").is_file()
                )
                payload = json.loads(output.getvalue())
                rendered = json.dumps(payload, sort_keys=True)
                self.assertNotIn(key(1), rendered)
                self.assertNotIn(key(4), rendered)
                self.assertNotIn("I1", rendered)
                self.assertEqual(payload["data"]["required_ingress"]["port"], 4242)


class ObfuscationActivateTests(unittest.TestCase):
    def test_activate_installs_once_verifies_and_schedules_exact_root_timeout(self):
        self.assertTrue(
            hasattr(core, "cmd_obfuscation_activate"),
            "obfuscation activate handler is missing",
        )

        class ActivationClock(dt.datetime):
            calls = 0

            @classmethod
            def now(cls, tz=None):
                cls.calls += 1
                return cls(2026, 9, 1, 10, 1, tzinfo=dt.timezone.utc)

        args = argparse.Namespace(
            transaction_id=TRANSACTION_ID,
            ingress_ready=True,
            timeout="10m",
            json=True,
        )
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            with patched_layout(root):
                document, classic, client, awg31, server, profile, backup = prepared_state()
                metadata_path = core.CLIENTS / "kat-iphone/metadata.json"
                metadata_before = metadata_path.read_bytes()
                run_calls = []
                reloads = []

                def commit(text, *, runtime_action):
                    self.assertEqual(text, server)
                    self.assertEqual(runtime_action, "reload")
                    reloads.append("reload")
                    core.atomic_write(core.GENERATED_CONFIG, text, 0o600)
                    core.atomic_write(core.RUNTIME_CONFIG, text, 0o600)
                    return True

                def runner(argv, **kwargs):
                    run_calls.append((list(argv), kwargs))
                    return subprocess.CompletedProcess(argv, 0, b"", b"")

                patches = [
                    mock.patch.object(core.dt, "datetime", ActivationClock),
                    mock.patch.object(core, "mutation_lock", return_value=contextlib.nullcontext()),
                    mock.patch.object(
                        core,
                        "verify_transition_backup_precondition",
                        return_value=backup,
                    ),
                    mock.patch.object(core, "managed_transition_prestate_digest", return_value="ab" * 32),
                    mock.patch.object(core, "require_awg31_capability", return_value=document["capability"]),
                    mock.patch.object(core, "ingress_boundary_attestation", return_value="lightsail"),
                    mock.patch.object(core, "udp_port_is_listening", return_value=False),
                    mock.patch.object(core, "udp_port_bind_available", return_value=True),
                    mock.patch.object(core, "validate_native_server"),
                    mock.patch.object(core, "is_service_active", return_value=True),
                    mock.patch.object(
                        core,
                        "transfer_map",
                        return_value={key(3): (100, 200)},
                        create=True,
                    ),
                    mock.patch.object(core, "commit_server_config", side_effect=commit),
                    mock.patch.object(
                        core,
                        "safe_awg_query",
                        side_effect=lambda interface, field: {
                            "public-key": key(2),
                            "listen-port": "4242",
                        }[field],
                    ),
                    mock.patch.object(core, "live_peers", return_value={key(3)}),
                    mock.patch.object(core, "run", side_effect=runner),
                    mock.patch.object(core, "audit"),
                    contextlib.redirect_stdout(output),
                ]
                with contextlib.ExitStack() as stack:
                    for patcher in patches:
                        stack.enter_context(patcher)
                    try:
                        result = core.cmd_obfuscation_activate(args)
                    except core.AwgctlError as exc:
                        self.fail(f"activation is incomplete: {exc}")

                self.assertEqual(result, 0)
                self.assertEqual(ActivationClock.calls, 1)
                self.assertEqual(reloads, ["reload"])
                active = core.load_transition_document()
                self.assertEqual(active["state"], "active")
                self.assertEqual(active["activated_at"], "2026-09-01T10:01:00Z")
                self.assertEqual(active["deadline_at"], "2026-09-01T10:11:00Z")
                self.assertEqual((active["pre_rx"], active["pre_tx"]), (100, 200))
                self.assertEqual(core.load_config()["obfuscation"]["mode"], "awg31")
                self.assertEqual(core.HEADER_PROTECTION_KEY.read_bytes(), b"\xb6" * 32)
                self.assertEqual(
                    (core.CLIENTS / "kat-iphone/kat-iphone.conf").read_text(), profile
                )
                self.assertEqual(metadata_path.read_bytes(), metadata_before)
                self.assertEqual(
                    run_calls,
                    [
                        (
                            [
                                "systemd-run",
                                "--quiet",
                                "--collect",
                                "--unit",
                                f"awgctl-obfuscation-rollback-{TRANSACTION_ID}",
                                "--on-active=10m",
                                str(core.INTERNAL_ENTRYPOINT),
                                "_obfuscation-timeout",
                                TRANSACTION_ID,
                            ],
                            {"timeout": 15},
                        )
                    ],
                )
                payload = json.loads(output.getvalue())
                self.assertEqual(payload["data"]["deadline_at"], "2026-09-01T10:11:00Z")
                self.assertNotIn(key(3), json.dumps(payload))

    def test_timer_failure_synchronously_restores_classic_and_records_rolled_back_outcome(self):
        class ActivationClock(dt.datetime):
            @classmethod
            def now(cls, tz=None):
                return cls(2026, 9, 1, 10, 1, tzinfo=dt.timezone.utc)

        args = argparse.Namespace(
            transaction_id=TRANSACTION_ID,
            ingress_ready=True,
            timeout="10m",
            json=True,
        )
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            with patched_layout(root):
                document, classic, client, awg31, server, profile, backup = prepared_state()
                classic_server = core.GENERATED_CONFIG.read_bytes()
                classic_profile = (core.CLIENTS / "kat-iphone/kat-iphone.conf").read_bytes()
                systemd_calls = []

                def commit(text, *, runtime_action):
                    core.atomic_write(core.GENERATED_CONFIG, text, 0o600)
                    core.atomic_write(core.RUNTIME_CONFIG, text, 0o600)
                    return True

                def runner(argv, **kwargs):
                    systemd_calls.append(list(argv))
                    if argv[0] == "systemd-run":
                        raise core.AwgctlError("timer creation failed")
                    if argv[:2] == ["systemctl", "stop"]:
                        return subprocess.CompletedProcess(argv, 0, b"", b"")
                    if argv[:3] == ["systemctl", "is-active", "--quiet"]:
                        return subprocess.CompletedProcess(argv, 3, b"", b"")
                    raise AssertionError(f"unexpected command: {argv}")

                def restore(backup_name, expected_document, *, now):
                    self.assertEqual(backup_name, document["backup_name"])
                    self.assertEqual(expected_document["transaction_id"], TRANSACTION_ID)
                    core.atomic_json(core.CONFIG_FILE, classic, 0o600)
                    with contextlib.suppress(FileNotFoundError):
                        core.HEADER_PROTECTION_KEY.unlink()
                    core.atomic_write(core.GENERATED_CONFIG, classic_server, 0o600)
                    core.atomic_write(core.RUNTIME_CONFIG, classic_server, 0o600)
                    core.atomic_write(
                        core.CLIENTS / "kat-iphone/kat-iphone.conf",
                        classic_profile,
                        0o600,
                    )

                patches = [
                    mock.patch.object(core.dt, "datetime", ActivationClock),
                    mock.patch.object(core, "mutation_lock", return_value=contextlib.nullcontext()),
                    mock.patch.object(
                        core, "verify_transition_backup_precondition", return_value=backup
                    ),
                    mock.patch.object(core, "managed_transition_prestate_digest", return_value="ab" * 32),
                    mock.patch.object(core, "require_awg31_capability", return_value=document["capability"]),
                    mock.patch.object(core, "ingress_boundary_attestation", return_value="lightsail"),
                    mock.patch.object(core, "udp_port_is_listening", return_value=False),
                    mock.patch.object(core, "udp_port_bind_available", return_value=True),
                    mock.patch.object(core, "validate_native_server"),
                    mock.patch.object(core, "is_service_active", return_value=True),
                    mock.patch.object(core, "transfer_map", return_value={key(3): (100, 200)}),
                    mock.patch.object(core, "commit_server_config", side_effect=commit),
                    mock.patch.object(
                        core,
                        "safe_awg_query",
                        side_effect=lambda interface, field: {
                            "public-key": key(2),
                            "listen-port": "4242",
                        }[field],
                    ),
                    mock.patch.object(core, "live_peers", return_value={key(3)}),
                    mock.patch.object(core, "run", side_effect=runner),
                    mock.patch.object(
                        core,
                        "restore_obfuscation_backup",
                        side_effect=restore,
                        create=True,
                    ),
                    mock.patch.object(core, "audit"),
                ]
                with contextlib.ExitStack() as stack:
                    for patcher in patches:
                        stack.enter_context(patcher)
                    with self.assertRaises(core.AwgctlError):
                        core.cmd_obfuscation_activate(args)

                self.assertEqual(core.load_config()["obfuscation"]["mode"], "classic")
                self.assertEqual(core.GENERATED_CONFIG.read_bytes(), classic_server)
                self.assertIsNone(core.load_transition_document(required=False))
                self.assertFalse(pathlib.Path(document["pending"]["root"]).exists())
                outcome = core.load_transition_outcome()
                self.assertEqual(outcome["transaction_id"], TRANSACTION_ID)
                self.assertEqual(outcome["outcome"], "rolled_back")
                self.assertEqual(outcome["reason"], "activation-failed")
                self.assertTrue(
                    any(call[:2] == ["systemctl", "stop"] for call in systemd_calls)
                )

    def test_pending_artifact_tampering_fails_before_active_state_changes(self):
        class ActivationClock(dt.datetime):
            @classmethod
            def now(cls, tz=None):
                return cls(2026, 9, 1, 10, 1, tzinfo=dt.timezone.utc)

        args = argparse.Namespace(
            transaction_id=TRANSACTION_ID,
            ingress_ready=True,
            timeout="10m",
            json=True,
        )
        with tempfile.TemporaryDirectory() as directory:
            with patched_layout(pathlib.Path(directory)):
                document, classic, client, awg31, server, profile, backup = prepared_state()
                active_paths = {
                    core.CONFIG_FILE: core.CONFIG_FILE.read_bytes(),
                    core.GENERATED_CONFIG: core.GENERATED_CONFIG.read_bytes(),
                    core.RUNTIME_CONFIG: core.RUNTIME_CONFIG.read_bytes(),
                    core.CLIENTS / "kat-iphone/kat-iphone.conf": (
                        core.CLIENTS / "kat-iphone/kat-iphone.conf"
                    ).read_bytes(),
                }
                pathlib.Path(document["pending"]["profiles"][0]["qr"]).write_bytes(
                    b"tampered qr"
                )
                with (
                    mock.patch.object(core.dt, "datetime", ActivationClock),
                    mock.patch.object(core, "mutation_lock", return_value=contextlib.nullcontext()),
                    mock.patch.object(
                        core, "verify_transition_backup_precondition", return_value=backup
                    ),
                    mock.patch.object(core, "managed_transition_prestate_digest", return_value="ab" * 32),
                    mock.patch.object(core, "require_awg31_capability", return_value=document["capability"]),
                    mock.patch.object(core, "ingress_boundary_attestation", return_value="lightsail"),
                    mock.patch.object(core, "udp_port_is_listening", return_value=False),
                    mock.patch.object(core, "udp_port_bind_available", return_value=True),
                    mock.patch.object(core, "is_service_active", return_value=True),
                    mock.patch.object(
                        core,
                        "commit_server_config",
                        side_effect=AssertionError("tampered artifacts must not be installed"),
                    ),
                ):
                    with self.assertRaisesRegex(core.AwgctlError, "integrity"):
                        core.cmd_obfuscation_activate(args)

                self.assertEqual(core.load_transition_document()["state"], "prepared")
                self.assertEqual(core.load_config()["obfuscation"]["mode"], "classic")
                self.assertEqual(
                    {path: path.read_bytes() for path in active_paths}, active_paths
                )


class ObfuscationConfirmTests(unittest.TestCase):
    def test_confirm_requires_fresh_bidirectional_progress_then_marks_all_new_profiles_pending(self):
        self.assertTrue(
            hasattr(core, "cmd_obfuscation_confirm"),
            "obfuscation confirm handler is missing",
        )

        class ConfirmClock(dt.datetime):
            calls = 0

            @classmethod
            def now(cls, tz=None):
                cls.calls += 1
                return cls(2026, 9, 1, 10, 2, tzinfo=dt.timezone.utc)

        args = argparse.Namespace(transaction_id=TRANSACTION_ID, json=True)
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            with patched_layout(root):
                active, classic, client, awg31, server, profile, backup = active_state()
                systemd_calls = []
                handshake = int(
                    dt.datetime(2026, 9, 1, 10, 1, 30, tzinfo=dt.timezone.utc).timestamp()
                )

                def runner(argv, **kwargs):
                    systemd_calls.append(list(argv))
                    if argv[:2] == ["systemctl", "stop"]:
                        return subprocess.CompletedProcess(argv, 0, b"", b"")
                    if argv[:3] == ["systemctl", "is-active", "--quiet"]:
                        return subprocess.CompletedProcess(argv, 3, b"", b"")
                    raise AssertionError(f"unexpected command: {argv}")

                with (
                    mock.patch.object(core.dt, "datetime", ConfirmClock),
                    mock.patch.object(core, "mutation_lock", return_value=contextlib.nullcontext()),
                    mock.patch.object(core, "is_service_active", return_value=True),
                    mock.patch.object(core, "handshake_map", return_value={key(3): handshake}),
                    mock.patch.object(core, "transfer_map", return_value={key(3): (101, 201)}),
                    mock.patch.object(core, "run", side_effect=runner),
                    mock.patch.object(core, "audit"),
                    contextlib.redirect_stdout(output),
                ):
                    try:
                        result = core.cmd_obfuscation_confirm(args)
                    except core.AwgctlError as exc:
                        self.fail(f"confirm is incomplete: {exc}")

                self.assertEqual(result, 0)
                self.assertEqual(ConfirmClock.calls, 1)
                metadata = json.loads(
                    (core.CLIENTS / "kat-iphone/metadata.json").read_text()
                )
                self.assertEqual(metadata["profile_revision"], 4)
                self.assertEqual(metadata["distribution_status"], "pending")
                self.assertIsNone(metadata["distributed_at"])
                self.assertEqual(metadata["profile_change_reason"], "obfuscation:awg31")
                self.assertIsNone(core.load_transition_document(required=False))
                self.assertFalse(pathlib.Path(active["pending"]["root"]).exists())
                self.assertTrue(backup.is_dir())
                outcome = core.load_transition_outcome()
                self.assertEqual(outcome["outcome"], "confirmed")
                self.assertEqual(
                    systemd_calls[0],
                    [
                        "systemctl",
                        "stop",
                        f"awgctl-obfuscation-rollback-{TRANSACTION_ID}.timer",
                        f"awgctl-obfuscation-rollback-{TRANSACTION_ID}.service",
                    ],
                )
                payload = json.loads(output.getvalue())
                self.assertEqual(
                    payload["data"]["remove_ingress"],
                    {
                        "port": 55323,
                        "protocol": "UDP",
                        "source": "0.0.0.0/0",
                        "type": "Custom",
                    },
                )
                self.assertNotIn(key(3), json.dumps(payload))

    def test_one_sided_progress_and_timer_cancellation_failure_leave_active_state_unchanged(self):
        class ConfirmClock(dt.datetime):
            @classmethod
            def now(cls, tz=None):
                return cls(2026, 9, 1, 10, 2, tzinfo=dt.timezone.utc)

        args = argparse.Namespace(transaction_id=TRANSACTION_ID, json=True)
        handshake = int(
            dt.datetime(2026, 9, 1, 10, 1, 30, tzinfo=dt.timezone.utc).timestamp()
        )
        cases = (
            ("rx-only", (101, 200), False, handshake),
            ("tx-only", (100, 201), False, handshake),
            ("future-handshake", (101, 201), False, handshake + 31),
            ("timer-still-active", (101, 201), True, handshake),
        )
        for label, counters, timer_active, observed_handshake in cases:
            with self.subTest(case=label), tempfile.TemporaryDirectory() as directory:
                with patched_layout(pathlib.Path(directory)):
                    active, classic, client, awg31, server, profile, backup = active_state()
                    metadata_path = core.CLIENTS / "kat-iphone/metadata.json"
                    metadata_before = metadata_path.read_bytes()
                    transition_before = core.TRANSITION_FILE.read_bytes()
                    pending_root = pathlib.Path(active["pending"]["root"])

                    def runner(argv, **kwargs):
                        if argv[:2] == ["systemctl", "stop"]:
                            return subprocess.CompletedProcess(argv, 0, b"", b"")
                        if argv[:3] == ["systemctl", "is-active", "--quiet"]:
                            return subprocess.CompletedProcess(
                                argv, 0 if timer_active else 3, b"", b""
                            )
                        raise AssertionError(f"unexpected command: {argv}")

                    with (
                        mock.patch.object(core.dt, "datetime", ConfirmClock),
                        mock.patch.object(core, "mutation_lock", return_value=contextlib.nullcontext()),
                        mock.patch.object(core, "is_service_active", return_value=True),
                        mock.patch.object(
                            core,
                            "handshake_map",
                            return_value={key(3): observed_handshake},
                        ),
                        mock.patch.object(core, "transfer_map", return_value={key(3): counters}),
                        mock.patch.object(core, "run", side_effect=runner),
                    ):
                        with self.assertRaises(core.AwgctlError):
                            core.cmd_obfuscation_confirm(args)

                    self.assertEqual(metadata_path.read_bytes(), metadata_before)
                    self.assertEqual(core.TRANSITION_FILE.read_bytes(), transition_before)
                    self.assertTrue(pending_root.is_dir())
                    self.assertIsNone(core.load_transition_outcome())


class ObfuscationRollbackTests(unittest.TestCase):
    def test_rollback_binds_one_utc_instant_to_restore_and_outcome(self):
        class RollbackClock(dt.datetime):
            calls = 0

            @classmethod
            def now(cls, tz=None):
                cls.calls += 1
                return cls(2026, 9, 1, 10, 3, tzinfo=dt.timezone.utc)

        args = argparse.Namespace(transaction_id=TRANSACTION_ID, json=True)
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            with patched_layout(pathlib.Path(directory)):
                active_state()
                restore_times = []

                def restore(backup_name, document, *, now):
                    restore_times.append(now)

                def runner(argv, **kwargs):
                    if argv[:2] == ["systemctl", "stop"]:
                        return subprocess.CompletedProcess(argv, 0, b"", b"")
                    if argv[:3] == ["systemctl", "is-active", "--quiet"]:
                        return subprocess.CompletedProcess(argv, 3, b"", b"")
                    raise AssertionError(f"unexpected command: {argv}")

                with (
                    mock.patch.object(core.dt, "datetime", RollbackClock),
                    mock.patch.object(core, "mutation_lock", return_value=contextlib.nullcontext()),
                    mock.patch.object(core, "restore_obfuscation_backup", side_effect=restore),
                    mock.patch.object(core, "run", side_effect=runner),
                    mock.patch.object(core, "audit"),
                    contextlib.redirect_stdout(output),
                ):
                    try:
                        result = core.cmd_obfuscation_rollback(args)
                    except core.AwgctlError as exc:
                        self.fail(f"rollback did not bind its transaction clock: {exc}")

                self.assertEqual(result, 0)
                self.assertEqual(RollbackClock.calls, 1)
                self.assertEqual(
                    restore_times,
                    [dt.datetime(2026, 9, 1, 10, 3, tzinfo=dt.timezone.utc)],
                )
                self.assertEqual(
                    core.load_transition_outcome()["completed_at"],
                    "2026-09-01T10:03:00Z",
                )

    def test_rollback_restores_exact_id_and_is_idempotent_only_for_its_outcome(self):
        self.assertTrue(
            hasattr(core, "cmd_obfuscation_rollback"),
            "obfuscation rollback handler is missing",
        )

        class RollbackClock(dt.datetime):
            @classmethod
            def now(cls, tz=None):
                return cls(2026, 9, 1, 10, 3, tzinfo=dt.timezone.utc)

        args = argparse.Namespace(transaction_id=TRANSACTION_ID, json=True)
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            with patched_layout(root):
                active, classic, client, awg31, server, profile, backup = active_state()
                classic_server = core.GENERATED_CONFIG.read_bytes()
                classic_profile = core.render_client_config(
                    classic, key(4), key(5), key(2), "10.77.42.2/32"
                )
                restores = []

                def restore(backup_name, document, *, now):
                    restores.append((backup_name, document["transaction_id"]))
                    core.atomic_json(core.CONFIG_FILE, classic, 0o600)
                    with contextlib.suppress(FileNotFoundError):
                        core.HEADER_PROTECTION_KEY.unlink()
                    core.atomic_write(core.GENERATED_CONFIG, classic_server, 0o600)
                    core.atomic_write(core.RUNTIME_CONFIG, classic_server, 0o600)
                    core.atomic_write(
                        core.CLIENTS / "kat-iphone/kat-iphone.conf",
                        classic_profile,
                        0o600,
                    )

                def runner(argv, **kwargs):
                    if argv[:2] == ["systemctl", "stop"]:
                        return subprocess.CompletedProcess(argv, 0, b"", b"")
                    if argv[:3] == ["systemctl", "is-active", "--quiet"]:
                        return subprocess.CompletedProcess(argv, 3, b"", b"")
                    raise AssertionError(f"unexpected command: {argv}")

                with (
                    mock.patch.object(core.dt, "datetime", RollbackClock),
                    mock.patch.object(core, "mutation_lock", return_value=contextlib.nullcontext()),
                    mock.patch.object(core, "restore_obfuscation_backup", side_effect=restore),
                    mock.patch.object(core, "run", side_effect=runner),
                    mock.patch.object(core, "audit"),
                    contextlib.redirect_stdout(output),
                ):
                    try:
                        result = core.cmd_obfuscation_rollback(args)
                    except core.AwgctlError as exc:
                        self.fail(f"rollback is incomplete: {exc}")
                    second = core.cmd_obfuscation_rollback(args)
                    with self.assertRaises(core.AwgctlError):
                        core.cmd_obfuscation_rollback(
                            argparse.Namespace(
                                transaction_id="fedcba9876543210fedcba9876543210",
                                json=True,
                            )
                        )

                self.assertEqual((result, second), (0, 0))
                self.assertEqual(restores, [(active["backup_name"], TRANSACTION_ID)])
                self.assertEqual(core.load_config()["obfuscation"]["mode"], "classic")
                self.assertIsNone(core.load_transition_document(required=False))
                outcome = core.load_transition_outcome()
                self.assertEqual(outcome["outcome"], "rolled_back")
                self.assertEqual(outcome["reason"], "operator")
                self.assertIn('"idempotent": true', output.getvalue().lower())

    def test_stale_timeout_id_never_rolls_back_a_later_active_transaction(self):
        args = argparse.Namespace(
            transaction_id="fedcba9876543210fedcba9876543210",
            json=False,
        )
        with tempfile.TemporaryDirectory() as directory:
            with patched_layout(pathlib.Path(directory)):
                active_state()
                with (
                    mock.patch.object(core, "mutation_lock", return_value=contextlib.nullcontext()),
                    mock.patch.object(
                        core,
                        "restore_obfuscation_backup",
                        side_effect=AssertionError("stale timeout must not restore"),
                    ),
                ):
                    with self.assertRaises(core.AwgctlError):
                        core.cmd_obfuscation_timeout(args)
                self.assertEqual(core.load_transition_document()["transaction_id"], TRANSACTION_ID)
                self.assertEqual(core.load_config()["obfuscation"]["mode"], "awg31")

    def test_unverified_rollback_stops_interface_and_retains_exact_active_transaction(self):
        args = argparse.Namespace(transaction_id=TRANSACTION_ID, json=True)
        with tempfile.TemporaryDirectory() as directory:
            with patched_layout(pathlib.Path(directory)):
                active_state()
                service = mock.Mock()

                def runner(argv, **kwargs):
                    if argv[:2] == ["systemctl", "stop"]:
                        return subprocess.CompletedProcess(argv, 0, b"", b"")
                    if argv[:3] == ["systemctl", "is-active", "--quiet"]:
                        return subprocess.CompletedProcess(argv, 3, b"", b"")
                    raise AssertionError(f"unexpected command: {argv}")

                with (
                    mock.patch.object(core, "mutation_lock", return_value=contextlib.nullcontext()),
                    mock.patch.object(
                        core,
                        "restore_obfuscation_backup",
                        side_effect=core.AwgctlError("restore verification failed"),
                    ),
                    mock.patch.object(core, "run", side_effect=runner),
                    mock.patch.object(core, "service_action", service),
                    mock.patch.object(core, "audit"),
                ):
                    with self.assertRaisesRegex(core.AwgctlError, "interface stopped"):
                        core.cmd_obfuscation_rollback(args)

                service.assert_called_once_with("stop", "awg0")
                self.assertEqual(core.load_transition_document()["state"], "active")
                self.assertEqual(core.load_config()["obfuscation"]["mode"], "awg31")
                self.assertIsNone(core.load_transition_outcome())


class ObfuscationStatusTests(unittest.TestCase):
    def test_obfuscation_show_reports_versions_revision_transition_and_consistency_without_secrets(self):
        self.assertTrue(
            hasattr(core, "cmd_obfuscation_show"),
            "obfuscation show handler is missing",
        )
        output = io.StringIO()
        live_versions = {
            "policy_version": 1,
            "tools_version": "3.1.20990111",
            "module_version": "3.1.20990112",
        }
        with tempfile.TemporaryDirectory() as directory:
            with patched_layout(pathlib.Path(directory)):
                active, classic, client, awg31, server, profile, backup = active_state()
                with (
                    mock.patch.object(
                        core, "inspect_awg_versions", return_value=live_versions
                    ) as inspect_versions,
                    contextlib.redirect_stdout(output),
                ):
                    result = core.cmd_obfuscation_show(argparse.Namespace(json=True))

        self.assertEqual(result, 0)
        payload = json.loads(output.getvalue())
        data = payload["data"]
        self.assertEqual(data["mode"], "awg31")
        self.assertEqual(data["profile"], "russia-ios-v1")
        self.assertEqual(data["profile_revisions"], {"kat-iphone": 3})
        self.assertEqual(
            data["transition"],
            {
                "client": "kat-iphone",
                "deadline_at": "2026-09-01T10:11:00Z",
                "state": "active",
                "transaction_id": TRANSACTION_ID,
            },
        )
        self.assertEqual(data["versions"], live_versions)
        inspect_versions.assert_called_once_with()
        self.assertTrue(data["server_client_consistency"])
        self.assertEqual(len(data["header_protection_key_fingerprint"]), 12)
        serialized = json.dumps(payload, sort_keys=True)
        for secret in (key(1), key(3), key(4), key(5), "I1", str(core.PENDING_TRANSITIONS)):
            self.assertNotIn(secret, serialized)

    def test_status_json_embeds_transition_versions_revisions_and_consistency(self):
        output = io.StringIO()
        completed = subprocess.CompletedProcess([], 0, b"awg0 UP\n", b"")
        with tempfile.TemporaryDirectory() as directory:
            with patched_layout(pathlib.Path(directory)):
                active_state()
                with (
                    mock.patch.object(core, "systemctl_state", return_value=("active", "enabled")),
                    mock.patch.object(core, "run", return_value=completed),
                    mock.patch.object(core, "imds_value", return_value="203.0.113.7"),
                    mock.patch.object(core, "live_peers", return_value={key(3)}),
                    mock.patch.object(core, "handshake_map", return_value={key(3): 0}),
                    mock.patch.object(core, "nft_table_active", return_value=True),
                    mock.patch.object(core, "ingress_boundary_attestation", return_value="lightsail"),
                    mock.patch.object(
                        core,
                        "inspect_awg_versions",
                        return_value={
                            "policy_version": 1,
                            "tools_version": "3.1.20990101",
                            "module_version": "3.1.20990102",
                        },
                    ),
                    contextlib.redirect_stdout(output),
                ):
                    result = core.cmd_status(argparse.Namespace(json=True))

        self.assertEqual(result, 0)
        data = json.loads(output.getvalue())["data"]
        self.assertIn("mode", data, "status omits Task 4 obfuscation fields")
        self.assertEqual(data["mode"], "awg31")
        self.assertEqual(data["profile_revisions"], {"kat-iphone": 3})
        self.assertEqual(data["transition"]["state"], "active")
        self.assertEqual(data["versions"]["tools_version"], "3.1.20990101")
        self.assertTrue(data["server_client_consistency"])

    def test_health_json_embeds_obfuscation_transition_summary(self):
        output = io.StringIO()

        def runner(argv, **kwargs):
            stdout = b""
            if argv[:5] == ["ip", "-brief", "link", "show", "awg0"]:
                stdout = b"awg0 UP\n"
            elif argv[:6] == ["ip", "-4", "-brief", "address", "show", "awg0"]:
                stdout = b"awg0 UP 10.77.42.1/24\n"
            elif argv[:2] == ["dkms", "status"]:
                stdout = f"amneziawg/3.1, {core.os.uname().release}, installed\n".encode()
            elif argv[:2] == ["ufw", "status"]:
                stdout = b"Status: inactive\n"
            return subprocess.CompletedProcess(argv, 0, stdout, b"")

        with tempfile.TemporaryDirectory() as directory:
            with patched_layout(pathlib.Path(directory)):
                active_state()
                with (
                    mock.patch.object(core, "systemctl_state", return_value=("active", "enabled")),
                    mock.patch.object(core, "run", side_effect=runner),
                    mock.patch.object(core, "safe_awg_query", return_value="4242"),
                    mock.patch.object(core, "nft_table_active", return_value=True),
                    mock.patch.object(core, "management_security_checks", return_value=[]),
                    mock.patch.object(core, "docker_user_chain_exists", return_value=False),
                    mock.patch.object(core, "permission_problem", return_value=None),
                    mock.patch.object(core, "endpoint_ipv4s", return_value=["203.0.113.7"]),
                    mock.patch.object(core, "imds_value", return_value="203.0.113.7"),
                    mock.patch.object(core, "ingress_boundary_attestation", return_value="lightsail"),
                    mock.patch.object(core, "suspicious_wildcard_listeners", return_value=[]),
                    mock.patch.object(
                        core,
                        "inspect_awg_versions",
                        return_value={
                            "policy_version": 1,
                            "tools_version": "3.1.20990101",
                            "module_version": "3.1.20990102",
                        },
                    ),
                    contextlib.redirect_stdout(output),
                ):
                    core.cmd_health(argparse.Namespace(json=True))

        data = json.loads(output.getvalue())["data"]
        self.assertIn("mode", data, "health omits Task 4 obfuscation fields")
        self.assertEqual(data["mode"], "awg31")
        self.assertEqual(data["transition"]["state"], "active")
        self.assertEqual(data["profile_revisions"], {"kat-iphone": 3})
        self.assertTrue(data["server_client_consistency"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
