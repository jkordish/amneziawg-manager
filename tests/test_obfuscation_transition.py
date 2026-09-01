import contextlib
import copy
import argparse
import json
import datetime as dt
import subprocess
import io
import pathlib
import shutil
import sys
import tempfile
import stat
import threading
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
        "ACTIVATION_JOURNAL_FILE": root / "transitions/obfuscation-activation.json",
        "SERVICE_OPERATION_FILE": root / "run/awgctl/service-operation.json",
        "RUNTIME_CONFIG": root / "runtime/awg0.conf",
        "RUNTIME_DIR": root / "run/awgctl",
        "LOCK_FILE": root / "run/awgctl/mutation.lock",
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
    backup = make_transition_backup()
    document = transition_document(pending_base=core.PENDING_TRANSITIONS)
    document["backup_identity"] = core.backup_snapshot_identity(
        core.read_protected_tree(backup)
    )
    document["prestate_sha256"] = "ab" * 32
    document["pending_sha256"] = core.pending_transition_artifact_digest(pending_root)
    core.compare_and_swap_transition(
        document,
        expected_transaction_id=None,
        expected_state=None,
    )
    return document, config, client, new_config, server, profile, backup


def add_pending_managed_client(
    document,
    classic,
    target,
    awg31,
    *,
    now,
):
    metadata = {
        key_name: value
        for key_name, value in target.items()
        if key_name not in {"private_key", "psk"}
    }
    metadata.update(
        name="macbook",
        address="10.77.42.3/32",
        public_key=key(6),
        public_key_fingerprint=core.fingerprint(key(6)),
        owner="Kat",
        device="MacBook",
        expires="2026-09-02",
    )
    non_target = {**metadata, "private_key": key(7), "psk": key(8)}
    core.atomic_json(core.CLIENTS / "macbook/metadata.json", metadata, 0o600)
    core.atomic_write(core.CLIENT_KEYS / "macbook/private", key(7) + "\n", 0o600)
    core.atomic_write(core.CLIENT_KEYS / "macbook/public", key(6) + "\n", 0o600)
    core.atomic_write(core.CLIENT_KEYS / "macbook/psk", key(8) + "\n", 0o600)
    classic_profile = core.render_client_config(
        classic,
        key(7),
        key(8),
        key(2),
        "10.77.42.3/32",
    )
    core.atomic_write(core.CLIENTS / "macbook/macbook.conf", classic_profile, 0o600)
    core.atomic_write(core.CLIENTS / "macbook/macbook.png", b"classic macbook qr", 0o600)

    pending_root = pathlib.Path(document["pending"]["root"])
    header = (pending_root / "header-protection").read_bytes()
    pending_server = core.render_server_config(
        awg31,
        key(1),
        [target, non_target],
        now=now,
        header_protection_key=header,
    )
    core.atomic_write(pending_root / "awg0.conf", pending_server, 0o600)
    pending_profile = core.render_client_config(
        awg31,
        key(7),
        key(8),
        key(2),
        "10.77.42.3/32",
        header_protection_key=header,
    )
    core.atomic_write(
        pending_root / "clients/macbook/macbook.conf",
        pending_profile,
        0o600,
    )
    core.atomic_write(
        pending_root / "clients/macbook/macbook.png",
        b"pending macbook qr",
        0o600,
    )
    document = copy.deepcopy(document)
    document["pending"]["profiles"].append(
        {
            "name": "macbook",
            "config": str(pending_root / "clients/macbook/macbook.conf"),
            "qr": str(pending_root / "clients/macbook/macbook.png"),
            "current_revision": 3,
        }
    )
    document["pending"]["profiles"].sort(key=lambda item: item["name"])
    document["pending_sha256"] = core.pending_transition_artifact_digest(pending_root)
    core.atomic_json(core.TRANSITION_FILE, core.normalize_transition_document(document), 0o600)
    return document, non_target, pending_server


def make_transition_backup():
    backup = core.BACKUPS / "20260901T100000Z"
    backup.mkdir(parents=True, mode=0o700)
    for component in core.RESTORE_COMPONENTS:
        source = core.ROOT / component
        destination = backup / component
        if source.is_dir():
            shutil.copytree(source, destination)
        else:
            destination.mkdir(mode=0o700)
    core.chmod_secret_tree(backup)
    manifest = core.create_backup_manifest(
        backup,
        product_version=core.VERSION,
        created_at="2026-09-01T10:00:00Z",
    )
    core.atomic_json(backup / "manifest.json", manifest, 0o600)
    core.chmod_secret_tree(backup)
    return backup


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
        pre_handshake=0,
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
        "backup_identity": {
            "manifest_sha256": "de" * 32,
            "snapshot_sha256": "ef" * 32,
        },
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
        "pre_handshake": 0 if state == "active" else None,
        "prestate_sha256": "ab" * 32,
        "pending_sha256": "cd" * 32,
    }


def service_intent_document(*, phase="prepared", goal="requested", next_action=0):
    expected_actions = ["down"] if goal == "stopped" else ["down", "up"]
    owner_pid = None if phase == "verified" else 1234
    return {
        "schema_version": 1,
        "operation_id": TRANSACTION_ID,
        "service_action": "restart",
        "interface": "awg0",
        "phase": phase,
        "goal": goal,
        "expected_actions": expected_actions,
        "next_action": next_action,
        "transition_id": None,
        "generation_sha256": "ab" * 32,
        "owner_pid": owner_pid,
        "owner_start_ticks": None if owner_pid is None else 5678,
        "pre_service_active": True,
        "pre_firewall_up": True,
        "created_at": "2026-09-01T10:00:00Z",
        "updated_at": "2026-09-01T10:00:00Z",
    }


class FakeServiceRuntime:
    def __init__(self, *, active, firewall_up):
        self.active = active
        self.firewall_up = firewall_up

    def service_active(self, unused_interface):
        return self.active

    def firewall_postcondition(self, action):
        return self.firewall_up if action == "up" else not self.firewall_up

    def cleanup(self):
        self.firewall_up = False

    def apply(self):
        self.firewall_up = True


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


class MutationLockTests(unittest.TestCase):
    def test_mutation_lock_creates_one_protected_runtime_inode(self):
        with tempfile.TemporaryDirectory() as directory:
            with patched_layout(pathlib.Path(directory)), mock.patch.object(core, "require_root"):
                with core.mutation_lock():
                    parent = core.RUNTIME_DIR.lstat()
                    lock = core.LOCK_FILE.lstat()
                    self.assertTrue(stat.S_ISDIR(parent.st_mode))
                    self.assertEqual(stat.S_IMODE(parent.st_mode), 0o700)
                    self.assertEqual((parent.st_uid, parent.st_gid), (core.os.geteuid(), core.os.getegid()))
                    self.assertTrue(stat.S_ISREG(lock.st_mode))
                    self.assertEqual(stat.S_IMODE(lock.st_mode), 0o600)
                    self.assertEqual(lock.st_nlink, 1)
                    self.assertEqual((lock.st_uid, lock.st_gid), (core.os.geteuid(), core.os.getegid()))

    def test_mutation_lock_rejects_unsafe_parent_and_file_types_or_identity(self):
        unsafe_kinds = ("parent-mode", "parent-symlink", "file-symlink", "hardlink", "fifo", "owner")
        for kind in unsafe_kinds:
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                with patched_layout(root):
                    core.RUNTIME_DIR.parent.mkdir(parents=True, mode=0o700)
                    if kind == "parent-symlink":
                        target = root / "attacker"
                        target.mkdir(mode=0o700)
                        core.RUNTIME_DIR.symlink_to(target, target_is_directory=True)
                    else:
                        core.RUNTIME_DIR.mkdir(mode=0o700)
                    if kind == "parent-mode":
                        core.RUNTIME_DIR.chmod(0o777)
                    elif kind == "file-symlink":
                        target = root / "target"
                        target.write_bytes(b"")
                        core.LOCK_FILE.symlink_to(target)
                    elif kind == "hardlink":
                        target = root / "target"
                        target.write_bytes(b"")
                        core.os.link(target, core.LOCK_FILE)
                    elif kind == "fifo":
                        core.os.mkfifo(core.LOCK_FILE, 0o600)

                    patches = [mock.patch.object(core, "require_root")]
                    if kind == "owner":
                        patches.extend([
                            mock.patch.object(core.os, "geteuid", return_value=12345),
                            mock.patch.object(core.os, "getegid", return_value=12345),
                        ])
                    with contextlib.ExitStack() as stack:
                        for patcher in patches:
                            stack.enter_context(patcher)
                        with self.assertRaisesRegex(core.AwgctlError, "mutation.*unsafe"):
                            with core.mutation_lock():
                                self.fail("unsafe lock acquired")

    def test_internal_lock_timeout_is_bounded_and_controlled(self):
        monotonic = mock.Mock(side_effect=[0.0, 0.2, 0.6])
        with tempfile.TemporaryDirectory() as directory:
            with (
                patched_layout(pathlib.Path(directory)),
                mock.patch.object(core, "require_root"),
                mock.patch.object(core.fcntl, "flock", side_effect=BlockingIOError),
                mock.patch.object(core.time, "monotonic", side_effect=monotonic),
            ):
                with self.assertRaisesRegex(core.AwgctlError, "lock.*timeout"):
                    with core.mutation_lock(timeout_seconds=0.5):
                        self.fail("contended lock acquired")

    def test_current_lock_can_be_released_only_for_service_child_then_reacquired(self):
        acquired = threading.Event()
        release_waiter = threading.Event()
        errors = []

        def waiter():
            try:
                with core.mutation_lock():
                    acquired.set()
                    release_waiter.wait(timeout=5)
            except Exception as exc:
                errors.append(exc)

        with tempfile.TemporaryDirectory() as directory:
            with patched_layout(pathlib.Path(directory)), mock.patch.object(core, "require_root"):
                with core.mutation_lock():
                    thread = threading.Thread(target=waiter)
                    thread.start()
                    self.assertFalse(acquired.wait(timeout=0.1))
                    with core.temporarily_release_mutation_lock():
                        self.assertFalse(core.mutation_lock_is_held())
                        self.assertTrue(acquired.wait(timeout=5))
                        release_waiter.set()
                    self.assertTrue(core.mutation_lock_is_held())
                thread.join(timeout=5)
                self.assertFalse(thread.is_alive())
                self.assertEqual(errors, [])

                with self.assertRaisesRegex(core.AwgctlError, "mutation lock"):
                    with core.temporarily_release_mutation_lock():
                        self.fail("released without lock ownership")

    def test_failed_service_lock_reacquisition_never_claims_lock_ownership(self):
        with tempfile.TemporaryDirectory() as directory:
            with patched_layout(pathlib.Path(directory)), mock.patch.object(core, "require_root"):
                with core.mutation_lock():
                    real_flock = core.fcntl.flock

                    def fail_reacquire(descriptor, operation):
                        if operation == core.fcntl.LOCK_EX:
                            raise OSError("injected reacquisition failure")
                        return real_flock(descriptor, operation)

                    with (
                        mock.patch.object(core.fcntl, "flock", side_effect=fail_reacquire),
                        self.assertRaisesRegex(core.AwgctlError, "could not be reacquired"),
                    ):
                        with core.temporarily_release_mutation_lock():
                            pass
                    self.assertFalse(core.mutation_lock_is_held())


class ServiceOperationIntentTests(unittest.TestCase):
    def test_intent_schema_is_strict_typed_and_phase_consistent(self):
        valid = service_intent_document()
        self.assertEqual(core.normalize_service_operation_intent(valid), valid)

        mutations = (
            lambda value: value.update(extra=True),
            lambda value: value.update(schema_version=True),
            lambda value: value.update(operation_id=None),
            lambda value: value.update(service_action="reload"),
            lambda value: value.update(interface=[]),
            lambda value: value.update(phase="unknown"),
            lambda value: value.update(goal="unknown"),
            lambda value: value.update(expected_actions=["up"]),
            lambda value: value.update(next_action=True),
            lambda value: value.update(next_action=3),
            lambda value: value.update(transition_id=[]),
            lambda value: value.update(generation_sha256=None),
            lambda value: value.update(owner_pid=0),
            lambda value: value.update(owner_start_ticks=None),
            lambda value: value.update(pre_service_active=1),
            lambda value: value.update(pre_firewall_up=None),
            lambda value: value.update(created_at=None),
            lambda value: value.update(updated_at="2026-09-01T09:59:59Z"),
        )
        for mutate in mutations:
            candidate = copy.deepcopy(valid)
            mutate(candidate)
            with self.subTest(candidate=candidate), self.assertRaises(core.AwgctlError):
                core.normalize_service_operation_intent(candidate)

        for phase in ("compensating", "verified"):
            document = service_intent_document(phase=phase, goal="stopped")
            self.assertEqual(core.normalize_service_operation_intent(document), document)
        with self.assertRaisesRegex(core.AwgctlError, "phase and goal"):
            core.normalize_service_operation_intent(
                service_intent_document(phase="prepared", goal="stopped")
            )

    def test_intent_file_is_protected_and_compare_and_swap_is_exact(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            intent_path = root / "run/awgctl/service-operation.json"
            with (
                patched_layout(root),
                mock.patch.object(core, "require_root"),
                mock.patch.object(core, "SERVICE_OPERATION_FILE", intent_path, create=True),
            ):
                classic_state()
                self.assertEqual(core.SERVICE_OPERATION_FILE.parent, core.RUNTIME_DIR)
                document = service_intent_document()
                with core.mutation_lock():
                    core.compare_and_swap_service_operation_intent(
                        document,
                        expected_operation_id=None,
                        expected_phase=None,
                    )
                    self.assertEqual(core.load_service_operation_intent(), document)
                    self.assertFalse(core.PENDING_TRANSITIONS.exists())
                metadata = intent_path.stat()
                self.assertEqual(metadata.st_mode & 0o777, 0o600)
                self.assertEqual(metadata.st_nlink, 1)

                changed = copy.deepcopy(document)
                changed.update(phase="invoking", updated_at="2026-09-01T10:00:01Z")
                with core.mutation_lock(service_lifecycle=True):
                    with self.assertRaisesRegex(core.AwgctlError, "changed"):
                        core.compare_and_swap_service_operation_intent(
                            changed,
                            expected_operation_id="f" * 32,
                            expected_phase="prepared",
                        )
                    core.compare_and_swap_service_operation_intent(
                        changed,
                        expected_operation_id=TRANSACTION_ID,
                        expected_phase="prepared",
                    )
                    with self.assertRaisesRegex(core.AwgctlError, "does not match"):
                        core.delete_service_operation_intent("f" * 32)
                    core.delete_service_operation_intent(TRANSACTION_ID)
                self.assertFalse(intent_path.exists())

    def test_process_owner_identity_binds_pid_and_proc_start_time(self):
        with tempfile.TemporaryDirectory() as directory:
            proc_root = pathlib.Path(directory)
            stat_path = proc_root / "1234/stat"
            stat_path.parent.mkdir()
            stat_path.write_text(
                "1234 (manager worker) S "
                + " ".join(["1"] * 18 + ["5678"])
                + "\n",
                encoding="ascii",
            )
            with (
                mock.patch.object(core, "PROC_ROOT", proc_root, create=True),
                mock.patch.object(core.os, "getpid", return_value=1234),
            ):
                self.assertEqual(core.current_process_identity(), (1234, 5678))
                self.assertTrue(core.process_identity_is_alive(1234, 5678))
                self.assertFalse(core.process_identity_is_alive(1234, 9999))
                stat_path.unlink()
                self.assertFalse(core.process_identity_is_alive(1234, 5678))

                stat_path.write_text("malformed\n", encoding="ascii")
                with self.assertRaisesRegex(core.AwgctlError, "process identity"):
                    core.process_identity_is_alive(1234, 5678)


class TransitionInterlockTests(unittest.TestCase):
    def test_hook_intent_enforces_sequence_and_duplicate_idempotency(self):
        with tempfile.TemporaryDirectory() as directory:
            with patched_layout(pathlib.Path(directory)), mock.patch.object(core, "require_root"):
                classic_state()
                document = service_intent_document(phase="invoking")
                document["generation_sha256"] = core.managed_transition_prestate_digest()
                cleanup = mock.Mock()
                apply = mock.Mock()
                postcondition = mock.Mock(return_value=True)
                with (
                    core.mutation_lock(),
                    mock.patch.object(core, "firewall_cleanup", cleanup),
                    mock.patch.object(core, "apply_firewall", apply),
                    mock.patch.object(
                        core,
                        "firewall_action_postcondition",
                        postcondition,
                        create=True,
                    ),
                ):
                    core.compare_and_swap_service_operation_intent(
                        document,
                        expected_operation_id=None,
                        expected_phase=None,
                    )
                    with self.assertRaisesRegex(core.AwgctlError, "expected firewall action"):
                        core.run_firewall_action_locked("up")
                    self.assertEqual(
                        core.load_service_operation_intent()["next_action"],
                        0,
                    )

                    core.run_firewall_action_locked("down")
                    self.assertEqual(
                        core.load_service_operation_intent()["next_action"],
                        1,
                    )
                    core.run_firewall_action_locked("down")
                    self.assertEqual(cleanup.call_count, 1)
                    self.assertEqual(
                        core.load_service_operation_intent()["next_action"],
                        1,
                    )

                    core.run_firewall_action_locked("up")
                    self.assertEqual(
                        core.load_service_operation_intent()["next_action"],
                        2,
                    )
                    core.run_firewall_action_locked("up")
                    self.assertEqual(apply.call_count, 1)
                    with self.assertRaisesRegex(core.AwgctlError, "expected firewall action"):
                        core.run_firewall_action_locked("down")

                self.assertEqual(
                    [call.args[0] for call in postcondition.call_args_list],
                    ["down", "down", "up", "up"],
                )

    def test_hook_without_manager_intent_locks_and_mutates_normally(self):
        for action, target in (("up", "apply_firewall"), ("down", "firewall_cleanup")):
            with self.subTest(action=action), tempfile.TemporaryDirectory() as directory:
                with (
                    patched_layout(pathlib.Path(directory)),
                    mock.patch.object(core, "require_root"),
                ):
                    classic_state()
                    invoked = mock.Mock()
                    with (
                        mock.patch.object(core, target, invoked),
                        mock.patch.object(
                            core,
                            "firewall_action_postcondition",
                            return_value=True,
                            create=True,
                        ),
                    ):
                        args = core.build_parser(entrypoint="internal").parse_args(
                            ["_firewall", action]
                        )
                        core.dispatch(args)
                    invoked.assert_called_once_with()

    def test_hook_rejects_intent_generation_or_transition_drift(self):
        for drift in ("generation", "transition"):
            with self.subTest(drift=drift), tempfile.TemporaryDirectory() as directory:
                with patched_layout(pathlib.Path(directory)), mock.patch.object(core, "require_root"):
                    classic_state()
                    document = service_intent_document(phase="invoking")
                    document["generation_sha256"] = core.managed_transition_prestate_digest()
                    if drift == "generation":
                        document["generation_sha256"] = "ff" * 32
                    else:
                        document["transition_id"] = "f" * 32
                    with (
                        core.mutation_lock(),
                        mock.patch.object(core, "firewall_cleanup") as cleanup,
                        mock.patch.object(
                            core,
                            "firewall_action_postcondition",
                            return_value=True,
                            create=True,
                        ),
                    ):
                        core.compare_and_swap_service_operation_intent(
                            document,
                            expected_operation_id=None,
                            expected_phase=None,
                        )
                        with self.assertRaisesRegex(
                            core.AwgctlError,
                            "service operation (generation|transition) changed",
                        ):
                            core.run_firewall_action_locked("down")
                    cleanup.assert_not_called()


    def test_service_action_uses_durable_intent_and_lock_handoff_without_context_bearer(self):
        with tempfile.TemporaryDirectory() as directory:
            with patched_layout(pathlib.Path(directory)), mock.patch.object(core, "require_root"):
                classic_state()
                firewall_calls = []
                direct_args = core.build_parser(entrypoint="internal").parse_args(
                    ["_firewall", "down"]
                )

                def cleanup():
                    firewall_calls.append("down")

                def apply():
                    firewall_calls.append("up")

                def systemd_runner(argv, **kwargs):
                    self.assertEqual(
                        argv,
                        ["systemctl", "restart", "awg-quick@awg0.service"],
                    )
                    self.assertFalse(core.mutation_lock_is_held())
                    self.assertNotIn("environment", kwargs)
                    core.dispatch(direct_args)
                    with core.mutation_lock(service_lifecycle=True):
                        core.run_firewall_action_locked("down")
                    with core.mutation_lock(service_lifecycle=True):
                        core.run_firewall_action_locked("up")
                    return subprocess.CompletedProcess(argv, 0, b"", b"")

                with (
                    core.mutation_lock(),
                    mock.patch.object(core, "current_process_identity", return_value=(1234, 5678)),
                    mock.patch.object(core, "process_identity_is_alive", return_value=True),
                    mock.patch.object(core, "run", side_effect=systemd_runner) as runner,
                    mock.patch.object(core, "firewall_cleanup", side_effect=cleanup),
                    mock.patch.object(core, "apply_firewall", side_effect=apply),
                    mock.patch.object(core, "firewall_action_postcondition", return_value=True),
                    mock.patch.object(
                        core,
                        "service_is_active_exact",
                        return_value=True,
                        create=True,
                    ),
                ):
                    core.service_action("restart", "awg0")
                    self.assertTrue(core.mutation_lock_is_held())

                self.assertEqual(firewall_calls, ["down", "up"])
                self.assertFalse(core.SERVICE_OPERATION_FILE.exists())
                self.assertEqual(runner.call_count, 1)

    def test_start_stop_and_restart_complete_with_lock_taking_hooks(self):
        cases = (
            ("start", False, False, ("up",), True, True),
            ("stop", True, True, ("down",), False, False),
            ("restart", True, True, ("down", "up"), True, True),
        )
        for action, pre_active, pre_firewall, hooks, final_active, final_firewall in cases:
            with self.subTest(action=action), tempfile.TemporaryDirectory() as directory:
                with patched_layout(pathlib.Path(directory)), mock.patch.object(core, "require_root"):
                    classic_state()
                    runtime = FakeServiceRuntime(
                        active=pre_active,
                        firewall_up=pre_firewall,
                    )

                    def systemd_runner(argv, **kwargs):
                        self.assertFalse(core.mutation_lock_is_held())
                        for hook in hooks:
                            with core.mutation_lock(service_lifecycle=True):
                                core.run_firewall_action_locked(hook)
                            runtime.active = hook == "up"
                        return subprocess.CompletedProcess(argv, 0, b"", b"")

                    with (
                        core.mutation_lock(),
                        mock.patch.object(core, "current_process_identity", return_value=(1234, 5678)),
                        mock.patch.object(core, "process_identity_is_alive", return_value=True),
                        mock.patch.object(core, "service_is_active_exact", side_effect=runtime.service_active),
                        mock.patch.object(core, "firewall_action_postcondition", side_effect=runtime.firewall_postcondition),
                        mock.patch.object(core, "firewall_cleanup", side_effect=runtime.cleanup),
                        mock.patch.object(core, "apply_firewall", side_effect=runtime.apply),
                        mock.patch.object(core, "run", side_effect=systemd_runner),
                    ):
                        core.service_action(action, "awg0")

                    self.assertEqual(runtime.active, final_active)
                    self.assertEqual(runtime.firewall_up, final_firewall)
                    self.assertFalse(core.SERVICE_OPERATION_FILE.exists())

    def test_unrelated_mutator_rejects_while_live_service_owner_has_released_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            with patched_layout(pathlib.Path(directory)), mock.patch.object(core, "require_root"):
                classic_state()
                rejected = []

                def systemd_runner(argv, **kwargs):
                    self.assertFalse(core.mutation_lock_is_held())
                    try:
                        with core.mutation_lock():
                            self.fail("unrelated mutator crossed live service intent")
                    except core.AwgctlError as exc:
                        rejected.append(str(exc))
                    with core.mutation_lock(service_lifecycle=True):
                        core.run_firewall_action_locked("up")
                    return subprocess.CompletedProcess(argv, 0, b"", b"")

                with (
                    core.mutation_lock(),
                    mock.patch.object(core, "current_process_identity", return_value=(1234, 5678)),
                    mock.patch.object(core, "process_identity_is_alive", return_value=True),
                    mock.patch.object(core, "run", side_effect=systemd_runner),
                    mock.patch.object(core, "apply_firewall"),
                    mock.patch.object(core, "firewall_action_postcondition", return_value=True),
                    mock.patch.object(
                        core,
                        "service_is_active_exact",
                        return_value=True,
                        create=True,
                    ),
                ):
                    core.service_action("start", "awg0")

                self.assertEqual(len(rejected), 1)
                self.assertIn("service operation is pending", rejected[0])

    def test_crash_recovery_claims_compensation_before_releasing_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            with patched_layout(pathlib.Path(directory)), mock.patch.object(core, "require_root"):
                classic_state()
                runtime = FakeServiceRuntime(active=True, firewall_up=False)
                document = service_intent_document(
                    phase="compensating",
                    goal="stopped",
                    next_action=1,
                )
                document["generation_sha256"] = core.managed_transition_prestate_digest()
                with core.mutation_lock(service_lifecycle=True):
                    core.compare_and_swap_service_operation_intent(
                        document,
                        expected_operation_id=None,
                        expected_phase=None,
                    )
                rejected = []

                def systemd_runner(argv, **kwargs):
                    self.assertFalse(core.mutation_lock_is_held())
                    try:
                        with core.mutation_lock():
                            self.fail("second recovery crossed claimed compensation")
                    except core.AwgctlError as exc:
                        rejected.append(str(exc))
                    runtime.active = False
                    return subprocess.CompletedProcess(argv, 0, b"", b"")

                with (
                    mock.patch.object(core, "current_process_identity", return_value=(4321, 8765)),
                    mock.patch.object(
                        core,
                        "process_identity_is_alive",
                        side_effect=lambda pid, ticks: (pid, ticks) == (4321, 8765),
                    ),
                    mock.patch.object(core, "service_is_active_exact", side_effect=runtime.service_active),
                    mock.patch.object(core, "firewall_action_postcondition", side_effect=runtime.firewall_postcondition),
                    mock.patch.object(core, "run", side_effect=systemd_runner),
                ):
                    with core.mutation_lock():
                        pass

                self.assertEqual(rejected, ["service operation is pending"])
                self.assertFalse(core.SERVICE_OPERATION_FILE.exists())

    def test_next_lock_reconciles_every_crash_phase_by_proof_or_fail_closed_stop(self):
        cases = (
            ("prepared", 0, True, True, "cancel"),
            ("invoking", 2, True, True, "complete"),
            ("invoking", 0, True, True, "compensate"),
            ("compensating", 1, False, False, "complete-stopped"),
            ("verified", 1, False, False, "terminalize"),
        )
        for phase, next_action, active_before, firewall_before, expected in cases:
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as directory:
                with patched_layout(pathlib.Path(directory)), mock.patch.object(core, "require_root"):
                    classic_state()
                    runtime = FakeServiceRuntime(
                        active=active_before,
                        firewall_up=firewall_before,
                    )
                    goal = "stopped" if phase in {"compensating", "verified"} else "requested"
                    document = service_intent_document(
                        phase=phase,
                        goal=goal,
                        next_action=next_action,
                    )
                    document["generation_sha256"] = core.managed_transition_prestate_digest()
                    with core.mutation_lock(service_lifecycle=True):
                        core.compare_and_swap_service_operation_intent(
                            document,
                            expected_operation_id=None,
                            expected_phase=None,
                        )

                    def systemd_runner(argv, **kwargs):
                        self.assertEqual(
                            argv,
                            ["systemctl", "stop", "awg-quick@awg0.service"],
                        )
                        self.assertFalse(core.mutation_lock_is_held())
                        runtime.active = False
                        return subprocess.CompletedProcess(argv, 0, b"", b"")

                    with (
                        mock.patch.object(core, "process_identity_is_alive", return_value=False),
                        mock.patch.object(core, "service_is_active_exact", side_effect=runtime.service_active),
                        mock.patch.object(core, "firewall_action_postcondition", side_effect=runtime.firewall_postcondition),
                        mock.patch.object(core, "firewall_cleanup", side_effect=runtime.cleanup) as clean,
                        mock.patch.object(core, "run", side_effect=systemd_runner) as runner,
                    ):
                        with core.mutation_lock():
                            pass

                    self.assertFalse(core.SERVICE_OPERATION_FILE.exists())
                    if expected == "compensate":
                        self.assertFalse(runtime.active)
                        clean.assert_called_once_with()
                        runner.assert_called_once()
                    else:
                        clean.assert_not_called()
                        runner.assert_not_called()

    def test_service_failure_compensates_synchronously_and_retains_checkpoint_if_unproven(self):
        for compensation_succeeds in (True, False):
            with self.subTest(compensation_succeeds=compensation_succeeds), tempfile.TemporaryDirectory() as directory:
                with patched_layout(pathlib.Path(directory)), mock.patch.object(core, "require_root"):
                    classic_state()
                    runtime = FakeServiceRuntime(active=True, firewall_up=True)

                    def cleanup():
                        if not compensation_succeeds:
                            raise core.AwgctlError("injected firewall failure")
                        runtime.cleanup()

                    def systemd_runner(argv, **kwargs):
                        if argv[1] == "restart":
                            if compensation_succeeds:
                                return subprocess.CompletedProcess(argv, 0, b"", b"")
                            raise core.AwgctlError("injected systemctl failure")
                        self.assertEqual(argv[1], "stop")
                        runtime.active = False
                        return subprocess.CompletedProcess(argv, 0, b"", b"")

                    with (
                        core.mutation_lock(),
                        mock.patch.object(core, "current_process_identity", return_value=(1234, 5678)),
                        mock.patch.object(core, "process_identity_is_alive", return_value=True),
                        mock.patch.object(core, "service_is_active_exact", side_effect=runtime.service_active),
                        mock.patch.object(core, "firewall_action_postcondition", side_effect=runtime.firewall_postcondition),
                        mock.patch.object(core, "firewall_cleanup", side_effect=cleanup),
                        mock.patch.object(core, "run", side_effect=systemd_runner),
                    ):
                        with self.assertRaisesRegex(
                            core.AwgctlError,
                            "postcondition was not proven|fail-safe service compensation failed",
                        ):
                            core.service_action("restart", "awg0")

                    if compensation_succeeds:
                        self.assertFalse(core.SERVICE_OPERATION_FILE.exists())
                        self.assertFalse(runtime.active)
                        self.assertFalse(runtime.firewall_up)
                    else:
                        retained = core.load_service_operation_intent()
                        self.assertEqual(retained["phase"], "compensating")
                        self.assertEqual(retained["goal"], "stopped")

    def test_lost_manager_lock_leaves_invoking_intent_for_a_later_process(self):
        with tempfile.TemporaryDirectory() as directory:
            with patched_layout(pathlib.Path(directory)), mock.patch.object(core, "require_root"):
                classic_state()
                with (
                    core.mutation_lock(),
                    mock.patch.object(core, "current_process_identity", return_value=(1234, 5678)),
                    mock.patch.object(core, "service_is_active_exact", return_value=True),
                    mock.patch.object(core, "firewall_action_postcondition", return_value=True),
                    mock.patch.object(
                        core,
                        "run",
                        return_value=subprocess.CompletedProcess([], 0, b"", b""),
                    ),
                ):
                    real_flock = core.fcntl.flock

                    def fail_reacquire(descriptor, operation):
                        if operation == core.fcntl.LOCK_EX:
                            raise OSError("injected reacquisition failure")
                        return real_flock(descriptor, operation)

                    with (
                        mock.patch.object(core.fcntl, "flock", side_effect=fail_reacquire),
                        self.assertRaisesRegex(core.AwgctlError, "could not be reacquired"),
                    ):
                        core.service_action("restart", "awg0")

                retained = core.load_service_operation_intent()
                self.assertEqual(retained["phase"], "invoking")
                self.assertEqual(retained["owner_pid"], 1234)

    def test_intent_write_and_terminal_cleanup_failures_are_recoverable(self):
        with tempfile.TemporaryDirectory() as directory:
            with patched_layout(pathlib.Path(directory)), mock.patch.object(core, "require_root"):
                classic_state()
                with (
                    core.mutation_lock(),
                    mock.patch.object(core, "current_process_identity", return_value=(1234, 5678)),
                    mock.patch.object(core, "service_is_active_exact", return_value=False),
                    mock.patch.object(core, "firewall_action_postcondition", side_effect=lambda action: action == "down"),
                    mock.patch.object(core, "atomic_json", side_effect=OSError("injected intent write failure")),
                    mock.patch.object(core, "run") as runner,
                    self.assertRaisesRegex(core.AwgctlError, "intent persistence failed"),
                ):
                    core.service_action("start", "awg0")
                runner.assert_not_called()
                self.assertFalse(core.SERVICE_OPERATION_FILE.exists())

        with tempfile.TemporaryDirectory() as directory:
            with patched_layout(pathlib.Path(directory)), mock.patch.object(core, "require_root"):
                classic_state()
                runtime = FakeServiceRuntime(active=False, firewall_up=False)

                def systemd_runner(argv, **kwargs):
                    with core.mutation_lock(service_lifecycle=True):
                        runtime.firewall_up = True
                        core.run_firewall_action_locked("up")
                    runtime.active = True
                    return subprocess.CompletedProcess(argv, 0, b"", b"")

                with (
                    core.mutation_lock(),
                    mock.patch.object(core, "current_process_identity", return_value=(1234, 5678)),
                    mock.patch.object(core, "process_identity_is_alive", return_value=True),
                    mock.patch.object(core, "service_is_active_exact", side_effect=runtime.service_active),
                    mock.patch.object(core, "firewall_action_postcondition", side_effect=runtime.firewall_postcondition),
                    mock.patch.object(core, "apply_firewall"),
                    mock.patch.object(core, "run", side_effect=systemd_runner),
                    mock.patch.object(
                        core,
                        "delete_service_operation_intent",
                        side_effect=core.AwgctlError("injected terminal cleanup failure"),
                    ),
                    self.assertRaisesRegex(core.AwgctlError, "terminal cleanup failure"),
                ):
                    core.service_action("start", "awg0")

                self.assertEqual(core.load_service_operation_intent()["phase"], "verified")
                self.assertTrue(runtime.active)
                self.assertTrue(runtime.firewall_up)
                with core.mutation_lock():
                    pass
                self.assertFalse(core.SERVICE_OPERATION_FILE.exists())


    def test_direct_firewall_holds_mutation_lock_across_state_check_and_nft_change(self):
        cleanup_entered = threading.Event()
        allow_cleanup = threading.Event()
        transition_created = threading.Event()
        errors = []

        def cleanup():
            cleanup_entered.set()
            allow_cleanup.wait(timeout=5)

        def run_firewall(args):
            try:
                core.dispatch(args)
            except Exception as exc:
                errors.append(exc)

        def run_prepare():
            try:
                with core.mutation_lock(transition_lifecycle=True):
                    core.compare_and_swap_transition(
                        transition_document(
                            "prepared",
                            pending_base=core.PENDING_TRANSITIONS,
                        ),
                        expected_transaction_id=None,
                        expected_state=None,
                    )
                    transition_created.set()
            except Exception as exc:
                errors.append(exc)

        with tempfile.TemporaryDirectory() as directory:
            with (
                patched_layout(pathlib.Path(directory)),
                mock.patch.object(core, "require_root"),
                mock.patch.object(core, "firewall_cleanup", side_effect=cleanup),
                mock.patch.object(core, "firewall_action_postcondition", return_value=True),
            ):
                args = core.build_parser(entrypoint="internal").parse_args(
                    ["_firewall", "down"]
                )
                firewall_thread = threading.Thread(target=run_firewall, args=(args,))
                prepare_thread = threading.Thread(target=run_prepare)
                try:
                    firewall_thread.start()
                    self.assertTrue(cleanup_entered.wait(timeout=5))
                    prepare_thread.start()
                    self.assertFalse(
                        transition_created.wait(timeout=0.1),
                        "prepare crossed a firewall mutation that did not retain the lock",
                    )
                finally:
                    allow_cleanup.set()
                    firewall_thread.join(timeout=5)
                    prepare_thread.join(timeout=5)

                self.assertFalse(firewall_thread.is_alive())
                self.assertFalse(prepare_thread.is_alive())
                self.assertTrue(transition_created.is_set())
                self.assertEqual(errors, [])

    def test_profile_reader_waits_for_complete_multi_client_activation_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            with patched_layout(pathlib.Path(directory)), mock.patch.object(core, "require_root"):
                prepared_state()
                second = core.CLIENTS / "macbook/macbook.conf"
                core.atomic_write(second, "classic second\n", 0o600)
                first = core.CLIENTS / "kat-iphone/kat-iphone.conf"
                first_written = threading.Event()
                allow_finish = threading.Event()
                exported = threading.Event()
                observed = []

                def activation_writer():
                    with core.mutation_lock(transition_lifecycle=True):
                        core.atomic_write(first, "new first\n", 0o600)
                        first_written.set()
                        allow_finish.wait(timeout=5)
                        core.atomic_write(second, "new second\n", 0o600)

                def capture_output(path, content):
                    observed.append(content)
                    exported.set()
                    return path

                def reader():
                    core.cmd_client_export(
                        argparse.Namespace(
                            client_name="macbook",
                            stdout=False,
                            output=pathlib.Path("/tmp/exported.conf"),
                            json=False,
                        )
                    )

                writer_thread = threading.Thread(target=activation_writer)
                reader_thread = threading.Thread(target=reader)
                with (
                    mock.patch.object(core, "write_operator_secret", side_effect=capture_output),
                    mock.patch.object(core, "audit"),
                ):
                    writer_thread.start()
                    self.assertTrue(first_written.wait(timeout=5))
                    reader_thread.start()
                    self.assertFalse(exported.wait(timeout=0.1))
                    allow_finish.set()
                    writer_thread.join(timeout=5)
                    reader_thread.join(timeout=5)

                self.assertFalse(writer_thread.is_alive())
                self.assertFalse(reader_thread.is_alive())
                self.assertEqual(observed, [b"new second\n"])

    def test_every_unrelated_public_and_internal_mutator_is_rejected_before_handler_work(self):
        public_cases = (
            (["start", "--dry-run"], "cmd_service"),
            (["backup", "--dry-run"], "cmd_backup"),
            (["restore", "missing", "--dry-run"], "cmd_restore"),
            (["diagnose", "--dry-run"], "cmd_diagnose"),
            (["update", "apply", "--dry-run"], "cmd_update"),
            (["self-test", "--experimental", "--dry-run"], "cmd_self_test"),
            (["config", "set", "dns", "1.1.1.1", "--dry-run"], "cmd_config_set"),
            (["client", "add", "new-phone", "--dry-run"], "cmd_client_add"),
            (["client", "edit", "kat-iphone", "--owner", "Kat", "--dry-run"], "cmd_client_edit"),
            (["client", "import", "kat-iphone", "--config", "missing", "--dry-run"], "cmd_client_import"),
            (["client", "revoke", "kat-iphone", "--dry-run"], "cmd_client_revoke"),
            (["client", "rotate", "kat-iphone", "--dry-run"], "cmd_client_rotate"),
            (["client", "qr", "kat-iphone", "--dry-run"], "cmd_client_qr"),
            (["client", "expire", "--dry-run"], "cmd_client_expire"),
        )
        internal_cases = (
            (["_firewall", "up"], "cmd_firewall"),
            (["_expire-clients", "--dry-run"], "cmd_expire_clients"),
            (
                [
                    "_initialize-fresh",
                    "--endpoint",
                    "vpn.example.com",
                    "--external-interface",
                    "ens5",
                ],
                "cmd_initialize_fresh",
            ),
            (
                [
                    "_migrate-existing",
                    "--server-config",
                    "server.conf",
                    "--client-config",
                    "client.conf",
                ],
                "cmd_migrate_existing",
            ),
        )
        cases = (
            *(("public", argv, handler) for argv, handler in public_cases),
            *(("internal", argv, handler) for argv, handler in internal_cases),
        )
        for state in ("prepared", "active"):
            for entrypoint, argv, handler_name in cases:
                with (
                    self.subTest(state=state, argv=argv),
                    tempfile.TemporaryDirectory() as directory,
                ):
                    with patched_layout(pathlib.Path(directory)):
                        prepared = transition_document(
                            "prepared",
                            pending_base=core.PENDING_TRANSITIONS,
                        )
                        core.compare_and_swap_transition(
                            prepared,
                            expected_transaction_id=None,
                            expected_state=None,
                        )
                        if state == "active":
                            core.compare_and_swap_transition(
                                transition_document(
                                    "active",
                                    pending_base=core.PENDING_TRANSITIONS,
                                ),
                                expected_transaction_id=TRANSACTION_ID,
                                expected_state="prepared",
                            )
                        args = core.build_parser(entrypoint=entrypoint).parse_args(argv)
                        with (
                            mock.patch.object(core, "require_root"),
                            mock.patch.object(
                                core,
                                handler_name,
                                side_effect=AssertionError(
                                    "handler ran before transition interlock"
                                ),
                            ),
                        ):
                            with self.assertRaisesRegex(
                                core.AwgctlError,
                                "transition.*pending",
                            ):
                                core.dispatch(args)


class TransitionDocumentTests(unittest.TestCase):
    def test_transition_scalar_types_and_uint64_counters_fail_with_controlled_errors(self):
        active = transition_document("active")
        invalid_values = {
            "state": [],
            "mode": {},
            "profile_name": None,
            "client_name": ["kat-iphone"],
            "backup_name": False,
            "ingress_boundary": {},
            "prepared_at": 0,
            "activated_at": True,
            "pre_rx": -1,
            "pre_tx": 2**64,
            "pre_handshake": -1,
        }
        for field, value in invalid_values.items():
            with self.subTest(field=field, value=value):
                candidate = copy.deepcopy(active)
                candidate[field] = value
                try:
                    core.normalize_transition_document(candidate)
                except core.AwgctlError:
                    pass
                except Exception as exc:
                    self.fail(f"{field} leaked an uncontrolled {type(exc).__name__}")
                else:
                    self.fail(f"{field} accepted invalid value {value!r}")

        nested = copy.deepcopy(active)
        nested["pending"]["profiles"][0]["name"] = {"kat": "iphone"}
        with self.assertRaises(core.AwgctlError):
            core.normalize_transition_document(nested)

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
            "cleanup_phase": "complete",
            "profile_updates": [],
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
    def test_listener_inspection_fails_closed_and_detects_ipv6_only_use(self):
        failed = subprocess.CompletedProcess(["ss"], 1, b"", b"permission denied")
        with mock.patch.object(core, "run", return_value=failed):
            with self.assertRaises(core.AwgctlError):
                core.udp_port_is_listening(4242)

        ipv6 = subprocess.CompletedProcess(
            ["ss"],
            0,
            b"UNCONN 0 0 [::]:4242 [::]:*\n",
            b"",
        )
        with mock.patch.object(core, "run", return_value=ipv6):
            self.assertTrue(core.udp_port_is_listening(4242))

    def test_dual_family_port_reservation_holds_both_sockets_and_cleans_partial_failure(self):
        sockets = []

        class FakeSocket:
            def __init__(self, family, kind):
                self.family = family
                self.kind = kind
                self.bound = None
                self.closed = False
                self.options = []
                sockets.append(self)

            def setsockopt(self, *values):
                self.options.append(values)

            def bind(self, address):
                self.bound = address

            def close(self):
                self.closed = True

        reservation = core.acquire_udp_port_reservation(4242, socket_factory=FakeSocket)
        self.assertEqual(
            [(item.family, item.bound) for item in sockets],
            [
                (core.socket.AF_INET, ("0.0.0.0", 4242)),
                (core.socket.AF_INET6, ("::", 4242)),
            ],
        )
        self.assertTrue(all(not item.closed for item in sockets))
        reservation.release()
        self.assertTrue(all(item.closed for item in sockets))

        sockets.clear()

        class RacingSocket(FakeSocket):
            def bind(self, address):
                if self.family == core.socket.AF_INET6:
                    raise OSError("raced")
                super().bind(address)

        with self.assertRaises(core.AwgctlError):
            core.acquire_udp_port_reservation(4242, socket_factory=RacingSocket)
        self.assertTrue(sockets[0].closed)

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
    def test_unqualified_prepare_fails_before_runtime_lock_path_creation(self):
        args = argparse.Namespace(
            mode="awg31",
            profile="russia-ios-v1",
            client="kat-iphone",
            dry_run=False,
            json=True,
        )
        with tempfile.TemporaryDirectory() as directory:
            with (
                patched_layout(pathlib.Path(directory)),
                mock.patch.object(
                    core,
                    "require_awg31_capability",
                    side_effect=core.AwgctlError("installed pair is unqualified"),
                ) as gate,
                mock.patch.object(
                    core,
                    "mutation_lock",
                    side_effect=AssertionError("lock path touched before capability gate"),
                ),
            ):
                with self.assertRaisesRegex(core.AwgctlError, "unqualified"):
                    core.cmd_obfuscation_prepare(args)
                self.assertFalse(core.RUNTIME_DIR.exists())
        gate.assert_called_once_with()

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
                def locked(**kwargs):
                    self.assertTrue(kwargs.get("transition_lifecycle"))
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
                    mock.patch.object(
                        core,
                        "capture_transition_backup_identity",
                        return_value={
                            "manifest_sha256": "de" * 32,
                            "snapshot_sha256": "ef" * 32,
                        },
                    ),
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
    def test_commit_holds_dual_family_reservation_until_immediately_before_reload(self):
        probe = core.socket.socket(core.socket.AF_INET, core.socket.SOCK_DGRAM)
        try:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        finally:
            probe.close()
        reservation = core.acquire_udp_port_reservation(port)
        events = []
        real_atomic_write = core.atomic_write

        with tempfile.TemporaryDirectory() as directory:
            with patched_layout(pathlib.Path(directory)):
                classic_state()
                new_server = core.GENERATED_CONFIG.read_text() + "# replacement\n"

                def assert_reserved(event):
                    self.assertFalse(
                        core.udp_port_bind_available(port),
                        f"reservation was released before {event}",
                    )
                    events.append(event)

                def validate(text):
                    self.assertEqual(text, new_server)
                    assert_reserved("validate")

                def write(path, data, mode=0o600):
                    if path in {core.GENERATED_CONFIG, core.RUNTIME_CONFIG} and data == new_server:
                        assert_reserved(f"write:{path.name}")
                    return real_atomic_write(path, data, mode)

                def release():
                    self.assertFalse(core.udp_port_bind_available(port))
                    reservation.release()
                    events.append("release")

                def reload(action, interface):
                    self.assertEqual((action, interface), ("reload", "awg0"))
                    self.assertEqual(events[-1], "release")
                    competing = core.acquire_udp_port_reservation(port)
                    competing.release()
                    events.append("reload")

                try:
                    with (
                        mock.patch.object(core, "validate_native_server", side_effect=validate),
                        mock.patch.object(core, "atomic_write", side_effect=write),
                        mock.patch.object(core, "is_service_active", return_value=True),
                        mock.patch.object(core, "service_action", side_effect=reload),
                    ):
                        core.commit_server_config(
                            new_server,
                            runtime_action="reload",
                            before_runtime_action=release,
                        )
                finally:
                    reservation.release()

        self.assertEqual(
            events,
            [
                "validate",
                "write:awg0.conf",
                "write:awg0.conf",
                "release",
                "reload",
            ],
        )

    def test_competing_bind_after_release_and_reload_failure_restores_classic_bytes(self):
        probe = core.socket.socket(core.socket.AF_INET, core.socket.SOCK_DGRAM)
        try:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        finally:
            probe.close()
        reservation = core.acquire_udp_port_reservation(port)
        competitor = None

        with tempfile.TemporaryDirectory() as directory:
            with patched_layout(pathlib.Path(directory)):
                classic_state()
                classic_generated = core.GENERATED_CONFIG.read_bytes()
                classic_runtime = core.RUNTIME_CONFIG.read_bytes()
                replacement = classic_generated.decode() + "# replacement\n"
                reloads = 0

                def reload(action, interface):
                    nonlocal competitor, reloads
                    reloads += 1
                    if reloads == 1:
                        competitor = core.acquire_udp_port_reservation(port)
                        raise core.AwgctlError("injected post-release bind conflict")
                    self.assertEqual(core.GENERATED_CONFIG.read_bytes(), classic_generated)
                    self.assertEqual(core.RUNTIME_CONFIG.read_bytes(), classic_runtime)

                try:
                    with (
                        mock.patch.object(core, "validate_native_server"),
                        mock.patch.object(core, "is_service_active", return_value=True),
                        mock.patch.object(core, "service_action", side_effect=reload),
                        mock.patch.object(core, "audit"),
                    ):
                        with self.assertRaisesRegex(core.AwgctlError, "rollback verified"):
                            core.commit_server_config(
                                replacement,
                                runtime_action="reload",
                                before_runtime_action=reservation.release,
                            )
                finally:
                    reservation.release()
                    if competitor is not None:
                        competitor.release()

                self.assertEqual(reloads, 2)
                self.assertEqual(core.GENERATED_CONFIG.read_bytes(), classic_generated)
                self.assertEqual(core.RUNTIME_CONFIG.read_bytes(), classic_runtime)

    def test_every_activation_journal_phase_recovers_exact_id_before_next_command(self):
        for phase in sorted(core.ACTIVATION_JOURNAL_PHASES):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as directory:
                with patched_layout(pathlib.Path(directory)):
                    if phase in {"active", "final-armed"}:
                        document, classic, client, awg31, server, profile, backup = active_state()
                    else:
                        document, classic, client, awg31, server, profile, backup = prepared_state()
                    core.write_activation_journal(
                        TRANSACTION_ID,
                        phase=phase,
                        created_at=document["prepared_at"],
                    )
                    restored = []

                    def restore(name, current, *, now):
                        restored.append((name, current["transaction_id"], now))

                    with (
                        mock.patch.object(core, "restore_obfuscation_backup", side_effect=restore),
                        mock.patch.object(core, "cancel_transition_timeout"),
                        mock.patch.object(core, "cancel_transition_recovery"),
                        mock.patch.object(core, "audit"),
                    ):
                        core.reconcile_transition_recovery_locked()

                    self.assertEqual(len(restored), 1)
                    self.assertEqual(restored[0][0], document["backup_name"])
                    self.assertIsNone(core.load_transition_document(required=False))
                    self.assertIsNone(core.load_activation_journal())
                    outcome = core.load_transition_outcome()
                    self.assertEqual(outcome["transaction_id"], TRANSACTION_ID)
                    self.assertEqual(outcome["outcome"], "rolled_back")
                    self.assertEqual(outcome["cleanup_phase"], "complete")

    def test_proof_floor_is_captured_only_after_reload_and_exact_postcondition(self):
        class ActivationClock(dt.datetime):
            @classmethod
            def now(cls, tz=None):
                return cls(2026, 9, 1, 10, 1, tzinfo=dt.timezone.utc)

        with tempfile.TemporaryDirectory() as directory:
            with patched_layout(pathlib.Path(directory)):
                document, classic, client, awg31, server, profile, backup = prepared_state()
                with mock.patch.object(core, "validate_native_server"):
                    snapshot = core.validate_pending_transition_artifacts(
                        document,
                        [client],
                        now=dt.datetime(2026, 9, 1, 10, 0, tzinfo=dt.timezone.utc),
                    )
                events = []

                class Reservation:
                    held = True

                    def release(self):
                        if self.held:
                            self.held = False
                            events.append("reservation-released")

                def commit(text, *, runtime_action, before_runtime_action):
                    self.assertNotIn("reservation-released", events)
                    events.append("commit-entered")
                    before_runtime_action()
                    self.assertIn("reservation-released", events)
                    events.append("reloaded")
                    return True

                def verified(*args, **kwargs):
                    events.append("postcondition")

                def handshakes(interface):
                    self.assertIn("postcondition", events)
                    events.append("handshake-floor")
                    return {key(3): 1_777_891_200}

                def transfers(interface):
                    self.assertIn("postcondition", events)
                    events.append("counter-floor")
                    return {key(3): (300, 400)}

                with (
                    mock.patch.object(core.dt, "datetime", ActivationClock),
                    mock.patch.object(core, "install_pending_transition_snapshot"),
                    mock.patch.object(core, "verify_installed_transition_snapshot"),
                    mock.patch.object(core, "commit_server_config", side_effect=commit),
                    mock.patch.object(core, "verify_active_transition_postcondition", side_effect=verified),
                    mock.patch.object(core, "load_clients", return_value=[client]),
                    mock.patch.object(core, "handshake_map", side_effect=handshakes),
                    mock.patch.object(core, "transfer_map", side_effect=transfers),
                    mock.patch.object(core, "write_activation_journal", side_effect=lambda *a, **k: events.append(f"journal:{k['phase']}")),
                    mock.patch.object(core, "schedule_transition_recovery", side_effect=lambda *a, **k: events.append("recovery-armed")),
                    mock.patch.object(core, "schedule_transition_timeout", side_effect=lambda *a, **k: events.append("final-scheduled")),
                    mock.patch.object(core, "verify_transition_timeout", side_effect=lambda *a, **k: events.append("final-verified")),
                    mock.patch.object(
                        core,
                        "cancel_transition_recovery",
                        side_effect=lambda *a, **k: (
                            self.assertIn("final-verified", events),
                            events.append("recovery-cancelled"),
                        ),
                    ),
                    mock.patch.object(core, "delete_activation_journal", side_effect=lambda *a, **k: events.append("journal-deleted")),
                ):
                    active = core._install_active_transition(
                        document,
                        snapshot,
                        [client],
                        reservation=Reservation(),
                        timeout="10m",
                    )

                self.assertLess(events.index("reloaded"), events.index("postcondition"))
                self.assertLess(events.index("commit-entered"), events.index("reservation-released"))
                self.assertLess(events.index("reservation-released"), events.index("reloaded"))
                self.assertLess(events.index("postcondition"), events.index("handshake-floor"))
                self.assertLess(events.index("postcondition"), events.index("counter-floor"))
                self.assertLess(events.index("final-scheduled"), events.index("final-verified"))
                self.assertLess(events.index("final-verified"), events.index("recovery-cancelled"))
                self.assertEqual(active["pre_handshake"], 1_777_891_200)
                self.assertEqual((active["pre_rx"], active["pre_tx"]), (300, 400))
                self.assertEqual(active["deadline_at"], "2026-09-01T10:11:00Z")

    def test_activation_reproves_full_snapshot_at_bound_midnight_instant(self):
        instants = iter(
            (
                dt.datetime(2026, 9, 1, 23, 59, 59, tzinfo=dt.timezone.utc),
                dt.datetime(2026, 9, 2, 0, 0, 0, tzinfo=dt.timezone.utc),
            )
        )

        class MidnightClock(dt.datetime):
            @classmethod
            def now(cls, tz=None):
                return next(instants, cls(2026, 9, 2, 0, 0, tzinfo=dt.timezone.utc))

        with tempfile.TemporaryDirectory() as directory:
            with patched_layout(pathlib.Path(directory)):
                document, classic, client, awg31, server, profile, backup = prepared_state()
                verification_now = dt.datetime(
                    2026, 9, 1, 23, 59, 59, tzinfo=dt.timezone.utc
                )
                document, non_target, pending_server = add_pending_managed_client(
                    document,
                    classic,
                    client,
                    awg31,
                    now=verification_now,
                )
                with mock.patch.object(core, "validate_native_server"):
                    snapshot = core.validate_pending_transition_artifacts(
                        document,
                        [client, non_target],
                        now=verification_now,
                    )

                def commit(text, *, runtime_action, before_runtime_action):
                    self.assertEqual(text, pending_server)
                    core.atomic_write(core.GENERATED_CONFIG, text, 0o600)
                    core.atomic_write(core.RUNTIME_CONFIG, text, 0o600)
                    before_runtime_action()
                    return True

                with (
                    mock.patch.object(core.dt, "datetime", MidnightClock),
                    mock.patch.object(core, "validate_native_server"),
                    mock.patch.object(core, "commit_server_config", side_effect=commit),
                    mock.patch.object(core, "safe_awg_query", side_effect=[key(2), "4242"]),
                    mock.patch.object(core, "live_peers", return_value={key(3), key(6)}),
                    mock.patch.object(core, "handshake_map", return_value={key(3): 0}),
                    mock.patch.object(core, "transfer_map", return_value={key(3): (100, 200)}),
                    mock.patch.object(core, "write_activation_journal"),
                    mock.patch.object(core, "schedule_transition_recovery"),
                    mock.patch.object(core, "schedule_transition_timeout"),
                    mock.patch.object(core, "verify_transition_timeout"),
                    mock.patch.object(core, "cancel_transition_recovery"),
                    mock.patch.object(core, "delete_activation_journal"),
                ):
                    with self.assertRaisesRegex(
                        core.AwgctlError,
                        "configuration is inconsistent|installed managed client crossed",
                    ):
                        core._install_active_transition(
                            document,
                            snapshot,
                            [client, non_target],
                            reservation=core.UdpPortReservation([]),
                            timeout="10m",
                        )

    def test_activation_window_rejects_non_target_expiry_at_or_before_deadline(self):
        now = dt.datetime(2026, 9, 1, 23, 50, tzinfo=dt.timezone.utc)
        target = {
            "name": "kat-iphone",
            "management": "managed",
            "status": "active",
            "public_key": key(3),
            "expires": None,
        }
        non_target = {
            "name": "macbook",
            "management": "managed",
            "status": "active",
            "public_key": key(6),
            "expires": "2026-09-02",
        }
        with self.assertRaisesRegex(core.AwgctlError, "expiry.*rollback deadline"):
            core.ensure_activation_window(
                [target, non_target],
                now=now,
                deadline=now + dt.timedelta(minutes=10),
            )
        core.ensure_activation_window(
            [target, {**non_target, "expires": "2026-09-03"}],
            now=now,
            deadline=now + dt.timedelta(minutes=10),
        )

        midnight = dt.datetime(2026, 9, 2, 0, 0, tzinfo=dt.timezone.utc)
        with self.assertRaisesRegex(core.AwgctlError, "installed.*expiry"):
            core.ensure_activation_window(
                [target, non_target],
                now=midnight,
                deadline=midnight + dt.timedelta(minutes=10),
                installed_public_keys={key(3), key(6)},
            )

    def test_final_timer_proof_requires_active_exact_absolute_deadline(self):
        expected_argv = [
            "systemctl",
            "show",
            "--no-pager",
            "--property=ActiveState",
            "--property=NextElapseUSecRealtime",
            "--timestamp=unix",
            f"awgctl-obfuscation-rollback-{TRANSACTION_ID}.timer",
        ]
        valid = subprocess.CompletedProcess(
            expected_argv,
            0,
            b"ActiveState=active\nNextElapseUSecRealtime=@1788257460\n",
            b"",
        )
        with mock.patch.object(core, "run", return_value=valid) as runner:
            core.verify_transition_timeout(
                TRANSACTION_ID,
                deadline_at="2026-09-01T10:11:00Z",
            )
        runner.assert_called_once_with(expected_argv, check=False, timeout=15)

        invalid_outputs = (
            b"ActiveState=inactive\nNextElapseUSecRealtime=@1788257460\n",
            b"ActiveState=active\nNextElapseUSecRealtime=@1788257461\n",
            b"ActiveState=active\nNextElapseUSecRealtime=n/a\n",
            b"ActiveState=active\nUnexpected=value\n",
        )
        for output in invalid_outputs:
            with self.subTest(output=output), mock.patch.object(
                core,
                "run",
                return_value=subprocess.CompletedProcess(expected_argv, 0, output, b""),
            ):
                with self.assertRaisesRegex(core.AwgctlError, "rollback timer.*verified"):
                    core.verify_transition_timeout(
                        TRANSACTION_ID,
                        deadline_at="2026-09-01T10:11:00Z",
                    )

        with mock.patch.object(
            core,
            "run",
            return_value=subprocess.CompletedProcess(expected_argv, 1, b"", b"query failed"),
        ):
            with self.assertRaisesRegex(core.AwgctlError, "rollback timer.*verified"):
                core.verify_transition_timeout(
                    TRANSACTION_ID,
                    deadline_at="2026-09-01T10:11:00Z",
                )
        with mock.patch.object(
            core,
            "run",
            side_effect=core.AwgctlError("systemctl query disclosed an internal detail"),
        ):
            with self.assertRaisesRegex(
                core.AwgctlError,
                "^automatic rollback timer could not be verified$",
            ):
                core.verify_transition_timeout(
                    TRANSACTION_ID,
                    deadline_at="2026-09-01T10:11:00Z",
                )

    def test_final_timer_scheduling_at_deadline_keeps_recovery_armed(self):
        scheduled = False

        class TimerClock(dt.datetime):
            @classmethod
            def now(cls, tz=None):
                instant = (10, 11) if scheduled else (10, 1)
                return cls(
                    2026,
                    9,
                    1,
                    instant[0],
                    instant[1],
                    tzinfo=dt.timezone.utc,
                )

        with tempfile.TemporaryDirectory() as directory:
            with patched_layout(pathlib.Path(directory)):
                document, classic, client, awg31, server, profile, backup = prepared_state()
                with mock.patch.object(core, "validate_native_server"):
                    snapshot = core.validate_pending_transition_artifacts(
                        document,
                        [client],
                        now=dt.datetime(2026, 9, 1, 10, 0, tzinfo=dt.timezone.utc),
                    )

                def schedule(*args, **kwargs):
                    nonlocal scheduled
                    scheduled = True

                recovery_cancel = mock.Mock()
                with (
                    mock.patch.object(core.dt, "datetime", TimerClock),
                    mock.patch.object(core, "install_pending_transition_snapshot"),
                    mock.patch.object(core, "verify_installed_transition_snapshot"),
                    mock.patch.object(
                        core,
                        "commit_server_config",
                        side_effect=lambda text, *, runtime_action, before_runtime_action: (
                            before_runtime_action() is None
                        ),
                    ),
                    mock.patch.object(core, "verify_active_transition_postcondition"),
                    mock.patch.object(core, "load_clients", return_value=[client]),
                    mock.patch.object(core, "handshake_map", return_value={key(3): 0}),
                    mock.patch.object(core, "transfer_map", return_value={key(3): (100, 200)}),
                    mock.patch.object(core, "write_activation_journal"),
                    mock.patch.object(core, "schedule_transition_recovery"),
                    mock.patch.object(core, "schedule_transition_timeout", side_effect=schedule),
                    mock.patch.object(
                        core,
                        "verify_transition_timeout",
                        side_effect=AssertionError("an elapsed timer must not be accepted"),
                    ),
                    mock.patch.object(core, "cancel_transition_recovery", recovery_cancel),
                ):
                    with self.assertRaisesRegex(core.AwgctlError, "armed after its deadline"):
                        core._install_active_transition(
                            document,
                            snapshot,
                            [client],
                            reservation=core.UdpPortReservation([]),
                            timeout="10m",
                        )

                recovery_cancel.assert_not_called()

    def test_delayed_final_clock_recheck_rejects_midnight_crossing_before_artifact_mutation(self):
        instants = iter(
            (
                dt.datetime(2026, 9, 1, 23, 48, tzinfo=dt.timezone.utc),
                dt.datetime(2026, 9, 1, 23, 49, tzinfo=dt.timezone.utc),
                dt.datetime(2026, 9, 1, 23, 50, tzinfo=dt.timezone.utc),
                dt.datetime(2026, 9, 1, 23, 51, tzinfo=dt.timezone.utc),
            )
        )

        class DelayedClock(dt.datetime):
            @classmethod
            def now(cls, tz=None):
                return next(instants)

        class Reservation:
            def release(self):
                pass

        with tempfile.TemporaryDirectory() as directory:
            with patched_layout(pathlib.Path(directory)):
                document, classic, client, awg31, server, profile, backup = prepared_state()
                non_target = {
                    **client,
                    "name": "macbook",
                    "address": "10.77.42.3/32",
                    "public_key": key(6),
                    "private_key": key(7),
                    "psk": key(8),
                    "expires": "2026-09-02",
                }
                installer = mock.Mock(
                    side_effect=AssertionError("expiry crossing reached artifact installation")
                )
                pending_validator = mock.Mock(return_value=mock.sentinel.pending_snapshot)
                with (
                    mock.patch.object(core.dt, "datetime", DelayedClock),
                    mock.patch.object(core, "mutation_lock", return_value=contextlib.nullcontext()),
                    mock.patch.object(core, "ensure_no_drift"),
                    mock.patch.object(core, "verify_transition_backup_precondition"),
                    mock.patch.object(core, "managed_transition_prestate_digest", return_value="ab" * 32),
                    mock.patch.object(core, "ingress_boundary_attestation", return_value="lightsail"),
                    mock.patch.object(core, "require_awg31_capability", return_value=document["capability"]),
                    mock.patch.object(core, "udp_port_is_listening", return_value=False),
                    mock.patch.object(core, "is_service_active", return_value=True),
                    mock.patch.object(core, "acquire_udp_port_reservation", return_value=Reservation()),
                    mock.patch.object(core, "load_clients", return_value=[client, non_target]),
                    mock.patch.object(
                        core,
                        "validate_pending_transition_artifacts",
                        pending_validator,
                    ),
                    mock.patch.object(core, "_install_active_transition", installer),
                    mock.patch.object(core, "restore_obfuscation_backup"),
                    mock.patch.object(core, "cancel_transition_timeout"),
                    mock.patch.object(core, "cancel_transition_recovery"),
                ):
                    with self.assertRaisesRegex(core.AwgctlError, "classic state restored"):
                        core.cmd_obfuscation_activate(
                            argparse.Namespace(
                                transaction_id=TRANSACTION_ID,
                                ingress_ready=True,
                                timeout="10m",
                                json=True,
                            )
                        )
                installer.assert_not_called()
                pending_validator.assert_called_once()

    def test_backup_identity_rejects_valid_substitution_and_hardlinks(self):
        now = dt.datetime(2026, 9, 1, 10, 1, tzinfo=dt.timezone.utc)
        with tempfile.TemporaryDirectory() as directory:
            with patched_layout(pathlib.Path(directory)):
                document, classic, client, awg31, server, profile, backup = prepared_state()
                def pubkey_runner(argv, **kwargs):
                    supplied = kwargs["input_data"].decode().strip()
                    public = {key(1): key(2), key(4): key(3)}[supplied]
                    return subprocess.CompletedProcess(argv, 0, (public + "\n").encode(), b"")

                anchored_reader = core.read_protected_tree

                def capture_then_swap(path, **kwargs):
                    snapshot = anchored_reader(path, **kwargs)
                    core.atomic_write(
                        backup / "config/server.json",
                        b'{"substituted": true}\n',
                        0o600,
                    )
                    return snapshot

                with (
                    mock.patch.object(core, "read_protected_tree", side_effect=capture_then_swap),
                    mock.patch.object(core, "run", side_effect=pubkey_runner),
                    mock.patch.object(core, "validate_native_server"),
                    mock.patch.object(core, "validate_nftables_text"),
                ):
                    try:
                        snapshot = core.verify_transition_backup_precondition(
                            document,
                            classic,
                            now=now,
                        )
                    except core.AwgctlError as exc:
                        self.fail(f"valid immutable backup identity was rejected: {exc}")

                metadata_path = backup / "clients/kat-iphone/metadata.json"
                metadata = json.loads(metadata_path.read_text())
                metadata["owner"] = "Substituted Owner"
                core.atomic_json(metadata_path, metadata, 0o600)
                manifest = core.create_backup_manifest(
                    backup,
                    product_version=core.VERSION,
                    created_at="2026-09-01T10:00:00Z",
                )
                core.atomic_json(backup / "manifest.json", manifest, 0o600)
                with (
                    mock.patch.object(core, "mutation_lock", return_value=contextlib.nullcontext()),
                    mock.patch.object(
                        core,
                        "run",
                        side_effect=pubkey_runner,
                    ),
                    mock.patch.object(core, "validate_native_server"),
                    mock.patch.object(core, "validate_nftables_text"),
                    self.assertRaisesRegex(core.AwgctlError, "identity"),
                ):
                    core.verify_transition_backup_precondition(document, classic, now=now)

                metadata_path.unlink()
                core.os.link(core.CONFIG_FILE, metadata_path)
                with self.assertRaisesRegex(core.AwgctlError, "unsafe"):
                    core.read_protected_tree(backup)

    def test_pending_inventory_is_exact_and_install_uses_the_validated_byte_snapshot(self):
        now = dt.datetime(2026, 9, 1, 10, 1, tzinfo=dt.timezone.utc)
        with tempfile.TemporaryDirectory() as directory:
            with patched_layout(pathlib.Path(directory)):
                document, classic, client, awg31, server, profile, backup = prepared_state()
                pending_root = pathlib.Path(document["pending"]["root"])

                (pending_root / "unexpected").mkdir(mode=0o700)
                with self.assertRaisesRegex(core.AwgctlError, "inventory"):
                    core.validate_pending_transition_artifacts(
                        document,
                        [client],
                        now=now,
                    )
                (pending_root / "unexpected").rmdir()

                core.atomic_write(pending_root / "extra", b"surprise", 0o600)
                document["pending_sha256"] = core.pending_transition_artifact_digest(
                    pending_root
                )
                with self.assertRaisesRegex(core.AwgctlError, "inventory"):
                    core.validate_pending_transition_artifacts(
                        document,
                        [client],
                        now=now,
                    )
                (pending_root / "extra").unlink()
                document["pending_sha256"] = core.pending_transition_artifact_digest(
                    pending_root
                )

                with mock.patch.object(core, "validate_native_server"):
                    snapshot = core.validate_pending_transition_artifacts(
                        document,
                        [client],
                        now=now,
                    )
                pathlib.Path(document["pending"]["server_config"]).write_text(
                    "swapped server\n"
                )
                pathlib.Path(document["pending"]["profiles"][0]["config"]).write_text(
                    "swapped profile\n"
                )
                pathlib.Path(document["pending"]["profiles"][0]["qr"]).write_bytes(
                    b"swapped qr"
                )
                core.install_pending_transition_snapshot(document, snapshot)

                self.assertEqual(core.CONFIG_FILE.read_bytes(), snapshot.server_state)
                self.assertEqual(core.HEADER_PROTECTION_KEY.read_bytes(), snapshot.header_key)
                self.assertEqual(
                    (core.CLIENTS / "kat-iphone/kat-iphone.conf").read_bytes(),
                    snapshot.profile_bytes("kat-iphone"),
                )
                self.assertEqual(
                    (core.CLIENTS / "kat-iphone/kat-iphone.png").read_bytes(),
                    snapshot.qr_bytes("kat-iphone"),
                )

                (core.CLIENTS / "kat-iphone/kat-iphone.conf").write_text("corrupt")
                with self.assertRaisesRegex(core.AwgctlError, "installed.*snapshot"):
                    core.verify_installed_transition_snapshot(document, snapshot)

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

                def commit(text, *, runtime_action, before_runtime_action):
                    self.assertEqual(text, server)
                    self.assertEqual(runtime_action, "reload")
                    core.atomic_write(core.GENERATED_CONFIG, text, 0o600)
                    core.atomic_write(core.RUNTIME_CONFIG, text, 0o600)
                    before_runtime_action()
                    reloads.append("reload")
                    return True

                def runner(argv, **kwargs):
                    run_calls.append((list(argv), kwargs))
                    if argv[:2] == ["systemctl", "show"]:
                        return subprocess.CompletedProcess(
                            argv,
                            0,
                            b"ActiveState=active\nNextElapseUSecRealtime=@1788257460\n",
                            b"",
                        )
                    return subprocess.CompletedProcess(
                        argv,
                        3 if argv[:3] == ["systemctl", "is-active", "--quiet"] else 0,
                        b"",
                        b"",
                    )

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
                    mock.patch.object(
                        core,
                        "acquire_udp_port_reservation",
                        return_value=mock.Mock(),
                    ),
                    mock.patch.object(core, "validate_native_server"),
                    mock.patch.object(core, "is_service_active", return_value=True),
                    mock.patch.object(
                        core,
                        "transfer_map",
                        return_value={key(3): (100, 200)},
                        create=True,
                    ),
                    mock.patch.object(core, "handshake_map", return_value={key(3): 0}),
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
                self.assertEqual(ActivationClock.calls, 7)
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
                    run_calls[0][0],
                    [
                        "systemd-run",
                        "--quiet",
                        "--collect",
                        "--unit",
                        f"awgctl-obfuscation-recovery-{TRANSACTION_ID}",
                        "--on-active=10m",
                        str(core.INTERNAL_ENTRYPOINT),
                        "_obfuscation-timeout",
                        TRANSACTION_ID,
                    ],
                )
                self.assertEqual(
                    run_calls[1][0],
                    [
                        "systemd-run",
                        "--quiet",
                        "--collect",
                        "--unit",
                        f"awgctl-obfuscation-rollback-{TRANSACTION_ID}",
                        "--timer-property=AccuracySec=1s",
                        "--on-calendar=2026-09-01T10:11:00Z",
                        str(core.INTERNAL_ENTRYPOINT),
                        "_obfuscation-timeout",
                        TRANSACTION_ID,
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
                recovery_events = []

                def commit(text, *, runtime_action, before_runtime_action):
                    core.atomic_write(core.GENERATED_CONFIG, text, 0o600)
                    core.atomic_write(core.RUNTIME_CONFIG, text, 0o600)
                    before_runtime_action()
                    return True

                def runner(argv, **kwargs):
                    systemd_calls.append(list(argv))
                    if argv[0] == "systemd-run":
                        if any(
                            item == f"awgctl-obfuscation-recovery-{TRANSACTION_ID}"
                            for item in argv
                        ):
                            recovery_events.append("recovery-armed")
                            return subprocess.CompletedProcess(argv, 0, b"", b"")
                        if any(
                            item == f"awgctl-obfuscation-rollback-{TRANSACTION_ID}"
                            for item in argv
                        ):
                            recovery_events.append("final-timer-failed")
                            raise core.AwgctlError("timer creation failed")
                        raise AssertionError(f"unexpected transient unit: {argv}")
                    if argv[:2] == ["systemctl", "stop"]:
                        if any("obfuscation-recovery" in item for item in argv):
                            recovery_events.append("recovery-cancelled")
                        return subprocess.CompletedProcess(argv, 0, b"", b"")
                    if argv[:3] == ["systemctl", "is-active", "--quiet"]:
                        return subprocess.CompletedProcess(argv, 3, b"", b"")
                    raise AssertionError(f"unexpected command: {argv}")

                def restore(backup_name, expected_document, *, now):
                    recovery_events.append("classic-restored")
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
                    mock.patch.object(
                        core,
                        "acquire_udp_port_reservation",
                        return_value=mock.Mock(),
                    ),
                    mock.patch.object(core, "validate_native_server"),
                    mock.patch.object(core, "is_service_active", return_value=True),
                    mock.patch.object(core, "transfer_map", return_value={key(3): (100, 200)}),
                    mock.patch.object(core, "handshake_map", return_value={key(3): 0}),
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
                self.assertEqual(
                    recovery_events[:3],
                    ["recovery-armed", "final-timer-failed", "classic-restored"],
                    "the recovery timer must remain armed until classic restore is proven",
                )
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
                    mock.patch.object(
                        core,
                        "acquire_udp_port_reservation",
                        return_value=mock.Mock(),
                    ),
                    mock.patch.object(core, "is_service_active", return_value=True),
                    mock.patch.object(core, "restore_obfuscation_backup"),
                    mock.patch.object(core, "cancel_transition_timeout"),
                    mock.patch.object(core, "cancel_transition_recovery"),
                    mock.patch.object(
                        core,
                        "commit_server_config",
                        side_effect=AssertionError("tampered artifacts must not be installed"),
                    ),
                ):
                    with self.assertRaisesRegex(core.AwgctlError, "classic state restored"):
                        core.cmd_obfuscation_activate(args)

                self.assertIsNone(core.load_transition_document(required=False))
                self.assertEqual(core.load_config()["obfuscation"]["mode"], "classic")
                self.assertEqual(
                    {path: path.read_bytes() for path in active_paths}, active_paths
                )
                self.assertEqual(core.load_transition_outcome()["outcome"], "rolled_back")


class ObfuscationConfirmTests(unittest.TestCase):
    def test_complete_outcome_coexisting_with_exact_current_resumes_cleanup(self):
        args = argparse.Namespace(transaction_id=TRANSACTION_ID, json=True)
        with tempfile.TemporaryDirectory() as directory:
            with patched_layout(pathlib.Path(directory)):
                active, classic, client, awg31, server, profile, backup = active_state()
                outcome = core.normalize_transition_outcome(
                    {
                        "schema_version": 1,
                        "transaction_id": TRANSACTION_ID,
                        "outcome": "confirmed",
                        "reason": "confirmed",
                        "completed_at": "2026-09-01T10:02:00Z",
                        "client_name": "kat-iphone",
                        "profile_name": "russia-ios-v1",
                        "old_port": 55323,
                        "new_port": 4242,
                        "cleanup_phase": "complete",
                        "profile_updates": [
                            {
                                "name": "kat-iphone",
                                "from_revision": 3,
                                "to_revision": 4,
                            }
                        ],
                    }
                )
                core.atomic_json(core.TRANSITION_OUTCOME_FILE, outcome, 0o600)
                pending_root = pathlib.Path(active["pending"]["root"])

                with (
                    mock.patch.object(core, "cancel_transition_recovery"),
                ):
                    core.reconcile_transition_recovery_locked()

                self.assertIsNone(core.load_transition_document(required=False))
                self.assertFalse(pending_root.exists())

                with (
                    mock.patch.object(
                        core, "mutation_lock", return_value=contextlib.nullcontext()
                    ),
                    mock.patch.object(core, "cancel_transition_recovery"),
                    contextlib.redirect_stdout(io.StringIO()),
                ):
                    self.assertEqual(core.cmd_obfuscation_confirm(args), 0)

                metadata = json.loads(
                    (core.CLIENTS / "kat-iphone/metadata.json").read_text()
                )
                self.assertEqual(metadata["profile_revision"], 4)
                self.assertEqual(metadata["distribution_status"], "pending")

    def test_complete_outcome_never_interferes_with_a_later_transaction(self):
        outcome = core.normalize_transition_outcome(
            {
                "schema_version": 1,
                "transaction_id": TRANSACTION_ID,
                "outcome": "rolled_back",
                "reason": "operator",
                "completed_at": "2026-09-01T10:02:00Z",
                "client_name": "kat-iphone",
                "profile_name": "russia-ios-v1",
                "old_port": 55323,
                "new_port": 4242,
                "cleanup_phase": "complete",
                "profile_updates": [],
            }
        )
        later = {"transaction_id": "fedcba9876543210fedcba9876543210"}
        with (
            mock.patch.object(core, "load_transition_outcome", return_value=outcome),
            mock.patch.object(core, "load_transition_document", return_value=later),
            mock.patch.object(core, "load_activation_journal", return_value=None),
            mock.patch.object(core, "resume_transition_cleanup") as resume,
        ):
            core.reconcile_transition_recovery_locked()
        resume.assert_not_called()

    def test_terminal_cleanup_resumes_after_each_authoritative_checkpoint_boundary(self):
        boundaries = (
            "after-outcome",
            "after-metadata",
            "after-pending",
            "after-current",
        )
        for boundary in boundaries:
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as directory:
                with patched_layout(pathlib.Path(directory)):
                    active, classic, client, awg31, server, profile, backup = active_state()
                    outcome = core.begin_transition_outcome(
                        active,
                        outcome="confirmed",
                        reason="confirmed",
                        completed_at="2026-09-01T10:02:00Z",
                        profile_updates=[
                            {"name": "kat-iphone", "from_revision": 3, "to_revision": 4}
                        ],
                    )

                    patcher = contextlib.nullcontext()
                    if boundary != "after-outcome":
                        helper_name = {
                            "after-metadata": "apply_confirmed_profile_updates",
                            "after-pending": "remove_transition_pending",
                            "after-current": "remove_current_transition",
                        }[boundary]
                        original = getattr(core, helper_name)
                        fired = False

                        def crash_after(*args, _original=original, **kwargs):
                            nonlocal fired
                            result = _original(*args, **kwargs)
                            if not fired:
                                fired = True
                                raise RuntimeError("injected crash after durable boundary")
                            return result

                        patcher = mock.patch.object(core, helper_name, side_effect=crash_after)
                    with patcher, mock.patch.object(core, "cancel_transition_recovery"):
                        if boundary == "after-outcome":
                            pass
                        else:
                            with self.assertRaisesRegex(RuntimeError, "injected crash"):
                                core.resume_transition_cleanup(active, outcome)

                    with (
                        mock.patch.object(core, "mutation_lock", return_value=contextlib.nullcontext()),
                        mock.patch.object(core, "cancel_transition_recovery"),
                        contextlib.redirect_stdout(io.StringIO()),
                    ):
                        self.assertEqual(
                            core.cmd_obfuscation_confirm(
                                argparse.Namespace(transaction_id=TRANSACTION_ID, json=True)
                            ),
                            0,
                        )
                    completed = core.load_transition_outcome()

                    self.assertEqual(completed["cleanup_phase"], "complete")
                    self.assertIsNone(core.load_transition_document(required=False))
                    self.assertFalse(pathlib.Path(active["pending"]["root"]).exists())
                    metadata = json.loads((core.CLIENTS / "kat-iphone/metadata.json").read_text())
                    self.assertEqual(metadata["profile_revision"], 4)
                    self.assertEqual(metadata["distribution_status"], "pending")

    def test_confirm_rechecks_every_active_and_pending_postcondition_before_timer_mutation(self):
        class ConfirmClock(dt.datetime):
            @classmethod
            def now(cls, tz=None):
                return cls(2026, 9, 1, 10, 2, tzinfo=dt.timezone.utc)

        cases = ("profile", "qr", "pending", "generated", "runtime", "live-port", "live-peer")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                with patched_layout(pathlib.Path(directory)):
                    active, classic, client, awg31, server, profile, backup = active_state()
                    metadata_before = (core.CLIENTS / "kat-iphone/metadata.json").read_bytes()
                    transition_before = core.TRANSITION_FILE.read_bytes()
                    if case == "profile":
                        core.atomic_write(core.CLIENTS / "kat-iphone/kat-iphone.conf", "tampered\n", 0o600)
                    elif case == "qr":
                        core.atomic_write(core.CLIENTS / "kat-iphone/kat-iphone.png", b"tampered", 0o600)
                    elif case == "pending":
                        core.atomic_write(pathlib.Path(active["pending"]["server_config"]), "tampered\n", 0o600)
                    elif case == "generated":
                        core.atomic_write(core.GENERATED_CONFIG, "tampered\n", 0o600)
                    elif case == "runtime":
                        core.atomic_write(core.RUNTIME_CONFIG, "tampered\n", 0o600)

                    timer = mock.Mock(side_effect=AssertionError("timer mutated before exact postcondition"))
                    with (
                        mock.patch.object(core.dt, "datetime", ConfirmClock),
                        mock.patch.object(core, "mutation_lock", return_value=contextlib.nullcontext()),
                        mock.patch.object(core, "validate_native_server"),
                        mock.patch.object(core, "is_service_active", return_value=True),
                        mock.patch.object(core, "safe_awg_query", side_effect=lambda interface, field: key(2) if field == "public-key" else ("9999" if case == "live-port" else "4242")),
                        mock.patch.object(core, "live_peers", return_value=set() if case == "live-peer" else {key(3)}),
                        mock.patch.object(core, "handshake_map", return_value={key(3): int(ConfirmClock.now().timestamp()) - 30}),
                        mock.patch.object(core, "transfer_map", return_value={key(3): (101, 201)}),
                        mock.patch.object(core, "cancel_transition_timeout", timer),
                    ):
                        with self.assertRaises(core.AwgctlError):
                            core.cmd_obfuscation_confirm(
                                argparse.Namespace(transaction_id=TRANSACTION_ID, json=True)
                            )

                    timer.assert_not_called()
                    self.assertEqual((core.CLIENTS / "kat-iphone/metadata.json").read_bytes(), metadata_before)
                    self.assertEqual(core.TRANSITION_FILE.read_bytes(), transition_before)
                    self.assertIsNone(core.load_transition_outcome())

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
                    if argv[0] == "systemd-run":
                        return subprocess.CompletedProcess(argv, 0, b"", b"")
                    if argv[:2] == ["systemctl", "stop"]:
                        return subprocess.CompletedProcess(argv, 0, b"", b"")
                    if argv[:3] == ["systemctl", "is-active", "--quiet"]:
                        return subprocess.CompletedProcess(argv, 3, b"", b"")
                    raise AssertionError(f"unexpected command: {argv}")

                with (
                    mock.patch.object(core.dt, "datetime", ConfirmClock),
                    mock.patch.object(core, "mutation_lock", return_value=contextlib.nullcontext()),
                    mock.patch.object(core, "validate_native_server"),
                    mock.patch.object(core, "is_service_active", return_value=True),
                    mock.patch.object(core, "safe_awg_query", side_effect=lambda interface, field: key(2) if field == "public-key" else "4242"),
                    mock.patch.object(core, "live_peers", return_value={key(3)}),
                    mock.patch.object(core, "handshake_map", return_value={key(3): handshake}),
                    mock.patch.object(core, "transfer_map", return_value={key(3): (101, 201)}),
                    mock.patch.object(core, "run", side_effect=runner),
                    mock.patch.object(core, "audit"),
                    contextlib.redirect_stdout(output),
                ):
                    try:
                        result = core.cmd_obfuscation_confirm(args)
                        with contextlib.redirect_stdout(io.StringIO()):
                            retry = core.cmd_obfuscation_confirm(args)
                    except core.AwgctlError as exc:
                        self.fail(f"confirm is incomplete: {exc}")

                self.assertEqual((result, retry), (0, 0))
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
                    next(call for call in systemd_calls if call[:2] == ["systemctl", "stop"]),
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
            ("rx-only", (101, 200), 3, handshake, 0),
            ("tx-only", (100, 201), 3, handshake, 0),
            ("future-handshake", (101, 201), 3, handshake + 31, 0),
            ("preserved-classic-stats", (101, 201), 3, handshake, handshake),
            ("timer-still-active", (101, 201), 0, handshake, 0),
            ("timer-query-failed", (101, 201), 1, handshake, 0),
        )
        for label, counters, timer_status, observed_handshake, handshake_floor in cases:
            with self.subTest(case=label), tempfile.TemporaryDirectory() as directory:
                with patched_layout(pathlib.Path(directory)):
                    active, classic, client, awg31, server, profile, backup = active_state()
                    if handshake_floor:
                        active["pre_handshake"] = handshake_floor
                        core.atomic_json(core.TRANSITION_FILE, active, 0o600)
                    metadata_path = core.CLIENTS / "kat-iphone/metadata.json"
                    metadata_before = metadata_path.read_bytes()
                    transition_before = core.TRANSITION_FILE.read_bytes()
                    pending_root = pathlib.Path(active["pending"]["root"])

                    def runner(argv, **kwargs):
                        if argv[0] == "systemd-run":
                            return subprocess.CompletedProcess(argv, 0, b"", b"")
                        if argv[:2] == ["systemctl", "stop"]:
                            return subprocess.CompletedProcess(argv, 0, b"", b"")
                        if argv[:3] == ["systemctl", "is-active", "--quiet"]:
                            return subprocess.CompletedProcess(
                                argv, timer_status, b"", b""
                            )
                        raise AssertionError(f"unexpected command: {argv}")

                    with (
                        mock.patch.object(core.dt, "datetime", ConfirmClock),
                        mock.patch.object(core, "mutation_lock", return_value=contextlib.nullcontext()),
                        mock.patch.object(core, "validate_native_server"),
                        mock.patch.object(core, "is_service_active", return_value=True),
                        mock.patch.object(core, "safe_awg_query", side_effect=lambda interface, field: key(2) if field == "public-key" else "4242"),
                        mock.patch.object(core, "live_peers", return_value={key(3)}),
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
    def test_internal_timeout_uses_bounded_lock_wait_and_never_restores_without_it(self):
        seen = []

        @contextlib.contextmanager
        def contended(**kwargs):
            seen.append(kwargs)
            raise core.AwgctlError("mutation lock acquisition timeout")
            yield

        with (
            mock.patch.object(core, "mutation_lock", side_effect=contended),
            mock.patch.object(
                core,
                "restore_obfuscation_backup",
                side_effect=AssertionError("timeout restored without the mutation lock"),
            ),
        ):
            with self.assertRaisesRegex(core.AwgctlError, "lock.*timeout"):
                core.cmd_obfuscation_timeout(
                    argparse.Namespace(transaction_id=TRANSACTION_ID, json=False)
                )
        self.assertEqual(
            seen,
            [{"timeout_seconds": 5, "transition_lifecycle": True}],
        )

    def test_real_transaction_backup_restore_uses_captured_snapshot_and_proves_classic_state(self):
        now = dt.datetime(2026, 9, 1, 10, 3, tzinfo=dt.timezone.utc)
        with tempfile.TemporaryDirectory() as directory:
            with patched_layout(pathlib.Path(directory)):
                active, classic, client, awg31, server, profile, backup = active_state()

                def pubkey_runner(argv, **kwargs):
                    supplied = kwargs["input_data"].decode().strip()
                    public = {key(1): key(2), key(4): key(3)}[supplied]
                    return subprocess.CompletedProcess(argv, 0, (public + "\n").encode(), b"")

                with (
                    mock.patch.object(core, "run", side_effect=pubkey_runner),
                    mock.patch.object(core, "validate_native_server"),
                    mock.patch.object(core, "validate_nftables_text"),
                    mock.patch.object(core, "service_action") as reload_service,
                    mock.patch.object(core, "safe_awg_query", side_effect=lambda interface, field: key(2) if field == "public-key" else "55323"),
                    mock.patch.object(core, "live_peers", return_value={key(3)}),
                ):
                    core.restore_obfuscation_backup(
                        active["backup_name"],
                        active,
                        now=now,
                    )

                self.assertEqual(core.load_config(), classic)
                self.assertEqual(core.load_config()["obfuscation"]["mode"], "classic")
                self.assertFalse(core.HEADER_PROTECTION_KEY.exists())
                self.assertEqual(core.GENERATED_CONFIG.read_bytes(), core.RUNTIME_CONFIG.read_bytes())
                reload_service.assert_called_once_with("reload", "awg0")
                self.assertTrue(backup.is_dir(), "ordinary backup must be retained")

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
    def test_status_and_health_hold_one_locked_snapshot_for_their_complete_read(self):
        events = []

        @contextlib.contextmanager
        def snapshot_lock(*, transition_lifecycle):
            self.assertTrue(transition_lifecycle)
            events.append("locked")
            try:
                yield
            finally:
                events.append("unlocked")

        def status_reader(args):
            self.assertEqual(events, ["locked"])
            events.append("status-read")
            return 17

        def health_reader(args):
            self.assertEqual(events, ["locked", "status-read", "unlocked", "locked"])
            events.append("health-read")
            return 23

        with (
            mock.patch.object(core, "mutation_lock", side_effect=snapshot_lock),
            mock.patch.object(core, "_cmd_status_locked", side_effect=status_reader),
            mock.patch.object(core, "_cmd_health_locked", side_effect=health_reader),
        ):
            self.assertEqual(core.cmd_status(argparse.Namespace(json=True)), 17)
            self.assertEqual(core.cmd_health(argparse.Namespace(json=True)), 23)

        self.assertEqual(
            events,
            [
                "locked",
                "status-read",
                "unlocked",
                "locked",
                "health-read",
                "unlocked",
            ],
        )

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
                    mock.patch.object(core, "mutation_lock", return_value=contextlib.nullcontext()),
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
                    mock.patch.object(core, "mutation_lock", return_value=contextlib.nullcontext()),
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
                    mock.patch.object(core, "mutation_lock", return_value=contextlib.nullcontext()),
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
