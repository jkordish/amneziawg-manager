import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


REPO_ROOT = pathlib.Path(__file__).parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))


class InstallationSettingsTests(unittest.TestCase):
    def test_defaults_create_separate_staging_and_operator_identities(self):
        from awginstall.settings import resolve_installation_settings

        settings = resolve_installation_settings(sudo_user="ubuntu")

        self.assertEqual(settings.staging_user, "awgctl")
        self.assertEqual(settings.staging_group, "awgctl")
        self.assertEqual(settings.staging_root, pathlib.Path("/var/lib/amneziawg-manager"))
        self.assertEqual(settings.operator_group, "awgctl-admin")
        self.assertEqual(settings.operators, ("ubuntu",))
        self.assertEqual(settings.sudo_policy, "scoped-nopasswd")
        self.assertEqual(settings.systemd_hardening, "conservative")
        self.assertEqual(settings.default_dns, ("1.1.1.2", "1.0.0.2"))

    def test_json_is_overridden_by_explicit_cli_values(self):
        from awginstall.settings import resolve_installation_settings

        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "install.json"
            path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "staging": {
                            "user": "vpn-stage",
                            "group": "vpn-stage",
                            "uid": 450,
                            "gid": 451,
                            "root": "/var/lib/vpn-stage",
                        },
                        "operators": {
                            "group": "vpn-operators",
                            "users": ["alice"],
                            "enroll_sudo_invoker": False,
                            "sudo_policy": "existing-sudo",
                        },
                        "systemd": {"hardening": "off"},
                        "dns": {"default": "cloudflare"},
                    }
                ),
                encoding="utf-8",
            )

            settings = resolve_installation_settings(
                settings_path=path,
                sudo_user="ubuntu",
                overrides={
                    "staging_user": "custom-stage",
                    "operator_group": "custom-admin",
                    "operators": ["bob"],
                    "default_dns": "9.9.9.9,149.112.112.112",
                },
            )

        self.assertEqual(settings.staging_user, "custom-stage")
        self.assertEqual(settings.staging_group, "vpn-stage")
        self.assertEqual(settings.operator_group, "custom-admin")
        self.assertEqual(settings.operators, ("alice", "bob"))
        self.assertEqual(settings.sudo_policy, "existing-sudo")
        self.assertEqual(settings.systemd_hardening, "off")
        self.assertEqual(settings.default_dns, ("9.9.9.9", "149.112.112.112"))

    def test_settings_reject_unknown_fields_and_unsafe_staging_roots(self):
        from awginstall.settings import SettingsError, resolve_installation_settings

        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "install.json"
            path.write_text('{"schema_version": 1, "mystery": true}', encoding="utf-8")
            with self.assertRaisesRegex(SettingsError, "unknown installation settings"):
                resolve_installation_settings(settings_path=path)

        for unsafe in ("/", "/opt/awgctl", "/var/lib", "relative/path"):
            with self.subTest(unsafe=unsafe), self.assertRaisesRegex(SettingsError, "staging root"):
                resolve_installation_settings(overrides={"staging_root": unsafe})

    def test_settings_reject_privileged_or_invalid_identity_names(self):
        from awginstall.settings import SettingsError, resolve_installation_settings

        for field, value in (
            ("staging_user", "root"),
            ("staging_group", "sudo"),
            ("operator_group", "docker"),
            ("staging_user", "Bad User"),
        ):
            with self.subTest(field=field, value=value), self.assertRaises(SettingsError):
                resolve_installation_settings(overrides={field: value})


class IdentityPlanTests(unittest.TestCase):
    def test_new_identity_plan_creates_locked_staging_and_separate_operator_group(self):
        from awginstall.identity import IdentitySnapshot, build_identity_plan
        from awginstall.settings import resolve_installation_settings

        settings = resolve_installation_settings(
            sudo_user="ubuntu",
            overrides={"operators": ["deploy"]},
        )
        snapshot = IdentitySnapshot(
            users={"ubuntu": None, "deploy": None},
            groups={},
            locked_users=set(),
            supplementary_groups={},
        )

        plan = build_identity_plan(settings, snapshot, allow_existing=False)

        self.assertEqual(
            plan.commands,
            (
                ("groupadd", "--system", "awgctl"),
                (
                    "useradd", "--system", "--gid", "awgctl", "--home-dir",
                    "/var/lib/amneziawg-manager", "--create-home", "--shell",
                    "/usr/sbin/nologin", "--comment", "AmneziaWG Manager staging account",
                    "awgctl",
                ),
                ("groupadd", "--system", "awgctl-admin"),
                ("usermod", "--append", "--groups", "awgctl-admin", "deploy"),
                ("usermod", "--append", "--groups", "awgctl-admin", "ubuntu"),
            ),
        )
        self.assertEqual(plan.created_users, ("awgctl",))
        self.assertEqual(plan.created_groups, ("awgctl", "awgctl-admin"))

    def test_existing_staging_identity_must_match_and_be_explicitly_adopted(self):
        from awginstall.identity import GroupRecord, IdentityError, IdentitySnapshot, UserRecord, build_identity_plan
        from awginstall.settings import resolve_installation_settings

        settings = resolve_installation_settings(sudo_user=None)
        snapshot = IdentitySnapshot(
            users={
                "awgctl": UserRecord(
                    name="awgctl", uid=450, gid=451,
                    home="/var/lib/amneziawg-manager", shell="/usr/sbin/nologin",
                )
            },
            groups={
                "awgctl": GroupRecord("awgctl", 451, ()),
                "awgctl-admin": GroupRecord("awgctl-admin", 452, ()),
            },
            locked_users={"awgctl"},
            supplementary_groups={"awgctl": ()},
        )

        with self.assertRaisesRegex(IdentityError, "adopt-existing-identities"):
            build_identity_plan(settings, snapshot, allow_existing=False)

        plan = build_identity_plan(settings, snapshot, allow_existing=True)
        self.assertEqual(plan.commands, ())

        mismatched = IdentitySnapshot(
            users={
                "awgctl": UserRecord(
                    name="awgctl", uid=450, gid=451,
                    home="/home/awgctl", shell="/bin/bash",
                )
            },
            groups=snapshot.groups,
            locked_users=set(),
            supplementary_groups={"awgctl": ("docker",)},
        )
        with self.assertRaisesRegex(IdentityError, "does not match"):
            build_identity_plan(settings, mismatched, allow_existing=True)

    def test_existing_operator_group_rejects_undeclared_members(self):
        from awginstall.identity import GroupRecord, IdentityError, IdentitySnapshot, UserRecord, build_identity_plan
        from awginstall.settings import resolve_installation_settings

        settings = resolve_installation_settings(
            sudo_user=None,
            overrides={"operators": ["ubuntu"]},
        )
        snapshot = IdentitySnapshot(
            users={
                "awgctl": UserRecord(
                    "awgctl", 450, 451, "/var/lib/amneziawg-manager", "/usr/sbin/nologin"
                ),
                "ubuntu": None,
            },
            groups={
                "awgctl": GroupRecord("awgctl", 451, ()),
                "awgctl-admin": GroupRecord("awgctl-admin", 452, ("ubuntu", "stale-admin")),
            },
            locked_users={"awgctl"},
            supplementary_groups={"awgctl": ()},
        )
        with self.assertRaisesRegex(IdentityError, "undeclared members: stale-admin"):
            build_identity_plan(settings, snapshot, allow_existing=True)

    def test_sudoers_grants_only_public_entrypoint(self):
        from awginstall.identity import render_sudoers

        rendered = render_sudoers("vpn-admins", "scoped-nopasswd")

        self.assertIn("%vpn-admins ALL=(root) NOPASSWD: NOSETENV: /usr/local/sbin/awgctl", rendered)
        self.assertNotIn("*", rendered)
        self.assertNotIn("awgctl-internal", rendered)
        self.assertEqual(render_sudoers("vpn-admins", "existing-sudo"), "")

    def test_worker_commands_confine_builds_more_strictly_than_downloads(self):
        from awginstall.identity import build_worker_command
        from awginstall.settings import resolve_installation_settings

        settings = resolve_installation_settings(sudo_user=None)
        job = pathlib.Path("/var/lib/amneziawg-manager/jobs/abc")
        build = build_worker_command(settings, job, ["/usr/bin/python3", "build.py"], network=False)
        download = build_worker_command(settings, job, ["/usr/bin/python3", "fetch.py"], network=True)

        self.assertIn("--property=PrivateNetwork=yes", build)
        self.assertNotIn("--property=PrivateNetwork=yes", download)
        self.assertIn("--property=CapabilityBoundingSet=", build)
        self.assertIn(f"--property=ReadWritePaths={job}", build)
        self.assertIn("--uid=awgctl", build)
        self.assertIn("--gid=awgctl", build)
        self.assertEqual(build[-2:], ["/usr/bin/python3", "build.py"])

    def test_worker_output_copy_rejects_links_and_unsafe_modes(self):
        from awginstall.identity import IdentityError, copy_validated_worker_output

        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source = root / "artifact"
            destination = root / "root-copy"
            source.write_bytes(b"verified later")
            source.chmod(0o600)
            copy_validated_worker_output(source, destination, expected_uid=os.getuid(), max_size=1024)
            self.assertEqual(destination.read_bytes(), b"verified later")
            self.assertEqual(destination.stat().st_mode & 0o777, 0o600)

            unsafe = root / "unsafe"
            unsafe.write_bytes(b"bad")
            unsafe.chmod(0o666)
            with self.assertRaisesRegex(IdentityError, "permissions"):
                copy_validated_worker_output(unsafe, root / "copy-unsafe", expected_uid=os.getuid(), max_size=1024)

            link = root / "link"
            link.symlink_to(source.name)
            with self.assertRaisesRegex(IdentityError, "regular single-link"):
                copy_validated_worker_output(link, root / "copy-link", expected_uid=os.getuid(), max_size=1024)


class HostConfigurationTests(unittest.TestCase):
    def test_successful_configuration_report_can_be_compensated_by_outer_transaction(self):
        from awginstall.host import HostPaths, configure_host, rollback_host_configuration
        from awginstall.identity import IdentitySnapshot, UserRecord
        from awginstall.settings import resolve_installation_settings

        snapshot = IdentitySnapshot(users={}, groups={}, locked_users=set(), supplementary_groups={})
        commands = []

        def runner(argv):
            commands.append(tuple(argv))
            return subprocess.CompletedProcess(argv, 0, b"", b"")

        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            settings = resolve_installation_settings(sudo_user=None)
            paths = HostPaths.under(root)
            with (
                mock.patch("awginstall.host._resolve_created_user", return_value=UserRecord(
                    "awgctl", os.getuid(), os.getgid(), str(settings.staging_root), "/usr/sbin/nologin"
                )),
                mock.patch("awginstall.host._prepare_staging_root"),
            ):
                report = configure_host(
                    settings,
                    product_root=root / "opt/amneziawg",
                    paths=paths,
                    allow_existing=False,
                    dry_run=False,
                    snapshot=snapshot,
                    runner=runner,
                )
                rollback_host_configuration(report, runner=runner)
            self.assertFalse(paths.sudoers.exists())
            self.assertFalse(paths.service_dropin.exists())
            self.assertFalse(paths.module_load.exists())
            self.assertFalse((root / "opt/amneziawg/config/installation.json").exists())
        self.assertIn(("userdel", "--remove", "awgctl"), commands)

    def test_dry_run_returns_complete_plan_without_commands_or_writes(self):
        from awginstall.host import HostPaths, configure_host
        from awginstall.identity import IdentitySnapshot
        from awginstall.settings import resolve_installation_settings

        settings = resolve_installation_settings(sudo_user="ubuntu")
        snapshot = IdentitySnapshot(
            users={"ubuntu": None}, groups={}, locked_users=set(), supplementary_groups={}
        )
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            paths = HostPaths.under(root)
            report = configure_host(
                settings,
                product_root=root / "opt/amneziawg",
                paths=paths,
                allow_existing=False,
                dry_run=True,
                snapshot=snapshot,
                runner=lambda argv: (_ for _ in ()).throw(AssertionError(argv)),
            )
            self.assertFalse((root / "etc").exists())
        self.assertIn(("groupadd", "--system", "awgctl"), report.identity.commands)
        self.assertTrue(report.sudoers)
        self.assertTrue(report.service_hardening)

    def test_apply_writes_validated_policy_and_installed_settings(self):
        from awginstall.host import HostPaths, configure_host
        from awginstall.identity import IdentitySnapshot, UserRecord
        from awginstall.settings import resolve_installation_settings

        snapshot = IdentitySnapshot(users={}, groups={}, locked_users=set(), supplementary_groups={})
        commands = []

        def runner(argv):
            commands.append(tuple(argv))
            return subprocess.CompletedProcess(argv, 0, b"", b"")

        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            settings = resolve_installation_settings(sudo_user=None)
            paths = HostPaths.under(root)
            with (
                mock.patch("awginstall.host._resolve_created_user", return_value=UserRecord(
                    "awgctl", os.getuid(), os.getgid(), str(settings.staging_root), "/usr/sbin/nologin"
                )),
                mock.patch("awginstall.host._prepare_staging_root"),
            ):
                configure_host(
                    settings,
                    product_root=root / "opt/amneziawg",
                    paths=paths,
                    allow_existing=False,
                    dry_run=False,
                    snapshot=snapshot,
                    runner=runner,
                )
            installed = json.loads((root / "opt/amneziawg/config/installation.json").read_text())
            self.assertEqual(installed["dns"]["policy"], "cloudflare-malware")
            self.assertEqual((paths.sudoers).stat().st_mode & 0o777, 0o440)
            self.assertIn("ProtectSystem=strict", paths.service_dropin.read_text())
            self.assertEqual(paths.module_load.read_text(), "# Managed by AmneziaWG Manager\namneziawg\n")
        self.assertTrue(any(command[0] == "visudo" for command in commands))
        self.assertTrue(any(command[:2] == ("systemd-analyze", "verify") for command in commands))
        self.assertIn(("systemctl", "daemon-reload"), commands)

    def test_apply_failure_compensates_new_identity_commands(self):
        from awginstall.host import HostConfigurationError, HostPaths, configure_host
        from awginstall.identity import IdentitySnapshot, UserRecord
        from awginstall.settings import resolve_installation_settings

        snapshot = IdentitySnapshot(users={}, groups={}, locked_users=set(), supplementary_groups={})
        commands = []

        def runner(argv):
            commands.append(tuple(argv))
            if argv[0] == "visudo":
                raise HostConfigurationError("invalid sudoers")
            return subprocess.CompletedProcess(argv, 0, b"", b"")

        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            settings = resolve_installation_settings(sudo_user=None)
            with (
                mock.patch("awginstall.host._resolve_created_user", return_value=UserRecord(
                    "awgctl", os.getuid(), os.getgid(), str(settings.staging_root), "/usr/sbin/nologin"
                )),
                mock.patch("awginstall.host._prepare_staging_root"),
            ):
                with self.assertRaisesRegex(HostConfigurationError, "invalid sudoers"):
                    configure_host(
                        settings,
                        product_root=root / "opt/amneziawg",
                        paths=HostPaths.under(root),
                        allow_existing=False,
                        dry_run=False,
                        snapshot=snapshot,
                        runner=runner,
                    )
        self.assertIn(("userdel", "--remove", "awgctl"), commands)
        self.assertIn(("groupdel", "awgctl-admin"), commands)
        self.assertIn(("groupdel", "awgctl"), commands)


class ConfinedBuildTests(unittest.TestCase):
    def test_source_build_runs_without_network_and_returns_root_staged_artifact(self):
        from awginstall.identity import UserRecord
        from awginstall.settings import resolve_installation_settings
        from awginstall.worker import build_in_confined_worker

        settings = resolve_installation_settings(sudo_user=None)
        observed = []

        def runner(argv):
            observed.append(list(argv))
            separator = list(argv).index("--")
            return subprocess.run(
                list(argv)[separator + 1 :],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
            )

        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            jobs = root / "jobs"
            jobs.mkdir()
            output = root / "artifact"
            build_in_confined_worker(
                settings,
                repo_root=REPO_ROOT,
                output=output,
                jobs_root=jobs,
                runner=runner,
                user=UserRecord(
                    "awgctl", os.getuid(), os.getgid(),
                    str(settings.staging_root), "/usr/sbin/nologin",
                ),
            )
            self.assertTrue(output.is_file())
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertEqual(list(jobs.iterdir()), [])
        self.assertIn("--property=PrivateNetwork=yes", observed[0])
        self.assertIn("--uid=awgctl", observed[0])


if __name__ == "__main__":
    unittest.main(verbosity=2)
