import json
import io
import os
import pathlib
import platform
import subprocess
import sys
import tempfile
import unittest
from contextlib import nullcontext, redirect_stderr
from unittest import mock


REPO_ROOT = pathlib.Path(__file__).parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from awginstall.deploy import active_release
from awginstall.cli import build_parser, main as installer_main, package_install_plan, parse_default_interface
from awginstall.installer import InstallerError, upgrade_product
from awginstall.platform import PlatformError, validate_platform
from awgctl.version import VERSION


class PlatformValidationTests(unittest.TestCase):
    def test_only_ubuntu_2404_amd64_is_supported(self):
        supported = validate_platform(
            {"ID": "ubuntu", "VERSION_ID": "24.04", "VERSION_CODENAME": "noble"},
            machine="x86_64",
        )
        self.assertEqual(supported["architecture"], "amd64")

        for release, machine in (("22.04", "x86_64"), ("24.04", "aarch64")):
            with self.subTest(release=release, machine=machine), self.assertRaises(PlatformError):
                validate_platform(
                    {"ID": "ubuntu", "VERSION_ID": release, "VERSION_CODENAME": "noble"},
                    machine=machine,
                )


class UpgradeTests(unittest.TestCase):
    def test_release_selector_layout_is_installed_before_post_upgrade_health(self):
        from awginstall import cli
        from awginstall.settings import resolve_installation_settings

        events = []
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory) / "opt/amneziawg"
            with (
                mock.patch.object(cli, "_install_entrypoints", side_effect=lambda *_: events.append("entrypoints")),
                mock.patch.object(cli, "_build_artifact", side_effect=lambda *_args, **_kwargs: events.append("build")),
                mock.patch.object(cli, "upgrade_product", side_effect=lambda **_kwargs: events.append("upgrade")),
            ):
                cli._deploy_source_release(
                    root,
                    REPO_ROOT,
                    health=True,
                    settings=resolve_installation_settings(sudo_user=None),
                )
        self.assertEqual(events, ["build", "entrypoints", "upgrade"])

    def test_release_build_failure_leaves_existing_entrypoints_untouched(self):
        from awginstall import cli
        from awginstall.settings import resolve_installation_settings

        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory) / "opt/amneziawg"
            libexec = root / "libexec"
            libexec.mkdir(parents=True)
            readme = root / "README.md"
            readme.write_bytes(b"prior readme\n")
            readme.chmod(0o640)
            internal = libexec / "awgctl-internal"
            internal.symlink_to("prior-internal")

            with (
                mock.patch.object(
                    cli,
                    "_build_artifact",
                    side_effect=InstallerError("injected build failure"),
                ),
                self.assertRaisesRegex(InstallerError, "injected build failure"),
            ):
                cli._deploy_source_release(
                    root,
                    REPO_ROOT,
                    health=True,
                    settings=resolve_installation_settings(sudo_user=None),
                )

            self.assertEqual(readme.read_bytes(), b"prior readme\n")
            self.assertEqual(readme.stat().st_mode & 0o777, 0o640)
            self.assertEqual(os.readlink(internal), "prior-internal")

    def test_entrypoint_mid_install_failure_restores_exact_prior_paths(self):
        from awginstall import cli

        with tempfile.TemporaryDirectory() as directory:
            test_root = pathlib.Path(directory)
            root = test_root / "opt/amneziawg"
            libexec = root / "libexec"
            libexec.mkdir(parents=True)
            libexec.chmod(0o700)
            readme = root / "README.md"
            readme.write_bytes(b"prior readme\n")
            readme.chmod(0o640)
            internal = libexec / "awgctl-internal"
            internal.symlink_to("prior-internal")
            public = test_root / "usr/local/sbin/awgctl"
            public.parent.mkdir(parents=True)
            public.symlink_to("prior-public")
            completion = test_root / "etc/bash_completion.d/awgctl"
            completion.parent.mkdir(parents=True)
            completion.write_bytes(b"prior completion\n")
            completion.chmod(0o640)
            prior_owners = {
                path: (path.lstat().st_uid, path.lstat().st_gid)
                for path in (readme, libexec, internal, public, completion)
            }
            original_replace = cli.os.replace
            failed = {"value": False}

            def replace(source, destination):
                if pathlib.Path(destination) == completion and not failed["value"]:
                    failed["value"] = True
                    raise OSError("injected entrypoint replacement failure")
                original_replace(source, destination)

            with (
                mock.patch.object(cli, "DEFAULT_ROOT", root),
                mock.patch.object(cli, "PUBLIC_ENTRYPOINT_PATH", public),
                mock.patch.object(cli, "COMPLETION_PATH", completion),
                mock.patch.object(cli.os, "replace", side_effect=replace),
                self.assertRaisesRegex(
                    InstallerError, "injected entrypoint replacement failure"
                ),
            ):
                cli._install_entrypoints(root, REPO_ROOT)

            self.assertTrue(failed["value"])
            self.assertEqual(readme.read_bytes(), b"prior readme\n")
            self.assertEqual(readme.stat().st_mode & 0o777, 0o640)
            self.assertEqual(os.readlink(internal), "prior-internal")
            self.assertEqual(libexec.stat().st_mode & 0o777, 0o700)
            self.assertEqual(os.readlink(public), "prior-public")
            self.assertEqual(completion.read_bytes(), b"prior completion\n")
            self.assertEqual(completion.stat().st_mode & 0o777, 0o640)
            self.assertEqual(
                {
                    path: (path.lstat().st_uid, path.lstat().st_gid)
                    for path in prior_owners
                },
                prior_owners,
            )

    def test_successful_entrypoint_install_returns_exact_rollback_report(self):
        from awginstall import cli

        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory) / "opt/amneziawg"
            root.mkdir(parents=True)
            report = cli._install_entrypoints(root, REPO_ROOT)

            self.assertIsNotNone(report)
            self.assertEqual((root / "README.md").read_bytes(), (REPO_ROOT / "README.md").read_bytes())
            self.assertEqual((root / "README.md").stat().st_mode & 0o777, 0o644)
            self.assertEqual(os.readlink(root / "libexec/awgctl-internal"), "../bin/awgctl")
            self.assertEqual((root / "libexec").stat().st_mode & 0o777, 0o755)

    def make_artifact(self, directory: pathlib.Path, content: bytes = b"new executable\n") -> pathlib.Path:
        artifact = directory / "artifact"
        artifact.write_bytes(content)
        return artifact

    def test_upgrade_preserves_legacy_binary_and_activates_new_release(self):
        with tempfile.TemporaryDirectory() as directory_text:
            directory = pathlib.Path(directory_text)
            root = directory / "opt/amneziawg"
            (root / "bin").mkdir(parents=True)
            (root / "bin/awgctl").write_bytes(b"legacy executable\n")

            upgrade_product(
                root=root,
                artifact=self.make_artifact(directory),
                version="0.1.0-beta.1",
                share_files={"VERSION": b"0.1.0-beta.1\n"},
                health_check=lambda _: 0,
            )

            self.assertEqual(active_release(root), "0.1.0-beta.1")
            self.assertEqual((root / "releases/legacy-import/awgctl").read_bytes(), b"legacy executable\n")

    def test_failed_health_check_rolls_back_to_preserved_legacy_binary(self):
        with tempfile.TemporaryDirectory() as directory_text:
            directory = pathlib.Path(directory_text)
            root = directory / "opt/amneziawg"
            (root / "bin").mkdir(parents=True)
            (root / "bin/awgctl").write_bytes(b"legacy executable\n")

            with self.assertRaisesRegex(InstallerError, "health verification failed"):
                upgrade_product(
                    root=root,
                    artifact=self.make_artifact(directory),
                    version="0.1.0-beta.1",
                    health_check=lambda _: 3,
                )

            self.assertEqual(active_release(root), "legacy-import")
            self.assertEqual((root / "bin/awgctl").read_bytes(), b"legacy executable\n")

    def test_public_signed_update_rolls_beta5_back_when_beta4_host_assets_are_missing(self):
        from awgctl import core

        with tempfile.TemporaryDirectory() as directory_text:
            directory = pathlib.Path(directory_text)
            root = directory / "opt/amneziawg"
            beta4 = self.make_artifact(directory, b"beta4 executable\n")
            upgrade_product(root=root, artifact=beta4, version="0.1.0-beta.4")

            beta5 = b"beta5 executable\n"
            health_commands = []

            def command_runner(argv, **_kwargs):
                command = tuple(argv)
                health_commands.append(command)
                if len(command) >= 2 and command[1] == "health":
                    self.assertFalse(
                        (directory / "etc/systemd/system/amneziawg-client-expiry.timer").exists()
                    )
                    return subprocess.CompletedProcess(argv, 3, b"", b"host assets missing")
                return subprocess.CompletedProcess(argv, 0, b"", b"")

            with (
                mock.patch.object(core, "ROOT", root),
                mock.patch.object(core, "VERSION", "0.1.0-beta.4"),
                mock.patch.object(core, "require_root"),
                mock.patch.object(core, "load_transition_document", return_value=None),
                mock.patch.object(core, "mutation_lock", side_effect=lambda **_kwargs: nullcontext()),
                mock.patch.object(core, "read_os_release", return_value={}),
                mock.patch.object(
                    core,
                    "validate_platform",
                    return_value={"version": "24.04", "architecture": "amd64"},
                ),
                mock.patch.object(core, "discover_release_tag", return_value="v0.1.0-beta.5"),
                mock.patch.object(
                    core,
                    "fetch_verified_release",
                    return_value=({"version": "0.1.0-beta.5"}, beta5),
                ),
                mock.patch.object(core, "create_backup", return_value=root / "backups/pre-update"),
                mock.patch.object(core, "run", side_effect=command_runner),
                mock.patch.object(core, "audit"),
                redirect_stderr(io.StringIO()),
            ):
                result = core.main(["update", "apply"])

            self.assertEqual(result, 1)
            self.assertEqual(active_release(root), "0.1.0-beta.4")
            self.assertEqual((root / "bin/awgctl").read_bytes(), b"beta4 executable\n")
            self.assertEqual(
                len([command for command in health_commands if command[1:] == ("health", "--json")]),
                1,
            )

    def test_upgrade_dry_run_does_not_create_installation_root(self):
        with tempfile.TemporaryDirectory() as directory_text:
            root = pathlib.Path(directory_text) / "opt/amneziawg"
            output = io.StringIO()
            with (
                mock.patch(
                    "awginstall.cli._configure_host_for_command",
                    side_effect=AssertionError("must not configure"),
                ),
                mock.patch(
                    "awginstall.cli._deploy_source_release",
                    side_effect=AssertionError("must not deploy"),
                ),
                mock.patch(
                    "awginstall.cli._run",
                    side_effect=AssertionError("must not run commands"),
                ),
            ):
                result = installer_main(
                    ["upgrade", "--dry-run"],
                    root=root,
                    repo_root=REPO_ROOT,
                    output=output,
                )
            self.assertEqual(result, 0)
            self.assertFalse(root.exists())
            self.assertIn(f"would install awgctl {VERSION}", output.getvalue())

    def test_upgrade_rejects_post_selector_runtime_flags_before_any_mutation(self):
        from awginstall import cli

        for flags in (
            ["--apply-default-dns"],
            ["--apply-live"],
            ["--apply-default-dns", "--apply-live"],
        ):
            with self.subTest(flags=flags), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory) / "opt/amneziawg"
                errors = io.StringIO()
                with (
                    mock.patch.object(cli, "_configure_host_for_command") as configure,
                    mock.patch.object(cli, "_deploy_source_release") as deploy,
                    mock.patch.object(cli, "_apply_requested_runtime_settings") as apply_runtime,
                    mock.patch("sys.stderr", errors),
                ):
                    result = installer_main(
                        [
                            "upgrade",
                            "--yes",
                            "--ingress-boundary",
                            "lightsail",
                            *flags,
                        ],
                        root=root,
                        repo_root=REPO_ROOT,
                        output=io.StringIO(),
                    )

                self.assertEqual(result, 1)
                self.assertFalse(root.exists())
                configure.assert_not_called()
                deploy.assert_not_called()
                apply_runtime.assert_not_called()
                self.assertIn("complete the upgrade first", errors.getvalue())
                self.assertIn("awgctl", errors.getvalue())

    def test_installer_parser_exposes_all_product_workflows(self):
        parser = build_parser()
        for command in ("check", "install", "adopt", "upgrade", "configure"):
            with self.subTest(command=command):
                parsed = parser.parse_args([command, "--dry-run"] if command != "check" else [command])
                self.assertEqual(parsed.command, command)

    def test_ingress_boundary_override_is_available_on_policy_flows(self):
        parser = build_parser()
        for command in ("check", "install", "configure", "upgrade"):
            argv = [command, "--ingress-boundary", "lightsail"]
            if command != "check":
                argv.append("--dry-run")
            if command == "install":
                argv.extend(["--endpoint", "vpn.example.com"])
            with self.subTest(command=command):
                parsed = parser.parse_args(argv)
                self.assertEqual(parsed.ingress_boundary, "lightsail")

    def test_installer_exposes_security_overrides_and_filtered_dns_default(self):
        parser = build_parser()
        defaults = parser.parse_args(["install", "--dry-run", "--endpoint", "vpn.example.com"])
        custom = parser.parse_args([
            "configure", "--dry-run",
            "--staging-user", "vpn-stage",
            "--operator-group", "vpn-admins",
            "--operator", "deploy",
            "--sudo-policy", "existing-sudo",
            "--systemd-hardening", "off",
            "--default-dns", "9.9.9.9,149.112.112.112",
            "--adopt-existing-identities",
        ])
        self.assertIsNone(defaults.dns)
        self.assertEqual(custom.staging_user, "vpn-stage")
        self.assertEqual(custom.operator_group, "vpn-admins")
        self.assertEqual(custom.operator, ["deploy"])
        self.assertEqual(custom.default_dns, "9.9.9.9,149.112.112.112")
        self.assertTrue(custom.adopt_existing_identities)

    def test_upgrade_settings_start_from_persisted_policy_then_apply_cli_overrides(self):
        from awginstall import cli

        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory) / "opt/amneziawg"
            config = root / "config"
            config.mkdir(parents=True)
            (config / "installation.json").write_text(json.dumps({
                "schema_version": 1,
                "staging": {
                    "user": "vpn-stage", "group": "vpn-stage", "uid": 450, "gid": 451,
                    "root": "/var/lib/vpn-stage",
                },
                "operators": {
                    "group": "vpn-admins", "users": ["deploy"],
                    "enroll_sudo_invoker": False, "sudo_policy": "existing-sudo",
                },
                "systemd": {"hardening": "off"},
                "dns": {"default": ["9.9.9.9", "149.112.112.112"], "policy": "custom"},
                "network": {"ingress_boundary": "lightsail"},
            }))
            args = cli.build_parser().parse_args([
                "upgrade", "--dry-run", "--default-dns", "cloudflare-malware",
                "--ingress-boundary", "equivalent-external-firewall",
            ])
            settings = cli._resolved_settings(args, root=root)
        self.assertEqual(settings.staging_user, "vpn-stage")
        self.assertEqual(settings.operator_group, "vpn-admins")
        self.assertEqual(settings.operators, ("deploy",))
        self.assertEqual(settings.sudo_policy, "existing-sudo")
        self.assertEqual(settings.default_dns, ("1.1.1.2", "1.0.0.2"))
        self.assertEqual(settings.ingress_boundary, "equivalent-external-firewall")

    def test_install_configure_and_check_cli_boundary_overrides_persisted_setting(self):
        from awginstall import cli
        from awginstall.settings import resolve_installation_settings

        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory) / "opt/amneziawg"
            persisted = root / "config/installation.json"
            persisted.parent.mkdir(parents=True)
            persisted.write_text(json.dumps(
                resolve_installation_settings(
                    sudo_user=None, overrides={"ingress_boundary": "lightsail"}
                ).to_dict()
            ))
            for command in ("install", "configure", "check"):
                argv = [
                    command,
                    "--ingress-boundary",
                    "equivalent-external-firewall",
                ]
                if command == "install":
                    argv.extend(["--settings", str(persisted), "--endpoint", "vpn.example.com"])
                args = cli.build_parser().parse_args(argv)
                with self.subTest(command=command):
                    settings = cli._resolved_settings(args, root=root)
                    self.assertEqual(
                        settings.ingress_boundary, "equivalent-external-firewall"
                    )

    def test_upgrade_persists_legacy_missing_ingress_override_before_new_health(self):
        from awginstall import cli
        from awginstall.settings import resolve_installation_settings

        events = []
        legacy = resolve_installation_settings(sudo_user=None).to_dict()
        legacy.pop("network")
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory) / "opt/amneziawg"
            (root / "config").mkdir(parents=True)
            (root / "config/installation.json").write_text(json.dumps(legacy))
            preconfiguration = object()

            def configure(_args, *, settings, **_kwargs):
                events.append(("configure", settings.ingress_boundary))
                return preconfiguration

            def deploy(_root, _repo, *, settings, **_kwargs):
                events.append(("deploy", settings.ingress_boundary))

            with (
                mock.patch.object(cli, "_configure_host_for_command", side_effect=configure),
                mock.patch.object(cli, "_deploy_source_release", side_effect=deploy),
                mock.patch.object(
                    cli, "_apply_requested_runtime_settings"
                ) as apply_runtime,
            ):
                result = installer_main(
                    ["upgrade", "--yes", "--ingress-boundary", "lightsail"],
                    root=root,
                    repo_root=REPO_ROOT,
                    output=io.StringIO(),
                )

        self.assertEqual(result, 0)
        self.assertEqual(events, [("configure", "lightsail"), ("deploy", "lightsail")])
        apply_runtime.assert_not_called()

    def test_first_upgrade_applies_no_sudo_bootstrap_before_release_then_final_policy(self):
        from awginstall import cli

        configured = []
        deployed = []
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory) / "opt/amneziawg"
            with (
                mock.patch.object(cli, "_configure_host_for_command", side_effect=lambda _args, **kwargs: configured.append(kwargs["settings"])),
                mock.patch.object(cli, "_deploy_source_release", side_effect=lambda *_args, **kwargs: deployed.append(kwargs["settings"])),
                mock.patch.object(
                    cli, "_apply_requested_runtime_settings"
                ) as apply_runtime,
            ):
                result = installer_main(
                    ["upgrade", "--yes", "--ingress-boundary", "lightsail"],
                    root=root,
                    repo_root=REPO_ROOT,
                    output=io.StringIO(),
                )
        self.assertEqual(result, 0)
        self.assertEqual([value.sudo_policy for value in configured], ["none", "scoped-nopasswd"])
        self.assertEqual(configured[0].operators, ())
        self.assertEqual(configured[0].systemd_hardening, "off")
        self.assertEqual(deployed, [configured[1]])
        apply_runtime.assert_not_called()

    def test_first_upgrade_rolls_back_bootstrap_when_release_validation_fails(self):
        from awginstall import cli

        bootstrap_report = object()
        final_report = object()
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory) / "opt/amneziawg"
            errors = io.StringIO()
            with (
                mock.patch.object(
                    cli,
                    "_configure_host_for_command",
                    side_effect=[bootstrap_report, final_report],
                ),
                mock.patch.object(cli, "_deploy_source_release", side_effect=InstallerError("health failed")),
                mock.patch.object(cli, "rollback_host_configuration") as rollback,
                mock.patch("sys.stderr", errors),
            ):
                result = installer_main(
                    ["upgrade", "--yes", "--ingress-boundary", "lightsail"],
                    root=root,
                    repo_root=REPO_ROOT,
                    output=io.StringIO(),
                )
        self.assertEqual(result, 1)
        self.assertEqual(
            rollback.call_args_list,
            [mock.call(final_report), mock.call(bootstrap_report)],
        )
        self.assertIn("health failed", errors.getvalue())

    def test_first_upgrade_rolls_back_bootstrap_when_final_host_configuration_fails(self):
        from awginstall import cli
        from awginstall.host import HostConfigurationError

        bootstrap_report = object()
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory) / "opt/amneziawg"
            errors = io.StringIO()
            with (
                mock.patch.object(
                    cli,
                    "_configure_host_for_command",
                    side_effect=[bootstrap_report, HostConfigurationError("unit install failed")],
                ),
                mock.patch.object(cli, "_deploy_source_release") as deploy,
                mock.patch.object(cli, "rollback_host_configuration") as rollback,
                mock.patch("sys.stderr", errors),
            ):
                result = installer_main(
                    ["upgrade", "--yes", "--ingress-boundary", "lightsail"],
                    root=root,
                    repo_root=REPO_ROOT,
                    output=io.StringIO(),
                )

        self.assertEqual(result, 1)
        deploy.assert_not_called()
        rollback.assert_called_once_with(bootstrap_report)
        self.assertIn("unit install failed", errors.getvalue())

    def test_existing_upgrade_rolls_back_host_configuration_when_release_health_fails(self):
        from awginstall import cli
        from awginstall.settings import resolve_installation_settings

        final_report = object()
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory) / "opt/amneziawg"
            settings_path = root / "config/installation.json"
            settings_path.parent.mkdir(parents=True)
            settings_path.write_text(
                json.dumps(
                    resolve_installation_settings(
                        sudo_user=None,
                        overrides={"ingress_boundary": "lightsail"},
                    ).to_dict()
                )
            )
            with (
                mock.patch.object(
                    cli, "_configure_host_for_command", return_value=final_report
                ) as configure,
                mock.patch.object(
                    cli,
                    "_deploy_source_release",
                    side_effect=InstallerError("health failed"),
                ),
                mock.patch.object(cli, "rollback_host_configuration") as rollback,
                mock.patch("sys.stderr", io.StringIO()),
            ):
                result = installer_main(
                    ["upgrade", "--yes"],
                    root=root,
                    repo_root=REPO_ROOT,
                    output=io.StringIO(),
                )

        self.assertEqual(result, 1)
        configure.assert_called_once()
        rollback.assert_called_once_with(final_report)

    def test_existing_upgrade_health_failure_restores_selector_files_and_timer_state(self):
        from awginstall import cli, host
        from awginstall.host import HostPaths
        from awginstall.identity import IdentitySnapshot, UserRecord
        from awginstall.settings import resolve_installation_settings

        with tempfile.TemporaryDirectory() as directory:
            test_root = pathlib.Path(directory)
            root = test_root / "opt/amneziawg"
            beta4 = test_root / "beta4"
            beta4.write_bytes(b"beta4 executable\n")
            upgrade_product(root=root, artifact=beta4, version="0.1.0-beta.4")

            prior_readme = root / "README.md"
            prior_readme.write_bytes(b"prior installed readme\n")
            prior_readme.chmod(0o640)
            prior_libexec = root / "libexec"
            prior_libexec.mkdir()
            prior_libexec.chmod(0o700)
            prior_internal = prior_libexec / "awgctl-internal"
            prior_internal.symlink_to("prior-internal")

            settings = resolve_installation_settings(
                sudo_user=None,
                overrides={"ingress_boundary": "lightsail"},
            )
            paths = HostPaths.under(test_root)
            installation = root / "config/installation.json"
            prior = {
                paths.sudoers: (b"prior sudoers\n", 0o440),
                paths.service_dropin: (b"prior hardening\n", 0o644),
                paths.module_load: (b"prior module\n", 0o644),
                paths.expiry_service: (b"prior expiry service\n", 0o644),
                paths.expiry_timer: (b"prior expiry timer\n", 0o644),
                installation: (
                    (json.dumps(settings.to_dict(), sort_keys=True) + "\n").encode(),
                    0o600,
                ),
            }
            for path, (data, mode) in prior.items():
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
                path.chmod(mode)

            timer_state = {"enabled": False, "active": True}

            def runner(argv):
                command = tuple(argv)
                if command[:2] == ("systemctl", "is-enabled"):
                    code = 0 if timer_state["enabled"] else 1
                    stdout = b"enabled\n" if timer_state["enabled"] else b"disabled\n"
                    return subprocess.CompletedProcess(argv, code, stdout, b"")
                if command[:2] == ("systemctl", "is-active"):
                    code = 0 if timer_state["active"] else 3
                    stdout = b"active\n" if timer_state["active"] else b"inactive\n"
                    return subprocess.CompletedProcess(argv, code, stdout, b"")
                if command[:2] == ("systemctl", "enable"):
                    timer_state["enabled"] = True
                elif command[:2] == ("systemctl", "disable"):
                    timer_state["enabled"] = False
                elif command[:2] == ("systemctl", "start"):
                    timer_state["active"] = True
                elif command[:2] == ("systemctl", "stop"):
                    timer_state["active"] = False
                return subprocess.CompletedProcess(argv, 0, b"", b"")

            snapshot = IdentitySnapshot(
                users={}, groups={}, locked_users=set(), supplementary_groups={}
            )

            def configure(_args, *, settings, **_kwargs):
                return host.configure_host(
                    settings,
                    product_root=root,
                    paths=paths,
                    allow_existing=False,
                    dry_run=False,
                    snapshot=snapshot,
                    runner=runner,
                )

            def rollback(report):
                host.rollback_host_configuration(report, runner=runner)

            def build(_repo_root, artifact, **_kwargs):
                artifact.write_bytes(b"beta5 executable\n")

            with (
                mock.patch.object(
                    host,
                    "_resolve_created_user",
                    return_value=UserRecord(
                        "awgctl",
                        os.getuid(),
                        os.getgid(),
                        str(settings.staging_root),
                        "/usr/sbin/nologin",
                    ),
                ),
                mock.patch.object(host, "_prepare_staging_root"),
                mock.patch.object(cli, "_configure_host_for_command", side_effect=configure),
                mock.patch.object(cli, "rollback_host_configuration", side_effect=rollback),
                mock.patch.object(cli, "_build_artifact", side_effect=build),
                mock.patch.object(cli, "_health_check", return_value=3),
                mock.patch("sys.stderr", io.StringIO()),
            ):
                result = installer_main(
                    ["upgrade", "--yes"],
                    root=root,
                    repo_root=REPO_ROOT,
                    output=io.StringIO(),
                )

            self.assertEqual(result, 1)
            self.assertEqual(active_release(root), "0.1.0-beta.4")
            self.assertEqual((root / "bin/awgctl").read_bytes(), b"beta4 executable\n")
            self.assertEqual(prior_readme.read_bytes(), b"prior installed readme\n")
            self.assertEqual(prior_readme.stat().st_mode & 0o777, 0o640)
            self.assertEqual(prior_libexec.stat().st_mode & 0o777, 0o700)
            self.assertEqual(os.readlink(prior_internal), "prior-internal")
            for path, (data, mode) in prior.items():
                self.assertEqual(path.read_bytes(), data)
                self.assertEqual(path.stat().st_mode & 0o777, mode)
            self.assertEqual(timer_state, {"enabled": False, "active": True})

    def test_top_level_installer_help_is_runnable_without_pip(self):
        result = subprocess.run(
            [sys.executable, str(REPO_ROOT / "install.py"), "--help"],
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("install", result.stdout)
        self.assertIn("adopt", result.stdout)

    def test_fresh_package_plan_uses_official_ppa_and_running_kernel_without_a_shell(self):
        plan = package_install_plan("6.8.0-79-generic")
        self.assertIn(["add-apt-repository", "-y", "ppa:amnezia/ppa"], plan)
        self.assertTrue(any("linux-headers-6.8.0-79-generic" in command for command in plan))
        self.assertTrue(any("amneziawg" in command and command[:2] == ["apt-get", "install"] for command in plan))
        self.assertTrue(all(isinstance(command, list) for command in plan))

    def test_default_interface_parser_requires_one_unambiguous_device(self):
        self.assertEqual(parse_default_interface("default via 172.26.0.1 dev ens5 proto dhcp\n"), "ens5")
        with self.assertRaisesRegex(InstallerError, "default route"):
            parse_default_interface("")

    def test_fresh_install_dry_run_requires_no_root_and_performs_no_commands(self):
        output = io.StringIO()
        with mock.patch("awginstall.cli._run", side_effect=AssertionError("must not mutate")):
            result = installer_main(
                ["install", "--dry-run", "--endpoint", "vpn.example.com", "--external-interface", "ens5"],
                root=pathlib.Path("/opt/amneziawg"),
                repo_root=REPO_ROOT,
                output=output,
            )
        self.assertEqual(result, 0)
        self.assertIn("official Amnezia PPA", output.getvalue())
        self.assertIn("1.1.1.2,1.0.0.2", output.getvalue())

    def test_fresh_mutating_install_fails_closed_without_ingress_attestation(self):
        from awginstall import cli

        errors = io.StringIO()
        with (
            mock.patch.object(cli, "validate_platform", return_value={"architecture": "amd64"}),
            mock.patch.object(cli, "_install_amneziawg_packages") as install_packages,
            mock.patch.object(cli.pathlib.Path, "exists", return_value=False),
            mock.patch("sys.stderr", errors),
        ):
            result = installer_main(
                ["install", "--yes", "--endpoint", "vpn.example.com"],
                root=pathlib.Path("/test/amneziawg"),
                repo_root=REPO_ROOT,
                output=io.StringIO(),
            )

        self.assertEqual(result, 1)
        install_packages.assert_not_called()
        self.assertIn("--ingress-boundary", errors.getvalue())

    def test_configure_dry_run_reports_privilege_boundary_without_mutation(self):
        output = io.StringIO()
        report = mock.Mock(
            identity=mock.Mock(commands=(("groupadd", "--system", "awgctl"),)),
            sudoers="scoped",
            service_hardening="sandbox",
        )
        with mock.patch("awginstall.cli.configure_host", return_value=report) as configure:
            result = installer_main(
                ["configure", "--dry-run", "--json"],
                root=pathlib.Path("/opt/amneziawg"),
                repo_root=REPO_ROOT,
                output=output,
            )
        self.assertEqual(result, 0)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["settings"]["dns"]["policy"], "cloudflare-malware")
        self.assertEqual(payload["identity_commands"], [["groupadd", "--system", "awgctl"]])
        configure.assert_called_once()


if __name__ == "__main__":
    unittest.main(verbosity=2)
