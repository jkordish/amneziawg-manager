"""Manager-owned systemd hardening policy for the native awg-quick unit."""

from __future__ import annotations


class SandboxError(ValueError):
    """The requested service hardening policy is unsupported."""


def render_service_hardening(policy: str) -> str:
    if policy == "off":
        return ""
    if policy != "conservative":
        raise SandboxError(f"unsupported systemd hardening policy: {policy}")
    return """# Managed by AmneziaWG Manager. Local edits will be reported as drift.
[Unit]
After=systemd-modules-load.service

[Service]
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/opt/amneziawg/generated /run/awgctl
RuntimeDirectory=awgctl
RuntimeDirectoryMode=0700
RuntimeDirectoryPreserve=yes
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectClock=yes
ProtectControlGroups=yes
ProtectHostname=yes
ProtectKernelLogs=yes
ProtectKernelModules=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
"""


def render_module_load() -> str:
    return "# Managed by AmneziaWG Manager\namneziawg\n"
