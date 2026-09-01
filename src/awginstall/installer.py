"""High-level product installation transactions."""

from __future__ import annotations

import pathlib
from collections.abc import Callable, Mapping

from .deploy import (
    DeploymentError,
    activate_release,
    active_release,
    install_release,
    preserve_legacy_release,
)


class InstallerError(RuntimeError):
    """A safe installer error suitable for operator output."""


def upgrade_product(
    *,
    root: pathlib.Path,
    artifact: pathlib.Path,
    version: str,
    share_files: Mapping[str, bytes] | None = None,
    health_check: Callable[[pathlib.Path], int] | None = None,
) -> pathlib.Path:
    """Install product code and restore the previous selector on failure."""
    previous = active_release(root)
    try:
        if previous is None:
            previous = preserve_legacy_release(root)
        installed = install_release(
            root=root,
            artifact=artifact,
            version=version,
            share_files=share_files,
        )
        if health_check is not None and health_check(root / "bin/awgctl") != 0:
            raise InstallerError("health verification failed after product upgrade")
        return installed
    except Exception as exc:
        if previous is not None:
            try:
                activate_release(root, previous)
            except DeploymentError as rollback_exc:
                raise InstallerError(
                    f"product upgrade failed and rollback failed: {rollback_exc}"
                ) from exc
        if isinstance(exc, InstallerError):
            raise
        raise InstallerError(str(exc)) from exc
