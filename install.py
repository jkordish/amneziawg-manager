#!/usr/bin/env python3
"""Dependency-free source checkout installer for awgctl."""

from __future__ import annotations

import pathlib
import sys


REPO_ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from awginstall.cli import main


raise SystemExit(main(repo_root=REPO_ROOT))
