#!/usr/bin/env python3
"""Build the dependency-free awgctl executable zipapp."""

from __future__ import annotations

import argparse
import os
import pathlib
import shutil
import tempfile
import zipapp


REPO_ROOT = pathlib.Path(__file__).parents[1]
SOURCE_PACKAGE = REPO_ROOT / "src/awgctl"
INSTALL_PACKAGE = REPO_ROOT / "src/awginstall"


def build(output: pathlib.Path) -> None:
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="awgctl-build-") as directory:
        staging = pathlib.Path(directory)
        shutil.copytree(
            SOURCE_PACKAGE,
            staging / "awgctl",
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
        shutil.copytree(
            INSTALL_PACKAGE,
            staging / "awginstall",
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
        (staging / "__main__.py").write_text(
            "import pathlib\n"
            "import sys\n"
            "from awgctl.core import main\n"
            "entrypoint = 'internal' if pathlib.Path(sys.argv[0]).name == 'awgctl-internal' else 'public'\n"
            "raise SystemExit(main(entrypoint=entrypoint))\n",
            encoding="utf-8",
        )
        temporary = output.with_name(f".{output.name}.{os.getpid()}")
        temporary.unlink(missing_ok=True)
        zipapp.create_archive(
            staging,
            target=temporary,
            interpreter="/usr/bin/python3",
            compressed=True,
        )
        os.chmod(temporary, 0o755)
        os.replace(temporary, output)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    build(args.output)
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
