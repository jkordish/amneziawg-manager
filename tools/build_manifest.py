#!/usr/bin/env python3
"""Build the small signed-release manifest consumed by awgctl update."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from awgctl.semver import InvalidVersion, precedence_key


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    try:
        precedence_key(args.version)
    except InvalidVersion:
        parser.error(
            "--version must be a valid SemVer 2.0.0 release without a leading v"
        )
    if not args.artifact.is_file():
        parser.error("--artifact must be an existing regular file")
    data = args.artifact.read_bytes()
    manifest = {
        "schema_version": 1,
        "version": args.version,
        "tag": f"v{args.version}",
        "channel": "beta" if "-" in args.version else "stable",
        "platform": "ubuntu-24.04-amd64",
        "installation_schema_version": 1,
        "artifact": {
            "name": "awgctl.pyz",
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_name(f".{args.output.name}.{os.getpid()}")
    temporary.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, args.output)
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
