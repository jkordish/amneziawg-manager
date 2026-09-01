import pathlib
import sys

from .core import main


entrypoint = "internal" if pathlib.Path(sys.argv[0]).name == "awgctl-internal" else "public"
raise SystemExit(main(entrypoint=entrypoint))
