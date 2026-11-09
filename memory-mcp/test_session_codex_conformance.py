#!/usr/bin/env python3
"""Replay normalization and saved IndexState sequences from the server corpus."""
import importlib.util
from pathlib import Path
import sys

path = Path(__file__).resolve().parent / "conformance/gen_vectors.py"
spec = importlib.util.spec_from_file_location("conformance", path)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)

if __name__ == "__main__":
    sys.argv[1:1] = ["--check", "codex"]
    try:
        sys.exit(runner.main())
    except (ValueError, KeyError, TypeError) as exc:
        print("FAIL corpus: " + str(exc), file=sys.stderr)
        sys.exit(1)
