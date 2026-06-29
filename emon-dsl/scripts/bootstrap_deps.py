#!/usr/bin/env python3
"""Install repo-local Python dependencies without pip."""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from emon.deps import ensure_compiler_deps, DEPS_DIR


def main() -> int:
    ensure_compiler_deps(auto_install=True)
    print(f"Dependencies ready in {DEPS_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
