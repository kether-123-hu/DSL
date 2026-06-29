"""Small dependency bootstrapper for environments without pip.

The compiler frontend depends on Lark. Some lab machines have Python but no
pip/venv, so we keep a local wheel-based fallback under .deps/python.
"""

from __future__ import annotations

import importlib
import json
import os
from pathlib import Path
import sys
import urllib.request
import zipfile


ROOT = Path(__file__).resolve().parent.parent
DEPS_DIR = ROOT / ".deps" / "python"

_PYPI_JSON = "https://pypi.org/pypi/{name}/json"


def add_local_deps_to_path() -> None:
    """Put the repo-local dependency directory on sys.path if it exists."""
    if DEPS_DIR.exists():
        deps = str(DEPS_DIR)
        if deps not in sys.path:
            sys.path.insert(0, deps)


def ensure_module(module_name: str, package_name: str | None = None,
                  auto_install: bool = True) -> bool:
    """Ensure a Python module is importable.

    Returns True when the module is available. If auto_install is enabled and
    the first import fails, a pure-Python wheel is downloaded from PyPI and
    unpacked into .deps/python.
    """
    add_local_deps_to_path()
    try:
        importlib.import_module(module_name)
        return True
    except ModuleNotFoundError:
        if not auto_install:
            return False

    package = package_name or module_name
    install_wheel(package)
    add_local_deps_to_path()
    importlib.import_module(module_name)
    return True


def ensure_compiler_deps(auto_install: bool = True) -> None:
    """Ensure dependencies required by the compiler frontend are present."""
    ensure_module("lark", "lark", auto_install=auto_install)


def install_wheel(package_name: str) -> None:
    """Download and unpack the latest py3-none-any wheel for a package."""
    DEPS_DIR.mkdir(parents=True, exist_ok=True)
    url = _wheel_url(package_name)
    wheel_path = DEPS_DIR.parent / os.path.basename(url)
    print(f"[deps] downloading {package_name}: {url}", file=sys.stderr)
    with urllib.request.urlopen(url, timeout=30) as response:
        wheel_path.write_bytes(response.read())

    print(f"[deps] installing {wheel_path.name} -> {DEPS_DIR}", file=sys.stderr)
    with zipfile.ZipFile(wheel_path) as zf:
        zf.extractall(DEPS_DIR)


def _wheel_url(package_name: str) -> str:
    with urllib.request.urlopen(_PYPI_JSON.format(name=package_name), timeout=30) as response:
        data = json.load(response)

    version = data["info"]["version"]
    files = data["releases"][version]
    for file_info in files:
        filename = file_info["filename"]
        if file_info["packagetype"] == "bdist_wheel" and "py3-none-any" in filename:
            return file_info["url"]

    raise RuntimeError(f"No py3-none-any wheel found for {package_name} {version}")
