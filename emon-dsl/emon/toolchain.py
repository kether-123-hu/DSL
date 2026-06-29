"""End-to-end build and run helpers for Emon DSL tools."""

from __future__ import annotations

from dataclasses import dataclass, asdict
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import time
from typing import Iterable

from emon.deps import ensure_compiler_deps


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BUILD_ROOT = ROOT / "build" / "emon"


@dataclass
class ToolchainResult:
    source: str
    tool_name: str
    output_dir: str
    bpf_c: str
    loader_c: str
    manifest: str
    vmlinux_h: str
    bpf_o: str
    skel_h: str
    loader: str
    timings: dict[str, float]

    def to_dict(self) -> dict:
        return asdict(self)


def doctor() -> dict:
    """Return host capability information used by the Emon runner."""
    ensure_compiler_deps(auto_install=True)
    tools = {
        "clang": shutil.which("clang"),
        "bpftool": shutil.which("bpftool"),
        "gcc": shutil.which("gcc"),
        "pkg-config": shutil.which("pkg-config"),
    }
    libbpf = _run_text(["pkg-config", "--modversion", "libbpf"], check=False).strip()
    return {
        "root": str(ROOT),
        "python": platform.python_version(),
        "kernel": platform.release(),
        "tools": tools,
        "libbpf": libbpf or None,
        "btf": "/sys/kernel/btf/vmlinux" if Path("/sys/kernel/btf/vmlinux").exists() else None,
        "can_run_loader_without_sudo": os.geteuid() == 0,
    }


def build(source_path: str | Path, output_dir: str | Path | None = None,
          verbose: bool = True) -> ToolchainResult:
    """Compile .emon all the way to a userspace loader executable."""
    ensure_compiler_deps(auto_install=True)
    _require_tools(["clang", "bpftool", "gcc", "pkg-config"])

    source = Path(source_path).resolve()
    if not source.exists():
        raise FileNotFoundError(source)

    tool_stem = source.stem.replace("-", "_").replace(".", "_")
    out = Path(output_dir).resolve() if output_dir else DEFAULT_BUILD_ROOT / tool_stem
    out.mkdir(parents=True, exist_ok=True)

    timings: dict[str, float] = {}

    def timed(name: str, fn):
        start = time.perf_counter()
        value = fn()
        timings[name] = time.perf_counter() - start
        return value

    if verbose:
        print(f"[emon] source: {source}", flush=True)
        print(f"[emon] build:  {out}", flush=True)

    def compile_dsl():
        from emon.ir import compile_file
        return compile_file(str(source), str(out))

    artifacts = timed("dsl_compile_s", compile_dsl)
    bpf_c = Path(artifacts["bpf_c"]).resolve()
    loader_c = Path(artifacts["loader_c"]).resolve()
    manifest = Path(artifacts["manifest"]).resolve()
    tool_name = bpf_c.name.removesuffix(".bpf.c")

    vmlinux_h = timed("vmlinux_h_s", lambda: ensure_vmlinux_h(out))
    bpf_o = out / f"{tool_name}.bpf.o"
    skel_h = out / f"{tool_name}.skel.h"
    loader = out / f"{tool_name}_loader"

    timed("bpf_object_s", lambda: _compile_bpf(bpf_c, bpf_o, out))
    timed("skeleton_s", lambda: _gen_skeleton(bpf_o, skel_h))
    timed("loader_s", lambda: _compile_loader(loader_c, loader, out))

    if verbose:
        print(f"[emon] bpf:    {bpf_o}", flush=True)
        print(f"[emon] skel:   {skel_h}", flush=True)
        print(f"[emon] loader: {loader}", flush=True)

    return ToolchainResult(
        source=str(source),
        tool_name=tool_name,
        output_dir=str(out),
        bpf_c=str(bpf_c),
        loader_c=str(loader_c),
        manifest=str(manifest),
        vmlinux_h=str(vmlinux_h),
        bpf_o=str(bpf_o),
        skel_h=str(skel_h),
        loader=str(loader),
        timings=timings,
    )


def run(source_path: str | Path, output_dir: str | Path | None = None,
        duration: float | None = None, sudo: bool = False,
        extra_args: Iterable[str] = ()) -> int:
    """Build and run a DSL tool."""
    result = build(source_path, output_dir=output_dir, verbose=True)
    cmd = [result.loader, *extra_args]
    if sudo and os.geteuid() != 0:
        cmd.insert(0, "sudo")

    print(f"[emon] run: {' '.join(cmd)}", flush=True)
    if duration is None:
        return subprocess.call(cmd, cwd=result.output_dir)

    proc = subprocess.Popen(cmd, cwd=result.output_dir)
    try:
        proc.wait(timeout=duration)
    except subprocess.TimeoutExpired:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
    return proc.returncode


def write_build_report(result: ToolchainResult, path: str | Path) -> None:
    Path(path).write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")


def ensure_vmlinux_h(output_dir: str | Path) -> Path:
    """Ensure vmlinux.h exists in the build output directory."""
    out = Path(output_dir)
    target = out / "vmlinux.h"
    if target.exists() and target.stat().st_size > 0:
        return target

    btf = Path("/sys/kernel/btf/vmlinux")
    if not btf.exists():
        raise RuntimeError("Missing /sys/kernel/btf/vmlinux; cannot generate vmlinux.h")

    with target.open("w", encoding="utf-8") as f:
        subprocess.run(
            ["bpftool", "btf", "dump", "file", str(btf), "format", "c"],
            stdout=f,
            check=True,
        )
    return target


def _compile_bpf(bpf_c: Path, bpf_o: Path, include_dir: Path) -> None:
    arch = _target_arch()
    subprocess.run(
        [
            "clang", "-O2", "-g", "-target", "bpf", f"-D__TARGET_ARCH_{arch}",
            "-I", str(include_dir), "-I", str(ROOT / "include"),
            "-c", str(bpf_c), "-o", str(bpf_o),
        ],
        check=True,
    )


def _gen_skeleton(bpf_o: Path, skel_h: Path) -> None:
    with skel_h.open("w", encoding="utf-8") as f:
        subprocess.run(["bpftool", "gen", "skeleton", str(bpf_o)], stdout=f, check=True)


def _compile_loader(loader_c: Path, loader: Path, include_dir: Path) -> None:
    subprocess.run(
        [
            "gcc", "-O2", "-g", "-Wall", "-Wextra",
            "-Wno-unused-function", "-Wno-unused-variable",
            "-I", str(include_dir), "-I", str(ROOT / "include"),
            str(loader_c), "-o", str(loader),
            "-lbpf", "-lelf", "-lz",
        ],
        check=True,
    )


def _target_arch() -> str:
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        return "x86"
    if machine in ("aarch64", "arm64"):
        return "arm64"
    if machine.startswith("arm"):
        return "arm"
    if machine in ("riscv64",):
        return "riscv"
    return machine


def _require_tools(names: Iterable[str]) -> None:
    missing = [name for name in names if shutil.which(name) is None]
    if missing:
        raise RuntimeError("Missing required tools: " + ", ".join(missing))


def _run_text(cmd: list[str], check: bool = True) -> str:
    result = subprocess.run(cmd, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, check=check)
    return result.stdout
