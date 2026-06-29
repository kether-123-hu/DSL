#!/usr/bin/env python3
"""Benchmark Emon DSL compile pipeline and optional loader smoke runs."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from emon.toolchain import build, run


def discover_cases(category: str | None) -> list[Path]:
    base = ROOT / "benchmark"
    roots = [base / category] if category else [
        p for p in base.iterdir()
        if p.is_dir() and p.name != "results"
    ]
    cases: list[Path] = []
    for root in roots:
        cases.extend(sorted(root.glob("*.emon")))
    return cases


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Emon benchmark cases")
    parser.add_argument("--category", help="syscall/event/kprobe/tracepoint")
    parser.add_argument("--mode", choices=["compile", "smoke"], default="compile")
    parser.add_argument("--duration", type=float, default=3.0,
                        help="smoke run duration in seconds")
    parser.add_argument("--sudo", action="store_true",
                        help="run loader through sudo for smoke mode")
    parser.add_argument("--workload", action="append", default=[],
                        help="workload command to run during smoke mode")
    args = parser.parse_args()

    cases = discover_cases(args.category)
    if not cases:
        print("No benchmark cases found", file=sys.stderr)
        return 1

    results_dir = ROOT / "benchmark" / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    rows = []

    for case in cases:
        category = case.parent.name
        print(f"[bench] {category}/{case.name}")
        started = time.perf_counter()
        ok = True
        error = ""
        result = None
        try:
            out = results_dir / "build" / category / case.stem
            result = build(case, output_dir=out, verbose=False)
            if args.mode == "smoke":
                workload = None
                if args.workload:
                    workload = subprocess.Popen(args.workload)
                try:
                    run(case, output_dir=out, duration=args.duration, sudo=args.sudo)
                finally:
                    if workload and workload.poll() is None:
                        workload.terminate()
        except Exception as exc:
            ok = False
            error = str(exc)

        elapsed = time.perf_counter() - started
        timings = result.timings if result else {}
        rows.append({
            "category": category,
            "case": case.name,
            "mode": args.mode,
            "ok": ok,
            "elapsed_s": f"{elapsed:.6f}",
            "dsl_compile_s": f"{timings.get('dsl_compile_s', 0):.6f}",
            "bpf_object_s": f"{timings.get('bpf_object_s', 0):.6f}",
            "skeleton_s": f"{timings.get('skeleton_s', 0):.6f}",
            "loader_s": f"{timings.get('loader_s', 0):.6f}",
            "error": error,
        })

    csv_path = results_dir / f"bench-{stamp}.csv"
    json_path = results_dir / f"bench-{stamp}.json"
    fieldnames = list(rows[0].keys())
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    json_path.write_text(json.dumps(rows, indent=2), encoding="utf-8")

    failed = [row for row in rows if not row["ok"]]
    print(f"[bench] wrote {csv_path}")
    print(f"[bench] wrote {json_path}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
