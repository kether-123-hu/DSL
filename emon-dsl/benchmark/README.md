# Emon DSL Benchmarks

This directory contains runnable benchmark cases grouped by feature area.

## Categories

- `syscall/`: syscall tracepoints, filters, aggregation, latency.
- `event/`: ring buffer `emit` and userspace polling.
- `kprobe/`: kernel function probes.
- `tracepoint/`: generic tracepoint probes.

## Commands

Compile all benchmark cases:

```bash
python3 benchmark/run_bench.py --mode compile
```

Compile one category:

```bash
python3 benchmark/run_bench.py --category syscall
```

Smoke-run loaders for a few seconds, usually requiring root or suitable BPF
capabilities:

```bash
python3 benchmark/run_bench.py --mode smoke --sudo --duration 5
```

Results are written to `benchmark/results/*.csv` and `*.json`.
