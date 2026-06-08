#!/bin/bash
# 示例：在 Ubuntu 上把 examples/syscall_latency.emon 编译成可运行工具
#
# 步骤：
#   1) emon-compiler 生成 *.bpf.c、*_loader.c、*.yaml
#   2) clang 编译 eBPF 程序
#   3) bpftool 生成 skeleton
#   4) gcc 编译 loader 并链接 libbpf
set -euo pipefail

SRC="${1:-examples/syscall_latency.emon}"
NAME="$(basename "${SRC}" .emon)"
OUT_DIR="${OUT_DIR:-build/generated}"

if [ ! -x build/bin/emon-compiler ]; then
    echo "[error] 请先运行: ./scripts/build.sh"
    exit 1
fi

mkdir -p "${OUT_DIR}"
./build/bin/emon-compiler -o "${NAME}" --out-dir "${OUT_DIR}" "${SRC}"

# 2) clang -target bpf （实际需要 vmlinux.h 与内核 BTF）
echo "[注意] 以下编译步骤需要内核 BTF / libbpf 完整环境"
echo "  clang -target bpf -O2 -g -Iinclude -I/usr/include -c ${OUT_DIR}/${NAME}.bpf.c -o ${OUT_DIR}/${NAME}.bpf.o"
echo "  bpftool gen skeleton ${OUT_DIR}/${NAME}.bpf.o > ${OUT_DIR}/${NAME}.skel.h"
echo "  gcc ${OUT_DIR}/${NAME}_loader.c -o ${OUT_DIR}/${NAME}_loader -lbpf -lelf -lz"
