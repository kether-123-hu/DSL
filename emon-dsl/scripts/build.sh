#!/bin/bash
# =====================================================================
# Emon DSL —— Ubuntu 构建脚本
# 依赖：build-essential, cmake, pkg-config, libbpf-dev, libelf-dev,
#       llvm, clang, bpftool, linux-tools-$(uname -r)
# =====================================================================
set -euo pipefail

PROJ_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="${PROJ_DIR}/build"

echo "[emon] 项目目录: ${PROJ_DIR}"
echo "[emon] 构建目录: ${BUILD_DIR}"

# 检查依赖
missing=()
for cmd in cmake gcc g++ clang bpftool pkg-config python3; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        missing+=("$cmd")
    fi
done
if [ ${#missing[@]} -gt 0 ]; then
    echo "[error] 缺少以下工具：${missing[*]}"
    echo "请先运行: sudo apt-get install -y build-essential cmake pkg-config \\"
    echo "             libbpf-dev libelf-dev llvm clang bpftool python3"
    exit 1
fi

# CMake / make
mkdir -p "${BUILD_DIR}"
cd "${BUILD_DIR}"
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j"$(nproc)"

echo "[emon] 构建完成："
ls -l "${BUILD_DIR}"/bin/emon-* 2>/dev/null || true
echo "[emon] 运行示例："
echo "  cd ${BUILD_DIR} && ctest --output-on-failure"
echo "  ./bin/emon-compiler ${PROJ_DIR}/examples/syscall_latency.emon"
