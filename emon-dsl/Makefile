# =====================================================================
# Emon DSL 顶层 Makefile
# 目标平台：Ubuntu 22.04+（GNU Make 4.x，兼容原生 Linux 工具链）
# 对应开发流程：第 3–7 周 —— 语言设计、编译器前端/后端、运行时支持
# =====================================================================

# -------- 基本配置 --------
PROJECT       := emon-dsl
VERSION       := 0.0.1
PREFIX        ?= /usr/local
BUILD_DIR     := build
SRC_DIR       := src
INC_DIR       := include
GRAMMAR_DIR   := grammar
EXAMPLES_DIR  := examples
TESTS_DIR     := tests
SCRIPTS_DIR   := scripts

# -------- 工具链 --------
CC          ?= gcc
CXX         ?= g++
CMAKE       ?= cmake
MAKEFLAGS    += --no-print-directory

# -------- ANTLR4（用于 DSL 词法/语法分析）--------
ANTLR4_JAR   ?= $(SCRIPTS_DIR)/antlr-4.13.1-complete.jar
ANTLR4       ?= java -jar $(ANTLR4_JAR)
ANTLR4_OUT   := $(BUILD_DIR)/antlr4

# -------- LLVM / Clang / libbpf（用于 eBPF 目标代码编译）--------
CLANG        ?= clang
CLANG_FLAGS  := -target bpf -D__TARGET_ARCH_x86 -O2 -g -Wall \
                -I/usr/include -I$(INC_DIR)
LIBBPF_LD    := -lbpf -lelf -lz

# -------- 目标 --------
.PHONY: all compiler grammar runtime examples test clean install dirs help

all: dirs compiler runtime examples

dirs:
	@mkdir -p $(BUILD_DIR) $(ANTLR4_OUT)

# -------- ANTLR4 语法生成（对应文档 4.1 语言定义阶段）--------
grammar: dirs
	@echo "[grammar] 生成 Emon DSL 词法/语法分析器 ..."
	@if [ -f "$(ANTLR4_JAR)" ]; then \
	    $(ANTLR4) -Dlanguage=Cpp -o $(ANTLR4_OUT) \
	             -visitor -listener \
	             $(GRAMMAR_DIR)/EmonLexer.g4 $(GRAMMAR_DIR)/EmonParser.g4; \
	else \
	    echo "  [warn] ANTLR4 jar 未找到，跳过语法生成（请将 antlr-4.13.1-complete.jar 放入 $(SCRIPTS_DIR)/）"; \
	fi

# -------- CMake 驱动完整编译器+运行时构建（对应文档 3-6 阶段）--------
compiler: grammar
	@echo "[compiler] 构建 Emon DSL 编译器前端 ..."
	@cd $(BUILD_DIR) && $(CMAKE) .. -DCMAKE_BUILD_TYPE=Release \
	    -DANTLR4_OUT=$(CURDIR)/$(ANTLR4_OUT) \
	    && $(MAKE) -j$$(nproc) emon-compiler

runtime: compiler
	@echo "[runtime] 构建用户态 libbpf 运行时 ..."
	@cd $(BUILD_DIR) && $(MAKE) -j$$(nproc) emon-runtime

# -------- 示例 DSL 程序 → eBPF C 代码 → 可执行工具 --------
examples: runtime
	@echo "[examples] 编译示例 DSL 程序 ..."
	@for f in $(EXAMPLES_DIR)/*.emon; do \
	    echo "  - $$f"; \
	done

# -------- 测试 --------
test:
	@echo "[test] 运行单元测试与集成测试 ..."
	@cd $(BUILD_DIR) && ctest --output-on-failure || true

# -------- 清理 --------
clean:
	@echo "[clean] 清理构建目录 ..."
	@rm -rf $(BUILD_DIR)

# -------- 安装（Ubuntu）--------
install: all
	install -d $(PREFIX)/bin
	install -m 0755 $(BUILD_DIR)/emon-compiler $(PREFIX)/bin/emon-compiler
	install -m 0755 $(BUILD_DIR)/emon-loader   $(PREFIX)/bin/emon-loader
	install -d $(PREFIX)/include/emon
	install -m 0644 $(INC_DIR)/emon/*.h $(PREFIX)/include/emon/
	@echo "已安装到 $(PREFIX)"

# -------- 帮助 --------
help:
	@echo "Emon DSL Makefile (v$(VERSION))"
	@echo ""
	@echo "  make           - 构建编译器、运行时与示例（默认）"
	@echo "  make grammar   - 使用 ANTLR4 生成 DSL 词法/语法分析器"
	@echo "  make compiler  - 构建 emon-compiler"
	@echo "  make runtime   - 构建 libbpf 用户态运行时"
	@echo "  make examples  - 编译并运行示例工具"
	@echo "  make test      - 运行测试集"
	@echo "  make install   - 安装到 $(PREFIX)"
	@echo "  make clean     - 清理构建产物"
