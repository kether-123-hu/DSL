# Emon DSL —— 面向 eBPF 监控的领域特定语言

Emon DSL 是一套面向 eBPF 监控场景的领域特定语言及其编译工具链。它通过高层声明式语法，把常见的 eBPF 监控需求（系统调用、内核函数、用户态函数、网络事件、文件事件、进程行为等）抽象为可复用的语言原语，使开发者无需直接编写底层 C/eBPF 代码即可完成可观测性工具的开发。

本项目按照《项目开发计划书模板 V0.01(7)》的 8 周开发流程组织：

| 阶段 | 周数 | 主要任务 | 对应代码目录 |
|------|------|----------|--------------|
| 1. 需求分析与技术调研 | 第 1–2 周 | eBPF 背景、现有工具链、DSL 设计边界 | `docs/` |
| 2. DSL 语言定义与语义设计 | 第 3 周 | 词法/语法/语义规则设计 | `grammar/`、`include/emon/` |
| 3. 编译器前端实现 | 第 4 周 | 词法分析、语法分析、AST、语义检查 | `emon/lexer.py`、`parser.py`、`ast_nodes.py`、`semantic.py` |
| 4. 上下文推导与目标代码生成 | 第 5–6 周 | IR 构建、eBPF C 生成、loader 生成、manifest | `emon/ir.py`、`bpfc_gen.py`、`loader_gen.py`、`manifest_gen.py` |
| 5. 运行时支持与常见工具示例 | 第 7 周 | libbpf 用户态加载、事件输出、示例工具 | `src/runtime/`、`examples/` |
| 6. 测试评估与报告完善 | 第 8 周 | 语法/语义/代码生成测试、效果评估 | `tests/` |

## 框架组成

> **注意**：编译器前端和后端已全部迁移至 Python（`emon/` 目录）。
> C++ 仅保留运行时库（`src/runtime/`）用于生成 loader 的静态链接。

```
emon-dsl/
├── main.py                      # CLI 入口 (lex/parse/check/ir/compile)
├── CMakeLists.txt               # 仅编译 C 运行时库 (libemon-rt.a)
├── requirements.txt             # Python 依赖 (lark-parser)
├── emon/                        # Python 编译器核心 (全流程)
│   ├── lexer.py                 # 词法分析器
│   ├── parser.py                # 语法分析器 (Lark)
│   ├── ast_nodes.py             # AST 节点定义
│   ├── semantic.py              # 语义分析
│   ├── tokens.py                # Token 类型
│   ├── error.py                 # 错误类型
│   ├── ir.py                    # IR 构建 + compile() 入口
│   ├── bpfc_gen.py              # eBPF C 代码生成器
│   ├── loader_gen.py            # libbpf loader C 代码生成器
│   └── manifest_gen.py          # YAML manifest 生成器
├── grammar/                     # 语法定义文件
│   ├── emon.lark                # Lark 语法 (主力)
│   ├── EmonLexer.g4             # ANTLR4 词法 (参考)
│   └── EmonParser.g4            # ANTLR4 语法 (参考)
├── include/emon/                # C 运行时头文件
│   └── runtime_common.h         # 公共 API 声明
├── src/runtime/                 # C 运行时库 (libemon-rt.a)
│   ├── loader/                  # 信号处理 & 加载工具
│   ├── output/                  # 直方图/表格/事件打印
│   └── map/                     # BPF map 遍历 & top-N
├── examples/                    # 示例 DSL 程序 (8 个)
│   ├── syscall_count.emon       # 系统调用计数
│   ├── syscall_latency.emon     # 延迟监控 + 事件输出
│   ├── full_feature_test.emon   # 全功能语法测试
│   ├── simple_filter.emon       # let/if 条件分支
│   ├── kprobe_monitor.emon      # 内核函数 kprobe 监控
│   ├── multi_monitor.emon       # 多 observe 块
│   ├── file_monitor.emon        # 文件系统事件
│   └── net_monitor.emon         # 网络事件
├── tests/                       # 测试 (195 tests)
│   ├── test_lexer.py
│   ├── test_parser.py
│   ├── test_semantic.py
│   ├── test_ir.py
│   └── test_codegen.py
└── docs/                        # 设计文档
```

## Ubuntu 环境依赖

在 Ubuntu 22.04+ 下部署运行时，建议安装以下依赖：

```bash
sudo apt-get update
sudo apt-get install -y                 \
    build-essential cmake pkg-config    \
    libbpf-dev libelf-dev libz-dev      \
    llvm clang bpftool                  \
    python3 python3-pip                 \
    linux-tools-common linux-tools-$(uname -r)
pip3 install antlr4-python3-runtime
```

## 构建流程

```bash
cd emon-dsl
mkdir -p build && cd build
cmake ..
make -j$(nproc)
```

或直接使用顶层 Makefile：

```bash
make              # 构建编译器和运行时
make test         # 运行单元/集成测试
make examples     # 编译并运行示例
```

## 工作流（对应文档 5.1-5.7）

1. 用户在 `examples/*.emon` 中编写 DSL 源程序（含 `tool`、`option`、`observe`、`where`、`measure`、`when`、`emit`、`every` 等结构）。
2. `emon-compiler` 读取 DSL 源程序，依次执行词法分析 → 语法分析 → AST 构建 → 语义检查 → 中间表示 → 目标代码生成。
3. 生成产物：
   - `*.bpf.c`：内核态 eBPF C 程序（由 libbpf/CO-RE 方式编译）
   - `*_loader.c`：用户态 libbpf 加载器
   - `*.yaml`：工具 manifest 描述
4. 使用 `clang -target bpf` 编译 `.bpf.c` → `.o`；使用 `gcc/clang` 与 `libbpf` 链接编译 loader 为可执行文件。
5. 通过 `bpftool` 或 loader 程序加载与运行；运行时周期性读取 map 并按 `every` 规则输出。
