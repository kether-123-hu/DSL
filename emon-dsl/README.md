# Emon DSL —— 面向 eBPF 监控的领域特定语言

Emon DSL 是一套面向 eBPF 监控场景的领域特定语言及其编译工具链。它通过高层声明式语法，把常见的 eBPF 监控需求（系统调用、内核函数、用户态函数、网络事件、文件事件、进程行为等）抽象为可复用的语言原语，使开发者无需直接编写底层 C/eBPF 代码即可完成可观测性工具的开发。

本项目按照《项目开发计划书模板 V0.01(7)》的 8 周开发流程组织：

| 阶段 | 周数 | 主要任务 | 对应代码目录 |
|------|------|----------|--------------|
| 1. 需求分析与技术调研 | 第 1–2 周 | eBPF 背景、现有工具链、DSL 设计边界 | `docs/` |
| 2. DSL 语言定义与语义设计 | 第 3 周 | 词法/语法/语义规则设计 | `grammar/`、`include/emon/` |
| 3. 编译器前端实现 | 第 4 周 | 词法分析、语法分析、AST、语义检查 | `src/compiler/lexer`、`parser`、`ast`、`semantic` |
| 4. 上下文推导与目标代码生成 | 第 5–6 周 | 插装点分类、上下文推导、eBPF C 代码生成 | `src/compiler/codegen`、`src/compiler/ir` |
| 5. 运行时支持与常见工具示例 | 第 7 周 | libbpf 用户态加载、事件输出、示例工具 | `src/runtime/`、`examples/` |
| 6. 测试评估与报告完善 | 第 8 周 | 语法/语义/代码生成测试、效果评估 | `tests/` |

## 框架组成

```
emon-dsl/
├── CMakeLists.txt               # 顶层构建脚本（CMake）
├── Makefile                     # 顶层 Makefile（用于 Ubuntu 快速构建）
├── requirements.txt             # Python 依赖（测试脚本等）
├── .gitignore
├── grammar/                     # ANTLR4 语法定义（对应 DSL 语言定义阶段）
│   ├── EmonLexer.g4
│   └── EmonParser.g4
├── include/emon/                # 公共头文件
│   ├── ast_nodes.h
│   ├── semantic.h
│   ├── codegen.h
│   ├── ir.h
│   └── runtime_common.h
├── src/compiler/                # 编译器核心
│   ├── lexer/                   # 词法分析器（前端阶段）
│   ├── parser/                  # 语法分析器
│   ├── ast/                     # 抽象语法树节点
│   ├── semantic/                # 语义检查：变量/类型/字段合法性
│   ├── ir/                      # 中间表示
│   └── codegen/                 # 目标代码生成：eBPF C + libbpf loader + manifest
├── src/runtime/                 # 用户态运行时
│   ├── loader/                  # libbpf 加载框架
│   ├── output/                  # 事件输出（表格/直方图/日志）
│   └── map/                     # BPF map 读取与聚合
├── examples/                    # 示例 DSL 程序
│   ├── syscall_latency.emon
│   ├── syscall_count.emon
│   ├── func_latency.emon
│   └── file_access.emon
├── manifest/                    # 工具 manifest 模板
│   └── tool_manifest.yaml
├── tests/                       # 测试框架
│   ├── unit/
│   └── integration/
├── scripts/                     # 辅助脚本（build、checkout、lint）
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
