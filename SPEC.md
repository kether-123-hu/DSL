# Emon DSL 项目规格说明书

> **E**BPF **Mon**itoring DSL — 面向 eBPF 可观测性的领域特定语言编译器

| 属性 | 值 |
|------|-----|
| 项目名称 | Emon DSL |
| 版本 | 0.2.0 |
| 语言 | Python 3.10+ / C (运行时库) |
| 目标平台 | Linux x86_64 (Ubuntu 22.04+) |
| 测试 | 195 个单元测试，全部通过 |

---

## 1. 项目目标

构建完整的 eBPF 可观测性工具编译链，用声明式 DSL 描述监控需求，编译器自动生成内核态 BPF 程序和用户态加载器。

---

## 2. 系统架构

```
.emon 源文件 → lexer.py → parser.py → semantic.py → ir.py
                                                          │
                              ┌───────────────────────────┤
                              ▼               ▼           ▼
                         bpfc_gen.py   loader_gen.py  manifest_gen.py
                              │               │           │
                         *.bpf.c       *_loader.c     *.yaml
                              │               │
                         clang           gcc + libbpf
                              │               │
                         *.bpf.o       可执行 monitor
```

编译器全流程 Python 实现，C 仅用于运行时库。

---

## 3. 语言特性

### 3.1 Hook 类型（7 种）

| Hook | 语法 | 底层机制 |
|------|------|----------|
| syscall | `observe syscall("read")` | tracepoint sys_enter/sys_exit |
| kernel | `observe kernel("func")` | kprobe/kretprobe |
| tracepoint | `observe tracepoint("cat:name")` | tracepoint |
| uprobe | `observe uprobe("/bin/sh", "func")` | uprobe/uretprobe |
| sched | `observe sched("sched_switch")` | tracepoint sched |
| file | `observe file("vfs_read")` | kprobe |
| net | `observe net("tcp_sendmsg")` | kprobe |

### 3.2 聚合函数

| 函数 | Map 类型 |
|------|----------|
| `count()` | HASH |
| `sum/avg/min/max/hist/lhist` | PERCPU_HASH |

### 3.3 控制结构

`where` / `when` / `let` / `if-else` / `emit` / `every` / `begin` / `end`

---

## 4. 编译器模块

| 模块 | 功能 |
|------|------|
| `lexer.py` | 词法分析：源码 → Token 流 |
| `parser.py` + `emon.lark` | 语法分析：Token 流 → 类型化 AST |
| `semantic.py` | 语义检查：作用域、上下文变量、阶段限制 |
| `ir.py` | IR 构建 + compile() 入口 |
| `bpfc_gen.py` | eBPF C 代码生成 |
| `loader_gen.py` | libbpf loader C 代码生成 |
| `manifest_gen.py` | YAML manifest 生成 |

---

## 5. 示例清单（8 个）

| # | 文件 | 功能 |
|---|------|------|
| 1 | `syscall_count.emon` | 系统调用计数 |
| 2 | `syscall_latency.emon` | 延迟监控 + ring buffer 事件 |
| 3 | `full_feature_test.emon` | 全功能语法测试 |
| 4 | `simple_filter.emon` | let/if 条件分支 |
| 5 | `kprobe_monitor.emon` | 内核函数 kprobe 监控 |
| 6 | `multi_monitor.emon` | 多 observe 块 |
| 7 | `file_monitor.emon` | 文件系统事件 |
| 8 | `net_monitor.emon` | 网络事件 |

---

## 6. 测试覆盖（195 tests）

| 测试文件 | 数量 |
|----------|:--:|
| `test_lexer.py` | ~30 |
| `test_parser.py` | ~25 |
| `test_semantic.py` | ~40 |
| `test_ir.py` | ~30 |
| `test_codegen.py` | ~70 |

---

## 7. 验收标准

- [x] 8 个示例零错误编译（BPF + Loader）
- [x] 运行时零崩溃
- [x] 195 个单元测试全通过
- [x] PERCPU map 正确处理
- [x] Ctrl+C 可靠终止
- [x] 实际系统采集真实监控数据

---

## 8. 已知限制

1. `file`/`net`/`sched` hook 的 `size` 变量默认 0（无提取逻辑）
2. Map key 输出为 hex+可读前缀混合格式
3. 需要 root 权限运行
4. Ubuntu 22.04 需从源码安装 libbpf ≥1.4
