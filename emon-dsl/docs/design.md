# =====================================================================
# Emon DSL 架构设计
# =====================================================================
# 目标：将高层声明式 DSL（tool / observe / where / measure / when /
#       emit / every）翻译为 eBPF C + libbpf 加载器 + manifest
#
# 编译器全流程使用 Python 实现，C 仅用于运行时库（与 loader 静态链接）。
# 文档对应：项目计划书模板 v0.01(7) 第 4–5 节
# =====================================================================

                        ┌──────────────────────────┐
                        │ 用户 *.emon DSL 源文件   │
                        └────────────┬─────────────┘
                                     │
                        ┌────────────▼─────────────┐
                        │ Lexer / Parser           │
                        │   emon/lexer.py          │
                        │   emon/parser.py         │
                        │   grammar/emon.lark      │
                        └────────────┬─────────────┘
                                     │ AST
                        ┌────────────▼─────────────┐
                        │ AST & 语义检查           │
                        │   emon/ast_nodes.py      │
                        │   emon/semantic.py       │
                        └────────────┬─────────────┘
                                     │ IR
                        ┌────────────▼─────────────┐
                        │ 中间表示 IR Builder      │
                        │   emon/ir.py             │
                        └────────────┬─────────────┘
                                     │
                 ┌───────────────────┼───────────────────┐
                 ▼                   ▼                   ▼
          eBPF C 源             libbpf loader      manifest YAML
      emon/bpfc_gen.py       emon/loader_gen.py  emon/manifest_gen.py
                 │                   │                   │
                 │                   │                   │
        clang -target bpf       gcc + libbpf          可读配置
                 │            + libemon-rt.a
                 ▼                   │
              *.bpf.o          可执行 monitor 工具
                 │
          bpftool gen skeleton
                 │
              *.skel.h  <─── loader 包含

# =====================================================================
# 映射关系（文档 5.1-5.7）：
#   tool                           → 程序名 + 命名空间
#   option                         → 用户可配置参数（loader 中）
#   observe syscall(...)           → sys_enter/sys_exit tracepoint
#   measure latency                → __start_time map + delta 计算
#   where / when                   → BPF program 中 if return
#   @count/@avg/@hist              → BPF map + 类型推导
#   emit { ... }                   → event struct + ring buffer
#   every interval { ... }         → 用户态 sleep/poll 循环
# =====================================================================
