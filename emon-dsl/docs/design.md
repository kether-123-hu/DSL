# =====================================================================
# Emon DSL 架构设计
# =====================================================================
# 目标：将高层声明式 DSL（tool / observe / where / measure / when /
#       emit / every）翻译为 eBPF C + libbpf 加载器 + manifest
# 文档对应：项目计划书模板 v0.01(7) 第 4–5 节
# =====================================================================

                        ┌──────────────────────────┐
                        │ 用户 *.emon DSL 源文件   │
                        └────────────┬─────────────┘
                                     │
                        ┌────────────▼─────────────┐
                        │ Lexer / Parser           │
                        │   grammar/*.g4           │
                        │   src/compiler/{lexer,parser} │
                        └────────────┬─────────────┘
                                     │ AST
                        ┌────────────▼─────────────┐
                        │ AST & 语义检查           │
                        │   include/emon/ast_nodes.h│
                        │   semantic/              │
                        └────────────┬─────────────┘
                                     │ IR
                        ┌────────────▼─────────────┐
                        │ 中间表示 IR Builder      │
                        │   include/emon/ir.h      │
                        │   ir/ir_builder.cc       │
                        └────────────┬─────────────┘
                                     │
                 ┌───────────────────┼───────────────────┐
                 ▼                   ▼                   ▼
          eBPF C 源             libbpf loader      manifest YAML
      codegen/ebpfc_generator  codegen/libbpf_*   codegen/manifest_*
                 │                   │                   │
                 │                   │                   │
        clang -target bpf       gcc + libbpf          可读配置
                 │                   │
                 ▼                   ▼
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
