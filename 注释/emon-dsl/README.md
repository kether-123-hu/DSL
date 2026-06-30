# ===================================================================
# emon-dsl 目录 —— Emon DSL 编译器项目根目录
# ===================================================================
# 
# 【目录用途】
# 这是整个 Emon DSL 编译器项目的根目录。
# Emon DSL 是一门"领域特定语言"(Domain-Specific Language)，
# 专门用于编写 eBPF（扩展伯克利包过滤器）可观测性监控脚本。
#
# 简单来说：你用一种类似自然语言的简洁语法描述"我想监控什么"，
# 编译器会自动生成能在 Linux 内核中运行的 eBPF C 代码。
#
# 【目录结构一览】
#   emon/         → Python 编译器前端+后端（核心！词法→语法→语义→IR→代码生成）
#   grammar/      → Lark 语法定义文件（定义 Emon 语言的"法律"，什么写法合法）
#   include/      → C 语言公共头文件（运行时库的接口声明）
#   src/runtime/  → C 语言运行时库（用户态辅助函数：map 读取、输出、加载）
#   examples/     → 示例 .emon 脚本（学写 Emon 语言的最好教材）
#   manifest/     → 工具清单模板（描述 eBPF 工具的元信息）
#   main.py       → 命令行入口（支持 lex/parse/check/ir/compile 等子命令）
#   CMakeLists.txt→ C 运行时库的 CMake 构建脚本
#
# 【工作流程】
#   1. 用户编写 .emon 文件（监控脚本）
#   2. 运行 python3 main.py compile xxx.emon
#   3. 编译器生成 xxx.bpf.c (内核态) + xxx_loader.c (用户态) + xxx.yaml (描述)
#   4. 用 clang 编译 xxx.bpf.c → eBPF 字节码
#   5. 用 gcc 编译 xxx_loader.c → 可执行加载器
#   6. 运行加载器，eBPF 程序被注入内核，开始监控
# ===================================================================
