# ===================================================================
# CMakeLists.txt —— Emon DSL C 运行时库构建脚本
# ===================================================================
#
# 【本文件的作用】
# 这是 CMake 构建系统的顶层配置文件，用于编译 C 语言运行时库。
#
# 【重要说明】
# Emon DSL 的编译器前端和后端（词法分析、语法分析、语义分析、
# 代码生成）已全部用 Python 实现。Python 部分不需要 CMake 构建。
#
# 本 CMake 脚本仅用于编译 C 运行时库（libemon-rt.a）：
#   - emon_rt_loader.c → BPF 程序加载/挂载/信号处理
#   - emon_rt_map.c    → BPF map 遍历和打印
#   - emon_rt_output.c → 格式化输出（直方图、表格、条形图）
#
# 这个静态库会与编译器生成的 _loader.c 链接在一起，
# 形成最终的可执行 eBPF 监控工具。
#
# 【构建方式】
#   cd emon-dsl
#   mkdir build && cd build
#   cmake ..
#   make
#   产物: build/lib/libemon-rt.a
#
# 【依赖】
#   - libbpf: eBPF 用户态库（必需）
#   - pkg-config: 用于查找 libbpf
# =====================================================================
cmake_minimum_required(VERSION 3.16)  # CMake 最低版本要求
project(emon-dsl
    VERSION 0.0.1
    DESCRIPTION "Emon DSL: 面向 eBPF 的领域特定语言编译器"
    LANGUAGES C)                        # 本项目只包含 C 代码

# ---------- C 语言标准 ----------
set(CMAKE_C_STANDARD          17)      # 使用 C17 标准
set(CMAKE_C_STANDARD_REQUIRED ON)      # 强制要求 C17（不用旧标准回退）
set(CMAKE_POSITION_INDEPENDENT_CODE ON) # 生成位置无关代码（静态库必需）

# ---------- 编译选项 ----------
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "构建类型" FORCE)  # 默认 Release 模式
endif()

# 开启大部分警告（帮助发现潜在问题）
# -Wall: 所有常见警告
# -Wextra: 额外警告
# -Wno-unused-parameter: 忽略未使用参数（有些回调函数签名固定）
# -Wno-unused-variable: 忽略未使用变量
add_compile_options(-Wall -Wextra -Wno-unused-parameter -Wno-unused-variable)

# ---------- 依赖检测：libbpf ----------
# libbpf 是 Linux eBPF 工具链的核心用户态库
find_package(PkgConfig REQUIRED)       # 查找 pkg-config 工具
pkg_check_modules(LIBBPF REQUIRED IMPORTED_TARGET libbpf)  # 查找 libbpf 包

# ---------- 输出目录 ----------
# 静态库输出到 build/lib/
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# ---------- 公共头文件 ----------
# 让编译器能找到 include/ 目录下的头文件
include_directories(${CMAKE_SOURCE_DIR}/include)

# =====================================================================
# 子目录：编译 C 运行时库
#   src/runtime → libemon-rt.a（map 读取、事件输出、信号处理）
# =====================================================================
add_subdirectory(src/runtime)

# 提示用户 Python 编译器的使用方式
message(STATUS "[emon-dsl] Python 编译器: cd emon-dsl && python3 main.py compile <file.emon>")
