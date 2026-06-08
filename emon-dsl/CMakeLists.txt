# =====================================================================
# Emon DSL —— CMake 顶层构建脚本
# 目标平台：Ubuntu 22.04+ (Linux, x86_64)
# 对应的项目阶段：第 3–7 周 —— 语言定义 / 编译器前端 / 代码生成 / 运行时
# =====================================================================
cmake_minimum_required(VERSION 3.16)
project(emon-dsl
    VERSION 0.0.1
    DESCRIPTION "Emon DSL: An eBPF-oriented Domain-Specific Language compiler"
    LANGUAGES C CXX)

# ---------- 语言标准 ----------
set(CMAKE_C_STANDARD          17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD        20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# ---------- 编译选项 ----------
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

add_compile_options(-Wall -Wextra -Wno-unused-parameter -Wno-unused-variable)

# ---------- 依赖检测：libbpf（运行时必需）----------
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED IMPORTED_TARGET libbpf)

find_program(CLANG_EXECUTABLE clang REQUIRED)
find_program(BPFTOOL_EXECUTABLE bpftool REQUIRED)

# ---------- 输出目录 ----------
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# ---------- 公共头文件 ----------
include_directories(${CMAKE_SOURCE_DIR}/include)

# =====================================================================
# 子目录：按文档章节划分
#   compiler  -> 3-6 阶段：词法/语法/AST/语义/IR/代码生成
#   runtime   -> 5   阶段：libbpf 加载、事件输出、map 聚合
# =====================================================================
add_subdirectory(src/compiler)
add_subdirectory(src/runtime)

# ---------- 测试 ----------
enable_testing()
add_subdirectory(tests)

message(STATUS "Emon DSL v${PROJECT_VERSION} 构建配置完成")
message(STATUS "  CMAKE_BUILD_TYPE = ${CMAKE_BUILD_TYPE}")
message(STATUS "  CLANG            = ${CLANG_EXECUTABLE}")
message(STATUS "  LIBBPF_VERSION   = ${LIBBPF_VERSION}")
