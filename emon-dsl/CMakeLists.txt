# =====================================================================
# Emon DSL —— CMake 顶层构建脚本
# 目标平台：Ubuntu 22.04+ (Linux, x86_64)
#
# 注意：编译器前端和后端已全部迁移至 Python（emon/ 目录）。
#       本 CMake 仅用于编译 C 运行时库（libemon-rt.a），
#       该库与 Python 生成的 *_loader.c 静态链接。
#
# Python 编译器使用方式：
#   cd emon-dsl && python3 main.py compile examples/syscall_count.emon
# =====================================================================
cmake_minimum_required(VERSION 3.16)
project(emon-dsl
    VERSION 0.0.1
    DESCRIPTION "Emon DSL: An eBPF-oriented Domain-Specific Language compiler"
    LANGUAGES C)

# ---------- 语言标准 ----------
set(CMAKE_C_STANDARD          17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# ---------- 编译选项 ----------
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

add_compile_options(-Wall -Wextra -Wno-unused-parameter -Wno-unused-variable)

# ---------- 依赖检测：libbpf（运行时必需）----------
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED IMPORTED_TARGET libbpf)

# ---------- 输出目录 ----------
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# ---------- 公共头文件 ----------
include_directories(${CMAKE_SOURCE_DIR}/include)

# =====================================================================
# 子目录：仅构建 C 运行时库
#   runtime   -> libemon-rt.a（map 读取、事件输出、信号处理）
# =====================================================================
add_subdirectory(src/runtime)

# ---------- 测试 ----------
enable_testing()
message(STATUS "[emon-dsl] Python 编译器: cd emon-dsl && python3 main.py compile <file.emon>")
message(STATUS "[emon-dsl] C 运行时库: libemon-rt.a (链接到生成的 loader)")
add_subdirectory(tests)

message(STATUS "Emon DSL v${PROJECT_VERSION} 构建配置完成")
message(STATUS "  CMAKE_BUILD_TYPE = ${CMAKE_BUILD_TYPE}")
message(STATUS "  CLANG            = ${CLANG_EXECUTABLE}")
message(STATUS "  LIBBPF_VERSION   = ${LIBBPF_VERSION}")
