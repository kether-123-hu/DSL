# Emon DSL 编译器子目录 (后端保留)
# 前端 (lexer/parser/ast/semantic/ir) 已由 Python 实现替代
add_subdirectory(codegen)

# ---- 主编译器可执行文件 (待实现) ----
add_executable(emon-compiler
    codegen/ebpfc_generator.cc
    codegen/libbpf_loader_generator.cc
)
target_include_directories(emon-compiler PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src/compiler)
set_target_properties(emon-compiler PROPERTIES
    OUTPUT_NAME "emon-compiler")

message(STATUS "[compiler] emon-compiler 目标已配置")
