# Emon DSL 编译器子目录
# 划分：lexer / parser / ast / semantic / ir / codegen
add_subdirectory(lexer)
add_subdirectory(parser)
add_subdirectory(ast)
add_subdirectory(semantic)
add_subdirectory(ir)
add_subdirectory(codegen)

# ---- 主编译器可执行文件 ----
add_executable(emon-compiler
    main.cc
    lexer/emon_lexer.cc
    parser/emon_parser.cc
    ast/ast_nodes.cc
    semantic/semantic_checker.cc
    ir/ir_builder.cc
    codegen/ebpfc_generator.cc
    codegen/libbpf_loader_generator.cc
    codegen/manifest_generator.cc
)
target_include_directories(emon-compiler PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src/compiler)
set_target_properties(emon-compiler PROPERTIES
    OUTPUT_NAME "emon-compiler")

message(STATUS "[compiler] emon-compiler 目标已配置")
