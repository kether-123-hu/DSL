# Emon DSL —— 单元测试与集成测试
add_library(emon-test-main STATIC test_main.cc)
target_include_directories(emon-test-main PUBLIC ${CMAKE_SOURCE_DIR}/include)

function(emon_add_test name src)
    add_executable(${name} ${src})
    target_link_libraries(${name} PRIVATE emon-test-main)
    add_test(NAME ${name} COMMAND ${name})
endfunction()

emon_add_test(test_lexer       unit/test_lexer.cc)
emon_add_test(test_parser      unit/test_parser.cc)
emon_add_test(test_semantic    unit/test_semantic.cc)
emon_add_test(test_integration integration/test_compile_examples.cc)

message(STATUS "[tests] 已注册 4 个测试目标")
