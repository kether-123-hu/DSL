# Emon DSL —— 用户态运行时（libemon-rt.a）
add_library(emon-rt STATIC
    loader/emon_rt_loader.c
    output/emon_rt_output.c
    map/emon_rt_map.c
)
target_include_directories(emon-rt PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(emon-rt PUBLIC PkgConfig::LIBBPF)

message(STATUS "[runtime] emon-rt 静态库目标已配置")
