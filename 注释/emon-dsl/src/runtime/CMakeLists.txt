# ===================================================================
# src/runtime/CMakeLists.txt —— 运行时库构建配置
# ===================================================================
#
# 【本文件的作用】
# 将 loader/emon_rt_loader.c、output/emon_rt_output.c、map/emon_rt_map.c
# 三个源文件编译为一个静态库 libemon-rt.a（emon-rt）。
#
# 【为什么用静态库？】
# 静态库在链接时直接嵌入到可执行文件中，不需要额外的 .so 文件。
# 这样生成的 eBPF 工具是单文件可执行，部署更方便。
# ===================================================================
add_library(emon-rt STATIC          # 创建名为 emon-rt 的静态库
    loader/emon_rt_loader.c         # BPF 加载/挂载/生命周期
    output/emon_rt_output.c         # 格式化输出工具
    map/emon_rt_map.c               # Map 遍历和读取
)

# 让静态库能访问 include/ 下的公共头文件
target_include_directories(emon-rt PUBLIC ${CMAKE_SOURCE_DIR}/include)

# 链接 libbpf 库（提供 BPF 操作的 API）
target_link_libraries(emon-rt PUBLIC PkgConfig::LIBBPF)

message(STATUS "[runtime] emon-rt 静态库已配置")
