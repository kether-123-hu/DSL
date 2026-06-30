# ===================================================================
# examples/ 目录 —— Emon DSL 示例脚本
# ===================================================================
#
# 【目录用途】
# 存放各种用途的 .emon 示例脚本，展示 Emon DSL 语言的各项功能。
# 这些示例从简单到复杂，是学习 Emon DSL 语法的最佳参考。
#
# 【示例文件一览（按复杂度排列）】
#   syscall_count.emon      → 系统调用计数（最简单，演示 @count 聚合）
#   simple_filter.emon      → 条件过滤（演示 let/if/when 用法）
#   kprobe_monitor.emon     → 内核函数监控（演示 kernel observe）
#   net_monitor.emon        → 网络事件监控（演示 net observe）
#   file_monitor.emon       → 文件系统事件（演示 file observe）
#   syscall_latency.emon    → 系统调用延迟监控（演示 latency 测量，功能全面）
#   multi_monitor.emon      → 多类型混合监控（演示一个工具中多个 observe 块）
#   full_feature_test.emon  → 全功能测试（覆盖所有 7 种观察目标，所有语法特性）
# ===================================================================
