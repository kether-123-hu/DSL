// =====================================================================
// Emon DSL —— 中间表示（IR）接口
// IR 描述：“进入探针记录时间戳 / Map，退出探针读回并完成测量、聚合、emit 事件”
// 对应文档 5.4.1 —— observe ... measure latency 的翻译规则
// =====================================================================
#pragma once

#include "emon/ast_nodes.h"
#include <iosfwd>
#include <memory>
#include <string>
#include <vector>

namespace emon {

// ---- IR 基本块 / 指令骨架 ----
struct IRMap {
    std::string name;          // e.g. __start_time, @count
    std::string key_type;      // "u32", "u64", "pair<pid_t, u32>" ...
    std::string value_type;
    uint32_t max_entries;
    enum Kind { StartTime, AggCounter, AggSum, AggHist, EventRing } kind;
};

struct IREventStruct {
    std::string name;
    std::vector<std::pair<std::string, std::string>> fields;  // name, c-type
};

struct IRProbe {
    // 每个 observe 规则 → 一对 enter/exit（或单个 enter if latency 未使用）
    std::string section;       // "tracepoint/syscalls/sys_enter_read"
    std::string hookName;      // "read"
    std::vector<std::string> whereConds;  // DSL 的布尔表达式 → C 表达式（字符串形式）
    std::vector<std::string> whenConds;
    bool measuresLatency;
    std::vector<std::string> aggregations;  // 文本形式的 map 更新语句
    std::vector<std::string> emits;          // 事件提交语句
};

struct IRProgram {
    std::string toolName;
    std::vector<std::pair<std::string, std::string>> options;  // name -> default (c expr)
    std::vector<IRMap> maps;
    std::vector<IREventStruct> events;
    std::vector<IRProbe> probes;
    std::vector<std::string> everyTasks;   // 周期性任务（用户态）
    void dump(std::ostream&) const;
};

struct IRBuilder {
    std::unique_ptr<IRProgram> build(const Program& ast);
};

}  // namespace emon
