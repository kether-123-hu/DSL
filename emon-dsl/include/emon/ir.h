// =====================================================================
// Emon DSL —— 中间表示（IR）规范
//
// 本文档描述 IR 数据结构的设计意图，作为前后端桥接协议。
// 实际 IR 生成由 Python 前端实现:  emon/ir.py
//
// IR 输出格式为 JSON，数据结构如下:
//
// {
//   "tool_name": "...",
//   "options": [{"name": "...", "default": "..."}],
//   "maps": [
//     {"name": "@count", "map_type": "HASH",
//      "key_fields": ["pid"], "value_type": "u64", "max_entries": 10240}
//   ],
//   "events": [
//     {"name": "event_xxx", "fields": [{"name": "pid", "type": "u32"}]}
//   ],
//   "probes": [
//     {
//       "section": "tracepoint/syscalls/sys_enter_read",
//       "hook_kind": "SYSCALL", "hook_target": "read",
//       "is_exit": false, "measures_latency": false,
//       "where_conditions": ["(pid > 0)"],
//       "when_conditions": [],
//       "aggregations": [
//         {"map_name": "count", "agg_fn": "count",
//          "keys": ["pid"], "value_expr": ""}
//       ],
//       "emits": [],
//       "lets": [], "if_stmts": []
//     }
//   ],
//   "every_tasks": [
//     {"interval": "1s", "prints": [...], "agg_reads": ["count"]}
//   ],
//   "begin_stmts": [],
//   "end_stmts": []
// }
//
// 映射关系 (文档 5.4.1):
//   observe syscall("read")          → 1 个 entry probe
//   + measure latency                → 额外 1 个 exit probe
//   @count[pid] = count()            → IRMap(HASH) + IRAggregation
//   @avg[pid] = avg(latency)         → IRMap(PERCPU_HASH, value=struct)
//   emit { time = nsecs; }           → IREventStruct + IREmit
//   every 1s { print(@c); }          → IREveryTask
//   where pid > 0                    → where_conditions: ["(pid > 0)"]
// =====================================================================
