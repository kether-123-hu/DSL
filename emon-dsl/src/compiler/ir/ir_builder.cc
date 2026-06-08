// =====================================================================
// Emon DSL —— IR Builder（从 AST 推导 eBPF 探针结构）
// 参考文档 5.4.1 —— observe syscall(...) measure latency 的翻译规则
// =====================================================================
#include "emon/ir.h"
#include <sstream>
#include <iostream>

namespace emon {

static std::string exprToC(const Expr& e) {
    if (auto* l = dynamic_cast<const LitInt*>(&e)) return std::to_string(l->value);
    if (auto* l = dynamic_cast<const LitFloat*>(&e)) return std::to_string(l->value);
    if (auto* l = dynamic_cast<const LitStr*>(&e)) return "\"" + l->value + "\"";
    if (auto* l = dynamic_cast<const LitBool*>(&e)) return l->value ? "true" : "false";
    if (auto* l = dynamic_cast<const LitTime*>(&e)) return std::to_string(l->nanos);
    if (auto* l = dynamic_cast<const LitSize*>(&e)) return std::to_string(l->bytes);
    if (auto* c = dynamic_cast<const CtxIdent*>(&e)) return "ctx_" + c->name;
    if (auto* i = dynamic_cast<const Ident*>(&e))   return "opt_" + i->name;
    if (auto* a = dynamic_cast<const AggIdent*>(&e)) return "@" + a->name;
    if (auto* u = dynamic_cast<const UnaryOp*>(&e)) {
        return (u->op == UnaryOp::Not ? "!" : "-") + exprToC(*u->operand);
    }
    if (auto* b = dynamic_cast<const BinOp*>(&e)) {
        static const char* names[] = {
            "+", "-", "*", "/", "%", "<<", ">>", "&", "|", "^",
            "<", ">", "<=", ">=", "==", "!=", "&&", "||"
        };
        return "(" + exprToC(*b->lhs) + " " + names[b->op] + " " + exprToC(*b->rhs) + ")";
    }
    return "/*unknown*/0";
}

std::unique_ptr<IRProgram> IRBuilder::build(const Program& ast) {
    auto ir = std::make_unique<IRProgram>();
    ir->toolName = ast.toolName;

    // options 原样传入
    for (const auto& opt : ast.options) {
        ir->options.push_back({opt.first, exprToC(*opt.second)});
    }

    // 为每个 observe rule 生成探针 / map
    int ruleIdx = 0;
    for (const auto& r : ast.rules) {
        ++ruleIdx;
        const bool hasLatency = [&]{ for (auto& m : r->measures) if (m.metric == Metric::Latency) return true; return false; }();

        // 自动生成 __start_time map
        if (hasLatency) {
            ir->maps.push_back({"__start_time_" + std::to_string(ruleIdx),
                                 "u32", "u64", 1024, IRMap::StartTime});
        }
        for (const auto& a : r->aggregations) {
            IRMap::Kind k = IRMap::AggCounter;
            std::string vt = "u64";
            switch (a.fn) {
                case AggFn::Count: k = IRMap::AggCounter; vt = "u64"; break;
                case AggFn::Sum:   k = IRMap::AggSum;     vt = "u64"; break;
                case AggFn::Avg:   k = IRMap::AggSum;     vt = "struct avg_stat"; break;
                case AggFn::Hist:  k = IRMap::AggHist;    vt = "u64"; break;
                case AggFn::Min:   k = IRMap::AggSum;     vt = "s64"; break;
                case AggFn::Max:   k = IRMap::AggSum;     vt = "s64"; break;
            }
            ir->maps.push_back({"@" + a.target, "u32", vt, 1024, k});
        }
        for (const auto& e : r->emits) {
            IREventStruct ev;
            ev.name = ir->toolName + "_event_" + std::to_string(ir->events.size());
            for (const auto& f : e.fields) {
                ev.fields.push_back({f.name, "long"});  // 简化：统一用 long
            }
            ir->events.push_back(ev);
        }

        // 目标映射
        for (const auto& t : r->hook.targets) {
            IRProbe enter, exit;
            enter.measuresLatency = hasLatency;
            exit.measuresLatency  = false;
            for (auto& w : r->wheres) enter.whereConds.push_back(exprToC(*w.cond));
            for (auto& w : r->whens)  exit.whenConds.push_back(exprToC(*w.cond));

            switch (r->hook.kind) {
                case HookKind::Syscall:
                    enter.section = "tracepoint/syscalls/sys_enter_" + t;
                    enter.hookName = t;
                    exit.section  = "tracepoint/syscalls/sys_exit_" + t;
                    exit.hookName = t;
                    break;
                case HookKind::Kprobe:
                    enter.section = "kprobe/" + t;
                    enter.hookName = t;
                    exit.section  = "kretprobe/" + t;
                    exit.hookName = t;
                    break;
                default:
                    enter.section = "uprobe/" + t;
                    enter.hookName = t;
                    exit.section  = "uretprobe/" + t;
                    exit.hookName = t;
            }
            ir->probes.push_back(enter);
            if (hasLatency) ir->probes.push_back(exit);
        }
    }

    // every 块：保留 interval 文本
    for (const auto& es : ast.everyStmts) {
        if (es.interval) ir->everyTasks.push_back(exprToC(*es.interval));
    }
    return ir;
}

void IRProgram::dump(std::ostream& os) const {
    os << "[IR] tool = " << toolName << "\n";
    os << "[IR] maps=" << maps.size() << " probes=" << probes.size()
       << " events=" << events.size() << "\n";
    for (const auto& m : maps) os << "  map " << m.name << " : " << m.key_type << " -> " << m.value_type << "\n";
    for (const auto& p : probes) os << "  probe " << p.section << " (latency=" << p.measuresLatency << ")\n";
}

}  // namespace emon
