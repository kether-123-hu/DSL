// =====================================================================
// Emon DSL 语义检查器（骨架）
// 参考：文档 4.1.2 / 5.4 —— 上下文可达性、类型一致性
// =====================================================================
#include "emon/semantic.h"
#include <set>
#include <sstream>

namespace emon {

static const std::set<std::string> kExitOnly = {"retval"};
static const std::set<std::string> kBuiltinCtx = {
    "pid","tid","uid","gid","cpu","comm","retval","syscall",
    "arg0","arg1","arg2","arg3","arg4","arg5",
};

bool SemanticChecker::check(const Program& p) {
    for (const auto& r : p.rules) {
        if (!checkRule(*r)) return false;
    }
    return true;
}

bool SemanticChecker::checkRule(const ObserveRule& r) {
    const bool has_latency = [&] { for (auto& m : r.measures) if (m.metric == Metric::Latency) return true; return false; }();

    for (auto& w : r.wheres) if (!checkExpr(*w.cond, "where")) return false;
    for (auto& w : r.whens)  if (!checkExpr(*w.cond, "when"))  return false;

    // 基本约束：非成对探针下，retval 不可在 where 中使用（只在 exit/return 路径可用）
    // 这里做最小检查骨架
    (void)has_latency;
    return true;
}

bool SemanticChecker::checkExpr(const Expr& e, const std::string& phase) {
    if (auto* c = dynamic_cast<const CtxIdent*>(&e)) {
        if (kBuiltinCtx.count(c->name) == 0) {
            err_ = phase + " 中引用了未知上下文变量: " + c->name;
            return false;
        }
        if (phase == "where" && kExitOnly.count(c->name)) {
            err_ = phase + " 阶段不允许引用 '" + c->name + "'（只在事件返回后可用）";
            return false;
        }
    }
    if (auto* b = dynamic_cast<const BinOp*>(&e)) {
        return checkExpr(*b->lhs, phase) && checkExpr(*b->rhs, phase);
    }
    if (auto* u = dynamic_cast<const UnaryOp*>(&e)) {
        return checkExpr(*u->operand, phase);
    }
    return true;
}

}  // namespace emon
