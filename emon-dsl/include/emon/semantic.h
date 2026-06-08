// =====================================================================
// Emon DSL —— 语义检查接口
// 负责：
//   1. 变量声明前使用检查
//   2. where / when 条件类型检查
//   3. measure latency 对 hook 类型的合法性（例如 syscall 可用、tracepoint 未必）
//   4. 聚合变量 @name 类型一致性
//   5. emit 字段上下文可达性（retval 仅在 exit 探针中可用等）
// =====================================================================
#pragma once

#include "emon/ast_nodes.h"
#include <string>

namespace emon {

struct SemanticChecker {
    bool check(const Program& p);
    const std::string& lastError() const { return err_; }

private:
    std::string err_;
    bool checkRule(const ObserveRule& r);
    bool checkExpr(const Expr& e, const std::string& phase);
};

}  // namespace emon
