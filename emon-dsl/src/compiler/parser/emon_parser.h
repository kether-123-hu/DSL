// =====================================================================
// Emon DSL —— 语法分析器声明（递归下降）
// 文法参考：grammar/EmonParser.g4
// =====================================================================
#pragma once
#include "../lexer/emon_lexer.h"
#include "emon/ast_nodes.h"
#include <memory>
#include <vector>

namespace emon {

class Parser {
public:
    explicit Parser(const std::vector<Tok>& toks);
    std::unique_ptr<Program> parseProgram();

private:
    const std::vector<Tok>& t_;
    size_t i_ = 0;
    const Tok& peek(size_t k = 0) const { return t_[i_ + k < t_.size() ? i_ + k : t_.size() - 1]; }
    const Tok& eat()             { return t_[i_++]; }
    bool accept(TokType ty)      { if (peek().type == ty) { eat(); return true; } return false; }
    [[noreturn]] void expected(const std::string& what);

    // rule parsers
    void parseToolBody(Program& prog);
    RulePtr parseObserveRule();
    HookKind parseHookKind(std::vector<std::string>& out, std::string& cat);
    ExprPtr parseExpr();
    ExprPtr parseOr();
    ExprPtr parseAnd();
    ExprPtr parseBitOr();
    ExprPtr parseBitXor();
    ExprPtr parseBitAnd();
    ExprPtr parseEquality();
    ExprPtr parseRelational();
    ExprPtr parseShift();
    ExprPtr parseAdd();
    ExprPtr parseMul();
    ExprPtr parseUnary();
    ExprPtr parsePrimary();
};

}  // namespace emon
