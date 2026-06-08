// =====================================================================
// Emon DSL —— 公共 AST 节点（include/emon/ast_nodes.h）
// 对应文档 4.1.2 句法定义的文法产物
// =====================================================================
#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <variant>
#include <vector>

namespace emon {

enum class HookKind {
    Syscall, Tracepoint, Kprobe, Kretprobe,
    Uprobe, Uretprobe, Fentry, Fexit,
    Net, File, Proc,
};

enum class Metric { Latency, Count, Size };
enum class AggFn   { Count, Sum, Avg, Hist, Min, Max };

// ---------- 表达式节点 ----------
struct Expr {
    virtual ~Expr() = default;
    virtual std::string dump(int indent = 0) const = 0;
};
using ExprPtr = std::unique_ptr<Expr>;

struct LitInt : Expr {
    int64_t value;
    explicit LitInt(int64_t v) : value(v) {}
    std::string dump(int) const override;
};
struct LitFloat : Expr {
    double value;
    explicit LitFloat(double v) : value(v) {}
    std::string dump(int) const override;
};
struct LitStr : Expr {
    std::string value;
    explicit LitStr(std::string s) : value(std::move(s)) {}
    std::string dump(int) const override;
};
struct LitBool : Expr {
    bool value;
    explicit LitBool(bool v) : value(v) {}
    std::string dump(int) const override;
};
struct LitTime : Expr {
    int64_t nanos;
    explicit LitTime(int64_t n) : nanos(n) {}
    std::string dump(int) const override;
};
struct LitSize : Expr {
    uint64_t bytes;
    explicit LitSize(uint64_t b) : bytes(b) {}
    std::string dump(int) const override;
};

struct CtxIdent : Expr {
    // pid / tid / uid / gid / cpu / comm / retval / syscall / argN
    std::string name;
    explicit CtxIdent(std::string n) : name(std::move(n)) {}
    std::string dump(int) const override;
};
struct Ident : Expr {
    std::string name;
    explicit Ident(std::string n) : name(std::move(n)) {}
    std::string dump(int) const override;
};
struct AggIdent : Expr {
    std::string name;  // 不含 @ 前缀
    explicit AggIdent(std::string n) : name(std::move(n)) {}
    std::string dump(int) const override;
};

struct BinOp : Expr {
    enum Op { Add, Sub, Mul, Div, Mod,
              LShift, RShift, BitAnd, BitOr, BitXor,
              Lt, Gt, Le, Ge, Eq, Neq, And, Or };
    Op op; ExprPtr lhs, rhs;
    BinOp(Op o, ExprPtr l, ExprPtr r)
        : op(o), lhs(std::move(l)), rhs(std::move(r)) {}
    std::string dump(int) const override;
};
struct UnaryOp : Expr {
    enum Op { Not, Neg };
    Op op; ExprPtr operand;
    UnaryOp(Op o, ExprPtr x) : op(o), operand(std::move(x)) {}
    std::string dump(int) const override;
};

// ---------- 子句 ----------
struct ObserveRule;
using RulePtr = std::unique_ptr<ObserveRule>;

struct WhereClause    { ExprPtr cond; };
struct WhenClause     { ExprPtr cond; };
struct MeasureClause  { Metric metric; };

struct Aggregation {
    std::string target;     // @foo 的名字 "foo"
    AggFn fn;
    std::vector<ExprPtr> keys;
};

struct EmitField {
    std::string name;
    ExprPtr value;
};
struct EmitStmt { std::vector<EmitField> fields; };

struct LetStmt  { std::string name; ExprPtr value; };
struct EveryStmt {
    ExprPtr interval;
    std::vector<RulePtr> rules;  // may also contain print/agg-read
    std::vector<Aggregation> aggs;
};

// ---------- Hook 描述 ----------
struct Hook {
    HookKind kind;
    std::vector<std::string> targets;  // syscall names, function names...
    std::string category;              // tracepoint 类别 / uprobes 路径等
};

struct ObserveRule {
    Hook hook;
    std::vector<WhereClause>    wheres;
    std::vector<MeasureClause>  measures;
    std::vector<WhenClause>     whens;
    std::vector<Aggregation>    aggregations;
    std::vector<EmitStmt>       emits;
    std::vector<LetStmt>        lets;

    void dump(std::ostream& os, int indent) const;
};

// ---------- 顶层程序 ----------
struct Program {
    std::string toolName;
    std::vector<std::pair<std::string, ExprPtr>> options;  // name -> default
    std::vector<RulePtr> rules;
    std::vector<EveryStmt> everyStmts;

    void dump(std::ostream& os, int indent) const;
};

}  // namespace emon
