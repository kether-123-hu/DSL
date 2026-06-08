// =====================================================================
// Emon DSL —— 轻量级 Lexer 骨架（可被 ANTLR4 生成器替换）
// 本实现提供一个最小可用的 token 序列，供 AST/语义模块做原型驱动
// =====================================================================
#pragma once
#include <string>
#include <vector>

namespace emon {

enum class TokType {
    // 关键字
    K_Tool, K_Option, K_Observe, K_Where, K_Measure, K_When,
    K_Emit, K_Every, K_Let, K_Count, K_Sum, K_Avg, K_Hist,
    K_Min, K_Max, K_Latency, K_Size,
    K_Syscall, K_Tracepoint, K_Kprobe, K_Kretprobe,
    K_Uprobe, K_Fentry, K_Fexit, K_Net, K_File, K_Proc,
    // 内置上下文变量
    K_Pid, K_Tid, K_Uid, K_Gid, K_Cpu, K_Comm, K_Retval,
    K_Arg0, K_Arg1, K_Arg2, K_Arg3, K_Arg4, K_Arg5,
    K_True, K_False,
    // 字面量
    Int, Float, String, Time, Size, Ident, AggIdent,
    // 标点与运算符
    LParen, RParen, LBrace, RBrace, Comma, Semi, Colon, Dot, Assign,
    Plus, Minus, Star, Slash, Percent,
    Eq, Neq, Lt, Gt, Le, Ge, And, Or, Not,
    BitAnd, BitOr, BitXor, LShift, RShift,
    Eof,
};

struct Tok {
    TokType type;
    std::string text;
    int line;
};

class Lexer {
public:
    explicit Lexer(const std::string& source);
    const std::vector<Tok>& tokens() const { return toks_; }
    void tokenize();   // 执行扫描（由 Parser/Lexer 外部调用）

private:
    std::string src_;
    std::vector<Tok> toks_;
    size_t pos_ = 0;
    int line_ = 1;
};

}  // namespace emon
