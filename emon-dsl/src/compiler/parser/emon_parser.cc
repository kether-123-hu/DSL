// =====================================================================
// Emon DSL Parser —— 递归下降实现
// =====================================================================
#include "emon_parser.h"
#include <sstream>
#include <stdexcept>
#include <string>

namespace emon {

Parser::Parser(const std::vector<Tok>& toks) : t_(toks) {}

[[noreturn]] void Parser::expected(const std::string& what) {
    std::ostringstream os;
    os << "解析错误（第 " << peek().line << " 行）：期望 " << what
       << "，实际遇到 '" << peek().text << "'";
    throw std::runtime_error(os.str());
}

std::unique_ptr<Program> Parser::parseProgram() {
    auto prog = std::make_unique<Program>();
    if (!accept(TokType::K_Tool)) expected("'tool'");
    if (peek().type != TokType::Ident) expected("工具名称");
    prog->toolName = eat().text;
    if (!accept(TokType::LBrace)) expected("'{'");
    parseToolBody(*prog);
    if (!accept(TokType::RBrace)) expected("'}'");
    return prog;
}

void Parser::parseToolBody(Program& prog) {
    while (peek().type != TokType::RBrace && peek().type != TokType::Eof) {
        const TokType t = peek().type;
        if (t == TokType::K_Option) {
            eat();
            if (peek().type != TokType::Ident) expected("option 名称");
            std::string name = eat().text;
            if (!accept(TokType::Assign)) expected("'='");
            ExprPtr v = parseExpr();
            accept(TokType::Semi);
            prog.options.emplace_back(name, std::move(v));
        } else if (t == TokType::K_Observe) {
            prog.rules.push_back(parseObserveRule());
        } else if (t == TokType::K_Every) {
            eat();
            EveryStmt es;
            es.interval = parseExpr();
            if (!accept(TokType::LBrace)) expected("'{'");
            while (!accept(TokType::RBrace)) {
                // every 块目前仅支持聚合 / let / emit
                if (peek().type == TokType::K_Let) {
                    eat();
                    std::string n = eat().text;
                    accept(TokType::Assign);
                    es.aggs.push_back({});  // 占位
                } else {
                    eat();
                }
            }
            prog.everyStmts.push_back(std::move(es));
        } else {
            eat();  // 跳过未知 token，使解析器更健壮
        }
    }
}

RulePtr Parser::parseObserveRule() {
    eat();  // 'observe'
    auto rule = std::make_unique<ObserveRule>();
    std::string cat;
    rule->hook.kind = parseHookKind(rule->hook.targets, cat);
    rule->hook.category = std::move(cat);
    if (!accept(TokType::LBrace)) expected("'{' after observe hook");
    while (!accept(TokType::RBrace)) {
        const TokType t = peek().type;
        if (t == TokType::K_Where) {
            eat();
            rule->wheres.push_back(WhereClause{parseExpr()});
            accept(TokType::Semi);
        } else if (t == TokType::K_Measure) {
            eat();
            Metric m = Metric::Count;
            if (accept(TokType::K_Latency)) m = Metric::Latency;
            else if (accept(TokType::K_Count)) m = Metric::Count;
            else if (accept(TokType::K_Size))  m = Metric::Size;
            else expected("latency/count/size");
            rule->measures.push_back(MeasureClause{m});
            accept(TokType::Semi);
        } else if (t == TokType::K_When) {
            eat();
            rule->whens.push_back(WhenClause{parseExpr()});
            accept(TokType::Semi);
        } else if (t == TokType::K_AggIdent) {
            Aggregation a;
            a.target = eat().text;
            accept(TokType::Assign);
            if (peek().type == TokType::K_Count) a.fn = AggFn::Count, eat();
            else if (peek().type == TokType::K_Sum)  a.fn = AggFn::Sum, eat();
            else if (peek().type == TokType::K_Avg)  a.fn = AggFn::Avg, eat();
            else if (peek().type == TokType::K_Hist) a.fn = AggFn::Hist, eat();
            else if (peek().type == TokType::K_Min)  a.fn = AggFn::Min, eat();
            else if (peek().type == TokType::K_Max)  a.fn = AggFn::Max, eat();
            else expected("聚合函数 count/sum/avg/hist/min/max");
            if (accept(TokType::LParen)) {
                while (!accept(TokType::RParen)) {
                    a.keys.push_back(parseExpr());
                    accept(TokType::Comma);
                }
            }
            accept(TokType::Semi);
            rule->aggregations.push_back(std::move(a));
        } else if (t == TokType::K_Emit) {
            eat();
            EmitStmt es;
            if (!accept(TokType::LBrace)) expected("'{'");
            while (!accept(TokType::RBrace)) {
                if (peek().type != TokType::Ident) expected("emit 字段名");
                std::string fn = eat().text;
                if (!accept(TokType::Colon)) expected("':'");
                es.fields.push_back({fn, parseExpr()});
                accept(TokType::Comma);
            }
            accept(TokType::Semi);
            rule->emits.push_back(std::move(es));
        } else if (t == TokType::K_Let) {
            eat();
            LetStmt ls;
            if (peek().type != TokType::Ident) expected("变量名");
            ls.name = eat().text;
            accept(TokType::Assign);
            ls.value = parseExpr();
            accept(TokType::Semi);
            rule->lets.push_back(std::move(ls));
        } else {
            eat();
        }
    }
    return rule;
}

HookKind Parser::parseHookKind(std::vector<std::string>& out, std::string& cat) {
    const TokType t = peek().type;
    if (t == TokType::K_Syscall) {
        eat();
        if (!accept(TokType::LParen)) expected("'('");
        while (!accept(TokType::RParen)) {
            if (peek().type != TokType::String) expected("字符串 syscall 名");
            out.push_back(eat().text);
            accept(TokType::Comma);
        }
        return HookKind::Syscall;
    }
    if (t == TokType::K_Tracepoint) {
        eat();
        accept(TokType::LParen);
        if (peek().type == TokType::String) cat = eat().text;
        accept(TokType::Comma);
        while (!accept(TokType::RParen)) {
            if (peek().type == TokType::String) out.push_back(eat().text);
            accept(TokType::Comma);
        }
        return HookKind::Tracepoint;
    }
    auto single = [&](HookKind k) {
        eat();
        accept(TokType::LParen);
        if (peek().type == TokType::String) out.push_back(eat().text);
        accept(TokType::Colon);
        if (peek().type == TokType::String) cat = eat().text;
        accept(TokType::RParen);
        return k;
    };
    switch (t) {
        case TokType::K_Kprobe:    return single(HookKind::Kprobe);
        case TokType::K_Kretprobe: return single(HookKind::Kretprobe);
        case TokType::K_Uprobe:    return single(HookKind::Uprobe);
        case TokType::K_Fentry:    return single(HookKind::Fentry);
        case TokType::K_Fexit:     return single(HookKind::Fexit);
        case TokType::K_Net:       eat(); accept(TokType::LParen); accept(TokType::RParen); return HookKind::Net;
        case TokType::K_File:      eat(); accept(TokType::LParen); accept(TokType::RParen); return HookKind::File;
        case TokType::K_Proc:      eat(); accept(TokType::LParen); accept(TokType::RParen); return HookKind::Proc;
        default: expected("hook 类型 (syscall/tracepoint/kprobe/...)"); return HookKind::Syscall;
    }
}

ExprPtr Parser::parseExpr()     { return parseOr(); }
ExprPtr Parser::parseOr()       { auto l = parseAnd(); while (accept(TokType::Or))  l = std::make_unique<BinOp>(BinOp::Or, std::move(l), parseAnd()); return l; }
ExprPtr Parser::parseAnd()      { auto l = parseBitOr(); while (accept(TokType::And)) l = std::make_unique<BinOp>(BinOp::And, std::move(l), parseBitOr()); return l; }
ExprPtr Parser::parseBitOr()    { auto l = parseBitXor(); while (accept(TokType::BitOr)) l = std::make_unique<BinOp>(BinOp::BitOr, std::move(l), parseBitXor()); return l; }
ExprPtr Parser::parseBitXor()   { auto l = parseBitAnd(); while (accept(TokType::BitXor)) l = std::make_unique<BinOp>(BinOp::BitXor, std::move(l), parseBitAnd()); return l; }
ExprPtr Parser::parseBitAnd()   { auto l = parseEquality(); while (accept(TokType::BitAnd)) l = std::make_unique<BinOp>(BinOp::BitAnd, std::move(l), parseEquality()); return l; }
ExprPtr Parser::parseEquality() { auto l = parseRelational(); while (true) { if (accept(TokType::Eq))  l = std::make_unique<BinOp>(BinOp::Eq, std::move(l), parseRelational()); else if (accept(TokType::Neq)) l = std::make_unique<BinOp>(BinOp::Neq, std::move(l), parseRelational()); else return l; } }
ExprPtr Parser::parseRelational() { auto l = parseShift(); while (true) { if (accept(TokType::Lt)) l = std::make_unique<BinOp>(BinOp::Lt, std::move(l), parseShift()); else if (accept(TokType::Gt)) l = std::make_unique<BinOp>(BinOp::Gt, std::move(l), parseShift()); else if (accept(TokType::Le)) l = std::make_unique<BinOp>(BinOp::Le, std::move(l), parseShift()); else if (accept(TokType::Ge)) l = std::make_unique<BinOp>(BinOp::Ge, std::move(l), parseShift()); else return l; } }
ExprPtr Parser::parseShift()    { auto l = parseAdd(); while (true) { if (accept(TokType::LShift)) l = std::make_unique<BinOp>(BinOp::LShift, std::move(l), parseAdd()); else if (accept(TokType::RShift)) l = std::make_unique<BinOp>(BinOp::RShift, std::move(l), parseAdd()); else return l; } }
ExprPtr Parser::parseAdd()      { auto l = parseMul(); while (true) { if (accept(TokType::Plus))  l = std::make_unique<BinOp>(BinOp::Add, std::move(l), parseMul()); else if (accept(TokType::Minus)) l = std::make_unique<BinOp>(BinOp::Sub, std::move(l), parseMul()); else return l; } }
ExprPtr Parser::parseMul()      { auto l = parseUnary(); while (true) { if (accept(TokType::Star)) l = std::make_unique<BinOp>(BinOp::Mul, std::move(l), parseUnary()); else if (accept(TokType::Slash)) l = std::make_unique<BinOp>(BinOp::Div, std::move(l), parseUnary()); else if (accept(TokType::Percent)) l = std::make_unique<BinOp>(BinOp::Mod, std::move(l), parseUnary()); else return l; } }
ExprPtr Parser::parseUnary()    { if (accept(TokType::Not)) return std::make_unique<UnaryOp>(UnaryOp::Not, parseUnary()); if (accept(TokType::Minus)) return std::make_unique<UnaryOp>(UnaryOp::Neg, parseUnary()); return parsePrimary(); }

ExprPtr Parser::parsePrimary() {
    const Tok& tk = peek();
    switch (tk.type) {
        case TokType::LParen: {
            eat();
            auto e = parseExpr();
            if (!accept(TokType::RParen)) expected("')'");
            return e;
        }
        case TokType::Int:     eat(); return std::make_unique<LitInt>(std::stoll(tk.text));
        case TokType::Float:   eat(); return std::make_unique<LitFloat>(std::stod(tk.text));
        case TokType::String:  eat(); return std::make_unique<LitStr>(tk.text);
        case TokType::K_True:  eat(); return std::make_unique<LitBool>(true);
        case TokType::K_False: eat(); return std::make_unique<LitBool>(false);
        case TokType::Time:    eat(); return std::make_unique<LitTime>(1000);
        case TokType::Size:    eat(); return std::make_unique<LitSize>(1024);
        case TokType::AggIdent: eat(); return std::make_unique<AggIdent>(tk.text);
        case TokType::K_Pid: case TokType::K_Tid: case TokType::K_Uid:
        case TokType::K_Gid: case TokType::K_Cpu: case TokType::K_Comm:
        case TokType::K_Retval: case TokType::K_Syscall:
        case TokType::K_Arg0: case TokType::K_Arg1: case TokType::K_Arg2:
        case TokType::K_Arg3: case TokType::K_Arg4: case TokType::K_Arg5:
            eat(); return std::make_unique<CtxIdent>(tk.text);
        case TokType::Ident: eat(); return std::make_unique<Ident>(tk.text);
        default:
            expected("表达式");
            return nullptr;
    }
}

// ---- AST dump helpers ----
std::string LitInt::dump(int) const { return "LitInt(" + std::to_string(value) + ")"; }
std::string LitFloat::dump(int) const { return "LitFloat(" + std::to_string(value) + ")"; }
std::string LitStr::dump(int) const { return "LitStr(\"" + value + "\")"; }
std::string LitBool::dump(int) const { return value ? "true" : "false"; }
std::string LitTime::dump(int) const { return "LitTime(" + std::to_string(nanos) + "ns)"; }
std::string LitSize::dump(int) const { return "LitSize(" + std::to_string(bytes) + "B)"; }
std::string CtxIdent::dump(int) const { return "ctx::" + name; }
std::string Ident::dump(int) const { return "$" + name; }
std::string AggIdent::dump(int) const { return "@" + name; }

static const char* opName(BinOp::Op op) {
    switch (op) {
        case BinOp::Add: return "+"; case BinOp::Sub: return "-";
        case BinOp::Mul: return "*"; case BinOp::Div: return "/"; case BinOp::Mod: return "%";
        case BinOp::LShift: return "<<"; case BinOp::RShift: return ">>";
        case BinOp::BitAnd: return "&"; case BinOp::BitOr: return "|"; case BinOp::BitXor: return "^";
        case BinOp::Lt: return "<"; case BinOp::Gt: return ">"; case BinOp::Le: return "<="; case BinOp::Ge: return ">=";
        case BinOp::Eq: return "=="; case BinOp::Neq: return "!=";
        case BinOp::And: return "&&"; case BinOp::Or: return "||";
    }
    return "?";
}
std::string BinOp::dump(int) const {
    return "(" + lhs->dump() + " " + opName(op) + " " + rhs->dump() + ")";
}
std::string UnaryOp::dump(int) const {
    return std::string(op == Not ? "!" : "-") + operand->dump();
}

static std::string indentStr(int n) { return std::string(n * 2, ' '); }

void ObserveRule::dump(std::ostream& os, int n) const {
    os << indentStr(n) << "observe(...)\n";
    for (auto& w : wheres) os << indentStr(n + 1) << "where " << w.cond->dump() << "\n";
    for (auto& m : measures)
        os << indentStr(n + 1) << "measure " << (m.metric == Metric::Latency ? "latency" : "count") << "\n";
    for (auto& w : whens)   os << indentStr(n + 1) << "when " << w.cond->dump() << "\n";
    for (auto& a : aggregations)
        os << indentStr(n + 1) << "@" << a.target << " = fn(" << a.keys.size() << " keys)\n";
    for (auto& e : emits)
        os << indentStr(n + 1) << "emit(" << e.fields.size() << " fields)\n";
}

void Program::dump(std::ostream& os, int n) const {
    os << indentStr(n) << "tool " << toolName << " {\n";
    for (auto& opt : options) os << indentStr(n + 1) << "option " << opt.first << " = " << opt.second->dump() << "\n";
    for (auto& r : rules) r->dump(os, n + 1);
    os << indentStr(n) << "}\n";
}

}  // namespace emon
