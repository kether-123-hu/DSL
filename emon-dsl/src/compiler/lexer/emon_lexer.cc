// =====================================================================
// Emon DSL Lexer —— 轻量实现（非 ANTLR，可作为 ANTLR 生成器的参考/替代）
// 文档参考：4.1.1 词法定义
// =====================================================================
#include "emon_lexer.h"
#include <cctype>
#include <sstream>
#include <stdexcept>
#include <unordered_map>

namespace emon {

static const std::unordered_map<std::string, TokType> KW = {
    {"tool", TokType::K_Tool}, {"option", TokType::K_Option},
    {"observe", TokType::K_Observe}, {"where", TokType::K_Where},
    {"measure", TokType::K_Measure}, {"when", TokType::K_When},
    {"emit", TokType::K_Emit}, {"every", TokType::K_Every},
    {"let", TokType::K_Let},
    {"count", TokType::K_Count}, {"sum", TokType::K_Sum},
    {"avg", TokType::K_Avg}, {"hist", TokType::K_Hist},
    {"min", TokType::K_Min}, {"max", TokType::K_Max},
    {"latency", TokType::K_Latency}, {"size", TokType::K_Size},
    {"syscall", TokType::K_Syscall}, {"tracepoint", TokType::K_Tracepoint},
    {"kprobe", TokType::K_Kprobe}, {"kretprobe", TokType::K_Kretprobe},
    {"uprobe", TokType::K_Uprobe}, {"fentry", TokType::K_Fentry},
    {"fexit", TokType::K_Fexit},
    {"net", TokType::K_Net}, {"file", TokType::K_File}, {"proc", TokType::K_Proc},
    {"pid", TokType::K_Pid}, {"tid", TokType::K_Tid}, {"uid", TokType::K_Uid},
    {"gid", TokType::K_Gid}, {"cpu", TokType::K_Cpu}, {"comm", TokType::K_Comm},
    {"retval", TokType::K_Retval},
    {"arg0", TokType::K_Arg0}, {"arg1", TokType::K_Arg1},
    {"arg2", TokType::K_Arg2}, {"arg3", TokType::K_Arg3},
    {"arg4", TokType::K_Arg4}, {"arg5", TokType::K_Arg5},
    {"true", TokType::K_True}, {"false", TokType::K_False},
};

Lexer::Lexer(const std::string& source) : src_(source) { tokenize(); }

static inline bool isIdStart(char c) { return std::isalpha(static_cast<unsigned char>(c)) || c == '_'; }
static inline bool isIdCont(char c)  { return std::isalnum(static_cast<unsigned char>(c)) || c == '_'; }

void Lexer::tokenize() {
    const size_t N = src_.size();
    auto emit = [&](TokType t, std::string txt) {
        toks_.push_back({t, std::move(txt), line_});
    };
    while (pos_ < N) {
        const char c = src_[pos_];

        // 空白
        if (c == ' ' || c == '\t' || c == '\r') { ++pos_; continue; }
        if (c == '\n') { ++pos_; ++line_; continue; }

        // 注释
        if (c == '/' && pos_ + 1 < N && src_[pos_ + 1] == '/') {
            while (pos_ < N && src_[pos_] != '\n') ++pos_;
            continue;
        }
        if (c == '/' && pos_ + 1 < N && src_[pos_ + 1] == '*') {
            pos_ += 2;
            while (pos_ + 1 < N && !(src_[pos_] == '*' && src_[pos_ + 1] == '/')) {
                if (src_[pos_] == '\n') ++line_;
                ++pos_;
            }
            pos_ = (pos_ + 2 > N ? N : pos_ + 2);
            continue;
        }

        // 字符串
        if (c == '"') {
            size_t p = pos_ + 1;
            std::string s;
            while (p < N && src_[p] != '"') {
                if (src_[p] == '\\' && p + 1 < N) {
                    char e = src_[++p];
                    switch (e) {
                        case 'n': s += '\n'; break;
                        case 't': s += '\t'; break;
                        case 'r': s += '\r'; break;
                        case '0': s += '\0'; break;
                        default:  s += e;    break;
                    }
                    ++p;
                } else if (src_[p] == '\n') {
                    throw std::runtime_error("unterminated string on line " + std::to_string(line_));
                } else {
                    s += src_[p++];
                }
            }
            emit(TokType::String, s);
            pos_ = (p + 1 <= N ? p + 1 : N);
            continue;
        }

        // 数字 / 时间字面量 / 大小字面量
        if (std::isdigit(static_cast<unsigned char>(c))) {
            size_t p = pos_;
            while (p < N && std::isdigit(static_cast<unsigned char>(src_[p]))) ++p;
            if (p < N && src_[p] == '.') {
                ++p;
                while (p < N && std::isdigit(static_cast<unsigned char>(src_[p]))) ++p;
                emit(TokType::Float, src_.substr(pos_, p - pos_));
                pos_ = p;
                continue;
            }
            // 时间/大小后缀
            auto suf = [&](const std::string& s) -> bool {
                return src_.compare(p, s.size(), s) == 0 &&
                       (p + s.size() >= N || !isIdCont(src_[p + s.size()]));
            };
            for (auto unit : {"us","usec","ms","msec","s","sec","min","hr"}) {
                if (suf(unit)) {
                    emit(TokType::Time, src_.substr(pos_, p - pos_) + unit);
                    pos_ = p + std::string(unit).size();
                    goto next;
                }
            }
            for (auto unit : {"KB","MB","GB","TB","B"}) {
                if (suf(unit)) {
                    emit(TokType::Size, src_.substr(pos_, p - pos_) + unit);
                    pos_ = p + std::string(unit).size();
                    goto next;
                }
            }
            emit(TokType::Int, src_.substr(pos_, p - pos_));
            pos_ = p;
            continue;
        next: (void)0;
            continue;
        }

        // 聚合变量 @name
        if (c == '@') {
            size_t p = pos_ + 1;
            while (p < N && isIdCont(src_[p])) ++p;
            if (p == pos_ + 1) throw std::runtime_error("invalid @-ident");
            emit(TokType::AggIdent, src_.substr(pos_ + 1, p - pos_ - 1));
            pos_ = p;
            continue;
        }

        // 标识符 / 关键字
        if (isIdStart(c)) {
            size_t p = pos_;
            while (p < N && isIdCont(src_[p])) ++p;
            std::string word = src_.substr(pos_, p - pos_);
            auto it = KW.find(word);
            emit(it == KW.end() ? TokType::Ident : it->second, word);
            pos_ = p;
            continue;
        }

        // 运算符
        switch (c) {
            case '(': emit(TokType::LParen, "("); ++pos_; break;
            case ')': emit(TokType::RParen, ")"); ++pos_; break;
            case '{': emit(TokType::LBrace, "{"); ++pos_; break;
            case '}': emit(TokType::RBrace, "}"); ++pos_; break;
            case ',': emit(TokType::Comma, ","); ++pos_; break;
            case ';': emit(TokType::Semi, ";"); ++pos_; break;
            case ':': emit(TokType::Colon, ":"); ++pos_; break;
            case '.': emit(TokType::Dot, "."); ++pos_; break;
            case '+': emit(TokType::Plus, "+"); ++pos_; break;
            case '-': emit(TokType::Minus, "-"); ++pos_; break;
            case '*': emit(TokType::Star, "*"); ++pos_; break;
            case '/': emit(TokType::Slash, "/"); ++pos_; break;
            case '%': emit(TokType::Percent, "%"); ++pos_; break;
            case '=':
                if (pos_ + 1 < N && src_[pos_ + 1] == '=') { emit(TokType::Eq, "=="); pos_ += 2; }
                else { emit(TokType::Assign, "="); ++pos_; }
                break;
            case '!':
                if (pos_ + 1 < N && src_[pos_ + 1] == '=') { emit(TokType::Neq, "!="); pos_ += 2; }
                else { emit(TokType::Not, "!"); ++pos_; }
                break;
            case '<':
                if (pos_ + 1 < N && src_[pos_ + 1] == '=') { emit(TokType::Le, "<="); pos_ += 2; }
                else if (pos_ + 1 < N && src_[pos_ + 1] == '<') { emit(TokType::LShift, "<<"); pos_ += 2; }
                else { emit(TokType::Lt, "<"); ++pos_; }
                break;
            case '>':
                if (pos_ + 1 < N && src_[pos_ + 1] == '=') { emit(TokType::Ge, ">="); pos_ += 2; }
                else if (pos_ + 1 < N && src_[pos_ + 1] == '>') { emit(TokType::RShift, ">>"); pos_ += 2; }
                else { emit(TokType::Gt, ">"); ++pos_; }
                break;
            case '&':
                if (pos_ + 1 < N && src_[pos_ + 1] == '&') { emit(TokType::And, "&&"); pos_ += 2; }
                else { emit(TokType::BitAnd, "&"); ++pos_; }
                break;
            case '|':
                if (pos_ + 1 < N && src_[pos_ + 1] == '|') { emit(TokType::Or, "||"); pos_ += 2; }
                else { emit(TokType::BitOr, "|"); ++pos_; }
                break;
            case '^': emit(TokType::BitXor, "^"); ++pos_; break;
            default:
                throw std::runtime_error("unexpected character '" + std::string(1, c) + "' at line " + std::to_string(line_));
        }
    }
    toks_.push_back({TokType::Eof, "", line_});
}

}  // namespace emon
