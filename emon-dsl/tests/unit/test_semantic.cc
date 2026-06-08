// 语义检查测试骨架
#include "../compiler/lexer/emon_lexer.h"
#include "../compiler/parser/emon_parser.h"
#include "emon/semantic.h"
#include <cstdio>
#include <stdexcept>

static const char* kProgram =
    "tool m {\n"
    "  observe syscall(\"read\") {\n"
    "    where pid > 0;\n"
    "    measure latency;\n"
    "    @c = count(pid);\n"
    "  }\n"
    "}\n";

int main() {
    emon::Lexer lex(kProgram);
    emon::Parser parser(lex.tokens());
    auto prog = parser.parseProgram();
    emon::SemanticChecker sem;
    if (!sem.check(*prog)) throw std::runtime_error(sem.lastError());
    printf("PASS  test_semantic\n");
    return 0;
}
