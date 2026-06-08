// Parser 单元测试骨架
#include "../compiler/lexer/emon_lexer.h"
#include "../compiler/parser/emon_parser.h"
#include <cstdio>
#include <stdexcept>

static const char* kProgram =
    "tool syscall_latency_monitor {\n"
    "  option min_latency = 10000;\n"
    "  observe syscall(\"read\") {\n"
    "    where pid > 0;\n"
    "    measure latency;\n"
    "    @count = count(pid);\n"
    "  }\n"
    "}\n";

int main() {
    emon::Lexer lex(kProgram);
    emon::Parser parser(lex.tokens());
    auto prog = parser.parseProgram();
    if (!prog) throw std::runtime_error("parseProgram returned NULL");
    printf("PASS  test_parser (tool name = %s)\n", prog->toolName.c_str());
    return 0;
}
