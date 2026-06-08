// Lexer 单元测试（骨架）
#include "../compiler/lexer/emon_lexer.h"
#include <cassert>
#include <cstdio>
#include <stdexcept>

static void expect_ok(const std::string& src) {
    emon::Lexer lex(src);
    if (lex.tokens().empty())
        throw std::runtime_error("lexer produced 0 tokens");
    printf("  [lex] tokens(%zu) from source of %zu bytes\n",
           lex.tokens().size(), src.size());
}

int main() {
    expect_ok("tool foo { option x = 1; observe syscall(\"read\") { measure latency; } }");
    printf("PASS  test_lexer\n");
    return 0;
}
