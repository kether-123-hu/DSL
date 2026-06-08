// Emon DSL —— 集成测试：编译 examples/*.emon
// 对应文档 5.1-5.7 的示例程序验证
#include "../compiler/lexer/emon_lexer.h"
#include "../compiler/parser/emon_parser.h"
#include "emon/codegen.h"
#include "emon/ir.h"
#include "emon/semantic.h"
#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>

static std::string readAll(const std::string& path) {
    std::ifstream f(path);
    if (!f) return "";
    std::ostringstream ss; ss << f.rdbuf(); return ss.str();
}

int main(int argc, char** argv) {
    const char* files[] = {
        "examples/syscall_latency.emon",
        "examples/syscall_count.emon",
        nullptr,
    };
    (void)argc; (void)argv;
    int pass = 0, fail = 0;
    for (int i = 0; files[i]; ++i) {
        auto src = readAll(files[i]);
        if (src.empty()) { ++fail; fprintf(stderr, "MISSING %s\n", files[i]); continue; }
        try {
            emon::Lexer lex(src);
            emon::Parser parser(lex.tokens());
            auto prog = parser.parseProgram();
            if (!prog) throw std::runtime_error("parse null");
            emon::SemanticChecker sem;
            if (!sem.check(*prog)) throw std::runtime_error(sem.lastError());
            emon::IRBuilder irb;
            auto ir = irb.build(*prog);
            emon::CodegenOptions opts;
            opts.toolName = "test_" + std::to_string(i);
            opts.outputDir = "/tmp/emon-out";
            emon::EBPFCodegen().generate(*ir, opts);
            emon::LibbpfLoaderCodegen().generate(*ir, opts);
            emon::ManifestCodegen().generate(*ir, opts);
            ++pass;
            printf("PASS  %s\n", files[i]);
        } catch (std::exception& e) {
            ++fail;
            printf("FAIL  %s: %s\n", files[i], e.what());
        }
    }
    printf("=== integration: %d pass, %d fail ===\n", pass, fail);
    return fail ? 1 : 0;
}
