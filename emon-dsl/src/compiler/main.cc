// =====================================================================
// Emon DSL 编译器入口
// 流程：输入 *.emon → lexer → parser → AST → 语义检查 → IR → 代码生成
//       输出：*.bpf.c / *_loader.c / *.yaml
// =====================================================================
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "emon/ast_nodes.h"
#include "emon/codegen.h"
#include "emon/ir.h"
#include "emon/semantic.h"

namespace {

void usage(const char* argv0) {
    std::cerr
        << "用法: " << argv0 << " [选项] <source.emon>\n"
        << "  -o <name>    指定输出名称（默认与源文件同名）\n"
        << "  --out-dir <dir>  输出目录（默认 ./build/generated）\n"
        << "  --dump-ast   打印 AST 到 stderr\n"
        << "  --dump-ir    打印 IR 到 stderr\n"
        << "  --only-check 仅进行语法/语义检查，不生成代码\n"
        << "  -h | --help  显示本帮助\n"
        << "参考: 文档 4.1 语言定义、5.1-5.7 示例翻译流程\n";
}

std::string readFile(const std::string& path) {
    std::ifstream in(path);
    if (!in) {
        throw std::runtime_error("无法打开源文件: " + path);
    }
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

}  // namespace

int main(int argc, char** argv) {
    std::string srcPath;
    std::string outName;
    std::string outDir = "build/generated";
    bool dumpAST = false;
    bool dumpIR  = false;
    bool onlyCheck = false;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "-h" || a == "--help")        { usage(argv[0]); return 0; }
        else if (a == "-o")                     { outName = argv[++i]; }
        else if (a == "--out-dir")              { outDir = argv[++i]; }
        else if (a == "--dump-ast")             { dumpAST = true; }
        else if (a == "--dump-ir")              { dumpIR  = true; }
        else if (a == "--only-check")           { onlyCheck = true; }
        else if (a.front() == '-')              { usage(argv[0]); return 2; }
        else                                    { srcPath = a; }
    }
    if (srcPath.empty()) { usage(argv[0]); return 2; }

    try {
        // 1. 读源
        const std::string source = readFile(srcPath);
        std::cout << "[emon-compiler] 读取源: " << srcPath
                  << " (" << source.size() << " bytes)\n";

        // 2. Lexer → Parser → AST（对应文档 4.1）
        emon::Lexer  lexer(source);
        emon::Parser parser(lexer.tokens());
        auto program = parser.parseProgram();
        if (!program) {
            std::cerr << "[error] 语法分析失败\n";
            return 1;
        }
        if (dumpAST) program->dump(std::cerr, 0);

        // 3. 语义检查（变量 / 字段 / 聚合 / 上下文）
        emon::SemanticChecker sem;
        if (!sem.check(*program)) {
            std::cerr << "[error] 语义检查失败: " << sem.lastError() << "\n";
            return 1;
        }
        std::cout << "[emon-compiler] 语义检查通过\n";

        if (onlyCheck) return 0;

        // 4. IR 构建 —— 将声明式 DSL 转写为内部指令（文档 5.4）
        emon::IRBuilder irb;
        auto ir = irb.build(*program);
        if (dumpIR) ir->dump(std::cerr);

        // 5. 目标代码生成（文档 5.4.1-5.7）
        if (outName.empty()) {
            auto slash = srcPath.find_last_of("/\\");
            auto dot   = srcPath.find_last_of('.');
            outName = srcPath.substr(
                slash == std::string::npos ? 0 : slash + 1,
                (dot == std::string::npos ? srcPath.size() : dot) -
                    (slash == std::string::npos ? 0 : slash + 1));
        }

        emon::CodegenOptions opts;
        opts.toolName    = outName;
        opts.outputDir   = outDir;
        opts.verbose     = dumpIR;

        // 生成 *.bpf.c
        emon::EBPFCodegen cg;
        const auto bpfPath = cg.generate(*ir, opts);
        std::cout << "[emit] eBPF C 源 -> " << bpfPath << "\n";

        // 生成 *_loader.c
        emon::LibbpfLoaderCodegen lcg;
        const auto loaderPath = lcg.generate(*ir, opts);
        std::cout << "[emit] libbpf loader -> " << loaderPath << "\n";

        // 生成 manifest YAML
        emon::ManifestCodegen mcg;
        const auto manifestPath = mcg.generate(*ir, opts);
        std::cout << "[emit] manifest     -> " << manifestPath << "\n";

        std::cout << "[emon-compiler] 成功生成 3 份目标产物\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "[fatal] " << e.what() << "\n";
        return 1;
    }
}
