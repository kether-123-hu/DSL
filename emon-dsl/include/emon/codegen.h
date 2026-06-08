// =====================================================================
// Emon DSL —— 代码生成接口
// 三类产物（对应文档 5.4.2 / 5.4.7）：
//   *.bpf.c             内核态 eBPF C 程序（clang -target bpf 编译）
//   *_loader.c          用户态 libbpf loader（与 libbpf 链接）
//   *.yaml              工具 manifest
// =====================================================================
#pragma once

#include "emon/ir.h"
#include <string>

namespace emon {

struct CodegenOptions {
    std::string toolName;
    std::string outputDir;
    bool verbose = false;
};

// eBPF C 源代码生成（内核态 BPF 程序
struct EBPFCodegen {
    std::string generate(const IRProgram& ir, const CodegenOptions& opts);
};

// libbpf 加载器（用户态）
struct LibbpfLoaderCodegen {
    std::string generate(const IRProgram& ir, const CodegenOptions& opts);
};

// manifest (YAML)
struct ManifestCodegen {
    std::string generate(const IRProgram& ir, const CodegenOptions& opts);
};

// 通用：把字符串写入文件；返回写入的路径
std::string writeToFile(const std::string& dir, const std::string& name,
                     const std::string& content);

}  // namespace emon
