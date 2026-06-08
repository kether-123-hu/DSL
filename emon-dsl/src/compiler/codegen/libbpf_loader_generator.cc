// =====================================================================
// Emon DSL —— 用户态 libbpf 加载器生成（文档 5.4.7）
// 负责：打开 *.o → 加载 → attach → 周期性 poll / 读 map → 输出
// =====================================================================
#include "emon/codegen.h"

namespace emon {

std::string LibbpfLoaderCodegen::generate(const IRProgram& ir,
                                          const CodegenOptions& opts) {
    std::ostringstream os;
    os << "// =====================================================================\n"
       << "// " << opts.toolName << " —— 用户态 libbpf 加载器（自动生成）\n"
       << "// 用法：\n"
       << "//   clang -c -g -O2 -target bpf " << opts.toolName << ".bpf.c \\\n"
       << "//       -o " << opts.toolName << ".bpf.o\n"
       << "//   bpftool gen skeleton " << opts.toolName << ".bpf.o \\\n"
       << "//       > " << opts.toolName << ".skel.h\n"
       << "//   gcc " << opts.toolName << "_loader.c -o " << opts.toolName
       << "_loader -lbpf -lelf -lz\n"
       << "// =====================================================================\n\n"
       << "#include <stdio.h>\n"
       << "#include <stdlib.h>\n"
       << "#include <unistd.h>\n"
       << "#include <signal.h>\n"
       << "#include <time.h>\n"
       << "#include <bpf/libbpf.h>\n\n"
       << "#include \"" << opts.toolName << ".skel.h\"\n\n"
       << "static volatile sig_atomic_t stop = 0;\n"
       << "static void sigint_handler(int) { stop = 1; }\n\n"
       << "static int handle_event(void *ctx, void *data, size_t sz) {\n"
       << "    (void)ctx; (void)sz;\n"
       << "    // emit 事件输出（文档 5.4.6 / 5.4.7）\n"
       << "    struct " << (ir.events.empty() ? std::string("{ long _;}") : ir.events[0].name)
       << " *ev = data;\n"
       << "    fprintf(stderr, \"[event] pid=%%d\\n\", (int)(long)ev);\n"
       << "    return 0;\n}\n\n"
       << "int main(int argc, char **argv) {\n"
       << "    struct " << opts.toolName << "_bpf *skel;\n"
       << "    struct ring_buffer *rb = NULL;\n"
       << "    int err;\n\n"
       << "    signal(SIGINT, sigint_handler);\n"
       << "    signal(SIGTERM, sigint_handler);\n\n"
       << "    skel = " << opts.toolName << "_bpf__open();\n"
       << "    if (!skel) { fprintf(stderr, \"open failed\\n\"); return 1; }\n\n"
       << "    err = " << opts.toolName << "_bpf__load(skel);\n"
       << "    if (err) { fprintf(stderr, \"load failed: %%d\\n\", err); return 1; }\n\n"
       << "    err = " << opts.toolName << "_bpf__attach(skel);\n"
       << "    if (err) { fprintf(stderr, \"attach failed: %%d\\n\", err); return 1; }\n\n"
       << "    // 周期性任务（every 块，文档 5.4.7）\n"
       << "    while (!stop) {\n"
       << "        sleep(1);\n"
       << "        fprintf(stderr, \"[every] tick\\n\");\n"
       << "    }\n\n"
       << "    " << opts.toolName << "_bpf__destroy(skel);\n"
       << "    return 0;\n"
       << "}\n";
    return writeToFile(opts.outputDir, opts.toolName + "_loader.c", os.str());
}

std::string ManifestCodegen::generate(const IRProgram& ir,
                                      const CodegenOptions& opts) {
    std::ostringstream os;
    os << "# Emon DSL tool manifest —— " << opts.toolName << "\n"
       << "# 由编译器自动生成（文档 5.5）\n"
       << "tool:\n"
       << "  name: " << opts.toolName << "\n"
       << "  version: \"0.1\"\n"
       << "maps:\n";
    for (const auto& m : ir.maps) {
        os << "  - name: " << m.name << "\n"
           << "    type: hash\n"
           << "    key_type: " << m.key_type << "\n"
           << "    value_type: " << m.value_type << "\n";
    }
    os << "probes:\n";
    for (const auto& p : ir.probes) {
        os << "  - section: " << p.section << "\n";
    }
    os << "every_tasks:\n";
    for (const auto& e : ir.everyTasks) {
        os << "  - interval: " << e << "\n";
    }
    return writeToFile(opts.outputDir, opts.toolName + ".yaml", os.str());
}

}  // namespace emon
