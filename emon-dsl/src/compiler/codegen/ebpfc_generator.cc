// =====================================================================
// Emon DSL —— eBPF C 代码生成（对应文档 5.4.2）
// 将 IR 翻译成标准 libbpf / BPF CO-RE 风格的 *.bpf.c 源
// =====================================================================
#include "emon/codegen.h"
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include <sys/types.h>

namespace emon {

std::string writeToFile(const std::string& dir, const std::string& name,
                        const std::string& content) {
    mkdir(dir.c_str(), 0755);  // 忽略 EEXIST
    const std::string path = dir + "/" + name;
    std::ofstream ofs(path);
    if (!ofs) throw std::runtime_error("无法打开输出文件: " + path);
    ofs << content;
    return path;
}

static std::string header(const std::string& tool) {
    std::ostringstream os;
    os << "// =====================================================================\n"
       << "// " << tool << " —— Emon DSL 生成的 eBPF C 程序\n"
       << "// 目标：libbpf / BPF CO-RE 加载（clang -target bpf 编译）\n"
       << "// 源 DSL 语义：见项目文档 5.1–5.7\n"
       << "// =====================================================================\n"
       << "\n"
       << "#include \"vmlinux.h\"\n"
       << "#include <bpf/bpf_helpers.h>\n"
       << "#include <bpf/bpf_tracing.h>\n"
       << "#include <bpf/bpf_core_read.h>\n"
       << "\n"
       << "char LICENSE[] SEC(\"license\") = \"Dual BSD/GPL\";\n"
       << "\n";
    return os.str();
}

// 生成 BPF map 定义（对应文档 5.4.1 的 start_time 隐式 map）
static std::string emitMaps(const IRProgram& ir) {
    std::ostringstream os;
    for (const auto& m : ir.maps) {
        os << "struct {\n"
           << "    __uint(type, "
           << (m.kind == IRMap::EventRing ? "BPF_MAP_TYPE_RINGBUF" : "BPF_MAP_TYPE_HASH")
           << ");\n"
           << "    __uint(max_entries, " << m.max_entries << ");\n"
           << "    __type(key, " << (m.kind == IRMap::EventRing ? "__u32" : m.key_type) << ");\n"
           << "    __type(value, " << m.value_type << ");\n"
           << "} " << m.name << " SEC(\".maps\");\n\n";
    }
    return os.str();
}

// 生成事件结构体定义（文档 5.4.6）
static std::string emitEventStructs(const IRProgram& ir) {
    std::ostringstream os;
    for (const auto& ev : ir.events) {
        os << "struct " << ev.name << " {\n";
        for (const auto& f : ev.fields) {
            os << "    " << f.second << " " << f.name << ";\n";
        }
        os << "};\n\n";
    }
    return os.str();
}

// 生成每个探针（文档 5.4.3 / 5.4.4）
static std::string emitProbes(const IRProgram& ir) {
    std::ostringstream os;
    int probeIdx = 0;
    for (const auto& p : ir.probes) {
        ++probeIdx;
        os << "SEC(\"" << p.section << "\")\n";
        os << "int BPF_KPROBE(" << ir.toolName << "_probe_" << probeIdx;

        // 选择参数（简化：统一采用 ctx 参数
        os << ", const void *ctx) {\n";

        if (p.measuresLatency) {
            // 进入探针：记录时间戳（文档 5.4.1）
            os << "    __u32 pid = bpf_get_current_pid_tgid() >> 32;\n"
               << "    __u64 now = bpf_ktime_get_ns();\n"
               << "    bpf_map_update_elem(&__start_time_1, &pid, &now, BPF_ANY);\n";
        } else {
            // 退出或计数：读取 start_time
            os << "    __u32 pid = bpf_get_current_pid_tgid() >> 32;\n"
               << "    __u64 *start = bpf_map_lookup_elem(&__start_time_1, &pid);\n"
               << "    __u64 delta = start ? (bpf_ktime_get_ns() - *start) : 0;\n"
               << "    if (start) bpf_map_delete_elem(&__start_time_1, &pid);\n";
        }

        // where / when 条件
        for (const auto& c : p.whereConds)
            os << "    if (!(" << c << ")) return 0;\n";
        for (const auto& c : p.whenConds)
            os << "    if (!(" << c << ")) return 0;\n";

        os << "    return 0;\n}\n\n";
    }
    return os.str();
}

std::string EBPFCodegen::generate(const IRProgram& ir, const CodegenOptions& opts) {
    std::ostringstream body;
    body << header(opts.toolName);
    body << emitMaps(ir);
    body << emitEventStructs(ir);
    body << emitProbes(ir);
    return writeToFile(opts.outputDir, opts.toolName + ".bpf.c", body.str());
}

}  // namespace emon
