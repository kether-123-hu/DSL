# Emon DSL —— 面向 eBPF 可观测性的领域特定语言

> **E**BPF **Mon**itoring DSL — 用声明式语法编写 eBPF 监控工具，自动生成内核态 BPF 程序和用户态加载器。

[![Tests](https://img.shields.io/badge/tests-195%20passed-green)](./emon-dsl/tests/)
[![Python](https://img.shields.io/badge/python-3.10+-blue)](https://python.org)

---

## 项目概述

Emon DSL 是一套完整的 eBPF 可观测性工具编译链。开发者用高层声明式语法描述监控需求，编译器自动生成：

| 产物 | 说明 |
|------|------|
| `*.bpf.c` | eBPF C 内核态程序（clang 编译为 `*.bpf.o`） |
| `*_loader.c` | libbpf 用户态加载器（gcc 编译为可执行工具） |
| `*.yaml` | 工具 manifest（可读的工具元数据描述） |

**核心理念**：你只管说"监控什么"，编译器负责"怎么监控"。

---

## 5 分钟上手

```bash
# 1. 安装依赖
cd emon-dsl
pip install -r requirements.txt

# 2. 编译示例
python3 main.py compile examples/syscall_count.emon

# 3. 编译为可执行工具
cp vmlinux.h .  # 从运行内核生成: bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
clang -O2 -g -target bpf -c syscall_counter.bpf.c -o syscall_counter.bpf.o
bpftool gen skeleton syscall_counter.bpf.o > syscall_counter.skel.h
gcc syscall_counter_loader.c -o syscall_counter -lbpf -lelf -lz

# 4. 运行
sudo ./syscall_counter
```

---

## 语言速览

```
tool my_monitor {
    option threshold = 1ms;       // 可配置参数
}

observe syscall("read", "write")  // 监控目标
where pid > 0                     // 前置过滤
measure latency                   // 测量延迟
when latency > threshold          // 后置过滤
{
    @count[pid, comm] = count();            // 计数聚合
    @avg_lat[pid, comm] = avg(latency);     // 平均延迟
    @hist[pid, comm] = hist(latency);       // 延迟分布直方图

    emit {                                   // 实时事件输出
        time = nsecs; pid = pid;
        comm = comm; latency = latency;
    };
}

every 1s {                                   // 每秒汇总
    print(top(@count, 10));
    print(@avg_lat);
    print(@hist);
}
```

**支持的 Hook 类型**：`syscall` | `kernel` (kprobe) | `tracepoint` | `uprobe` | `sched` | `file` | `net`

**聚合函数**：`count` | `sum` | `avg` | `min` | `max` | `hist` | `lhist`

---

## 项目结构

```
Emon_dsl_skeleton/
├── README.md                     # 本文件
├── SPEC.md                       # 项目规格说明书
├── API_REFERENCE.md              # API 参考文档
├── requirements.txt              # Python 依赖
│
└── emon-dsl/                     # 主项目目录
    ├── main.py                   # CLI 入口
    ├── requirements.txt          # Python 依赖
    ├── emon/                     # Python 编译器
    │   ├── lexer.py, parser.py, ast_nodes.py, semantic.py  # 前端
    │   ├── ir.py                 # IR 构建 + compile()
    │   ├── bpfc_gen.py           # eBPF C 代码生成
    │   ├── loader_gen.py         # loader C 代码生成
    │   └── manifest_gen.py       # YAML manifest 生成
    ├── grammar/emon.lark         # 语法定义
    ├── src/runtime/              # C 运行时库
    ├── examples/                 # 8 个示例
    ├── tests/                    # 195 个测试
    └── docs/                     # 设计文档
```

---

## CLI 命令

| 命令 | 说明 |
|------|------|
| `python3 main.py lex <file>` | 词法分析 |
| `python3 main.py parse <file>` | 语法分析 + AST |
| `python3 main.py check <file>` | 语义检查 |
| `python3 main.py ir <file>` | IR 构建 + JSON |
| `python3 main.py compile <file> [-o dir]` | 完整编译 |
| `python3 main.py` | 交互式 REPL |

---

## 环境依赖

**编译 BPF 程序**：
```bash
sudo apt install -y clang libbpf-dev libelf-dev zlib1g-dev llvm
```

**生成 vmlinux.h**（BPF CO-RE 编译必需）：
```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

**注意**：Ubuntu 22.04 自带的 `libbpf-dev` 版本过旧（0.5.0），推荐从源码安装 1.4+：
```bash
git clone --depth 1 --branch v1.4.7 https://github.com/libbpf/libbpf.git
cd libbpf/src && make -j$(nproc) && sudo make install
echo '/usr/lib64' | sudo tee /etc/ld.so.conf.d/libbpf.conf && sudo ldconfig
```

---

## 运行测试

```bash
cd emon-dsl
python3 -m unittest discover tests/ -v    # 195 tests
```

---

## 许可证

生成的 BPF 代码使用 Dual BSD/GPL 许可证。编译器本身为开源项目。
