# ===================================================================
# main.py —— Emon DSL 命令行入口（CLI）
# ===================================================================
#
# 【本文件的作用】
# 这是 Emon DSL 编译器的命令行入口程序。
# 用户通过命令行运行不同的子命令来完成编译流程的各个步骤。
#
# 【支持的命令】
#   python3 main.py lex <file.emon>     词法分析模式
#     将源代码拆分为 Token 列表并输出，显示每个 Token 的类型和位置
#
#   python3 main.py parse <file.emon>   语法分析 + AST 输出
#     解析 Token 序列为抽象语法树，以缩进格式输出
#
#   python3 main.py check <file.emon>   语义检查
#     检查 AST 的逻辑正确性（变量作用域、类型匹配等）
#
#   python3 main.py ir <file.emon>      IR 构建 + JSON 输出
#     将 AST 转换为中间表示并输出为 JSON 格式
#
#   python3 main.py compile <file.emon> 完整编译
#     执行完整编译流程：.emon → .bpf.c + _loader.c + .yaml
#     可选 -o 参数指定输出目录
#
#   python3 main.py                     交互式 REPL（词法分析）
#     进入交互模式，输入 Emon 代码片段查看 Token 分析结果
#
# 【各命令对应编译器的不同阶段】
#   lex    → 第一阶段：词法分析
#   parse  → 第二阶段：语法分析
#   check  → 第三阶段：语义分析
#   ir     → 第四阶段：IR 构建
#   compile→ 完整流程（第一→第五阶段）
# ===================================================================

import sys
import os
import argparse  # Python 标准库：命令行参数解析

from emon.lexer import Lexer, tokenize
from emon.tokens import TokenType


# ===================================================================
# 终端颜色辅助函数
# ===================================================================
# 使用 ANSI 转义码在终端输出彩色文字，提升可读性。

def _green(text: str) -> str:
    """绿色文字（表示成功、正常信息）"""
    return f"\033[32m{text}\033[0m"

def _yellow(text: str) -> str:
    """黄色文字（表示警告）"""
    return f"\033[33m{text}\033[0m"

def _red(text: str) -> str:
    """红色文字（表示错误）"""
    return f"\033[31m{text}\033[0m"

def _bold(text: str) -> str:
    """粗体文字（表示标题、重点）"""
    return f"\033[1m{text}\033[0m"


def format_token(token) -> str:
    """
    格式化一个 Token 用于终端显示。
    输出格式: Token类型(14字符宽) Token值(24字符宽) 行号:列号
    例如: KEYWORD        'observe'                L1:C1
    """
    if token.type == TokenType.EOF:
        return "EOF"
    return (
        f"{token.type.name:14} {repr(token.value):24} "
        f"L{token.line}:C{token.column}"
    )


# ===================================================================
# 子命令实现
# ===================================================================

def cmd_lex(source: str, filepath: str = "<stdin>"):
    """
    词法分析子命令。
    
    将源代码拆分为 Token 列表，显示每个 Token 的详细信息。
    同时统计各类 Token 的数量。
    """
    lexer = Lexer(source)
    tokens = lexer.tokenize()
    errors = lexer.errors.get_errors()

    print(f"{_bold('=== Emon DSL 词法分析器 ===')}  {filepath}")
    print()
    # 统计 Token 数量（不包括 EOF）
    print(f"{_bold('Token 列表:')} ({len([t for t in tokens if t.type != TokenType.EOF])} 个)")
    print("-" * 60)
    for token in tokens:
        print(format_token(token))

    # 显示错误
    if errors:
        print(f"\n{_red(_bold('错误:'))} ({len(errors)} 个)")
        print("-" * 60)
        for error in errors:
            print(f"  {_red(str(error))}")

    # Token 类型统计
    token_counts = {}
    for token in tokens:
        if token.type != TokenType.EOF:
            name = token.type.name
            token_counts[name] = token_counts.get(name, 0) + 1
    if token_counts:
        print(f"\n{_bold('统计:')}")
        for name, count in sorted(token_counts.items()):
            print(f"  {name}: {count}")

    return tokens, errors


def cmd_parse(source: str, filepath: str = "<stdin>"):
    """
    语法分析子命令。
    
    解析 Token 序列为 AST，以缩进格式输出树结构。
    同时统计各类 AST 节点的数量。
    """
    from emon.parser import parse

    print(f"{_bold('=== Emon DSL 语法分析器 ===')}  {filepath}")
    print()
    ast = parse(source)
    print(_bold("抽象语法树 (AST):"))
    print("-" * 60)
    print(ast.dump())  # 以缩进格式输出整个 AST

    # 递归统计各类型 AST 节点的数量
    def count_nodes(node) -> dict:
        counts = {}
        tname = type(node).__name__
        counts[tname] = counts.get(tname, 0) + 1
        if hasattr(node, '__dataclass_fields__'):
            for field_name in node.__dataclass_fields__:
                val = getattr(node, field_name)
                if isinstance(val, list):
                    for item in val:
                        if hasattr(item, '__dataclass_fields__'):
                            sub = count_nodes(item)
                            for k, v in sub.items():
                                counts[k] = counts.get(k, 0) + v
                elif hasattr(val, '__dataclass_fields__'):
                    sub = count_nodes(val)
                    for k, v in sub.items():
                        counts[k] = counts.get(k, 0) + v
        return counts

    stats = count_nodes(ast)
    print(f"\n{_bold('节点统计:')} (总计: {sum(stats.values())})")
    for name, count in sorted(stats.items()):
        print(f"  {name}: {count}")

    return ast


def cmd_check(source: str, filepath: str = "<stdin>"):
    """
    语义检查子命令。
    
    对 AST 执行所有语义检查，报告任何逻辑错误。
    如果没有错误，显示"通过"信息。
    """
    from emon.parser import parse
    from emon.semantic import analyze

    print(f"{_bold('=== Emon DSL 语义检查 ===')}  {filepath}")
    print()

    ast = parse(source)
    errors = analyze(ast)

    if errors:
        # 有错误：红色显示
        print(_red(_bold(f"发现 {len(errors)} 个语义错误:")))
        print("-" * 60)
        for e in errors:
            print(f"  {_red(str(e))}")
        return False
    else:
        # 无错误：绿色显示通过信息
        print(_green(_bold("未发现语义错误。")))
        print(_green("  - 所有上下文变量均可用"))
        print(_green("  - 所有聚合函数参数正确"))
        print(_green("  - 所有标识符作用域正确"))
        print(_green("  - 阶段限制已遵守"))
        return True


def cmd_ir(source: str, filepath: str = "<stdin>"):
    """
    IR 构建子命令。
    
    将 AST 转换为中间表示，并以 JSON 格式输出。
    显示程序结构概况（map 数量、探针数量等）。
    """
    from emon.ir import build_ir_from_source

    print(f"{_bold('=== Emon DSL IR 构建器 ===')}  {filepath}")
    print()

    ir = build_ir_from_source(source)

    # 概况信息
    print(f"工具名: {ir.tool_name}")
    print(f"选项数: {len(ir.options)}")
    print(f"Map 数: {len(ir.maps)}")
    print(f"事件数: {len(ir.events)}")
    print(f"探针数: {len(ir.probes)}")
    print(f"Every 任务数: {len(ir.every_tasks)}")
    print()

    # 输出 JSON 格式的 IR
    print(_bold("IR (JSON 格式):"))
    print("-" * 60)
    print(ir.to_json())

    return ir


def cmd_compile(source_path: str, output_dir: str = "."):
    """
    完整编译子命令。
    
    执行完整的编译流水线: .emon → .bpf.c + _loader.c + .yaml。
    这是用户最常用的命令。
    
    输出:
        xxx.bpf.c    → 内核态 eBPF C 程序
        xxx_loader.c → 用户态 libbpf 加载器
        xxx.yaml     → 工具清单
    """
    from emon.ir import compile_file

    print(f"{_bold('=== Emon DSL 编译器 ===')}")
    print(f"源文件: {source_path}")
    print(f"输出目录: {output_dir}")
    print()

    try:
        results = compile_file(source_path, output_dir)
    except ValueError as e:
        # 语义错误导致编译失败
        print(_red(_bold("编译失败:")))
        print(_red(str(e)))
        return None

    # 编译成功：显示生成的文件
    print(_green(_bold("编译成功!")))
    print()
    print(_bold("生成的文件:"))
    for kind, path in results.items():
        size = os.path.getsize(path)
        print(f"  {_green(f'[{kind}]')} {path} ({size} 字节)")

    # 显示后续编译步骤
    safe_name = os.path.splitext(os.path.basename(source_path))[0]
    safe_name = safe_name.replace("-", "_").replace(".", "_")
    print()
    print(_bold("后续步骤:"))
    bpf_base = os.path.basename(results["bpf_c"]).replace(".bpf.c", "")
    print(f"  1. 编译 BPF:  clang -O2 -g -target bpf -c {bpf_base}.bpf.c -o {bpf_base}.bpf.o")
    print(f"  2. 生成骨架: bpftool gen skeleton {bpf_base}.bpf.o > {bpf_base}.skel.h")
    print(f"  3. 构建加载器: gcc {os.path.basename(results['loader_c'])} -o {bpf_base}_loader -lbpf -lelf -lz")
    print(f"  4. 运行:       sudo ./{bpf_base}_loader")

    return results


def cmd_repl():
    """
    交互式 REPL（Read-Eval-Print-Loop）模式。
    
    用户可以逐行输入 Emon DSL 代码片段，查看词法分析结果。
    输入 'quit' 退出，输入 'help' 查看帮助。
    
    这是一个学习和调试工具，方便快速测试语法。
    """
    print(_bold("Emon DSL 交互式 REPL"))
    print("输入 Emon DSL 代码，输入 'quit' 退出，输入 'help' 查看帮助。")
    print("-" * 60)

    while True:
        try:
            line = input("\n> ").strip()
            if not line:
                continue

            if line.lower() == 'quit':
                print("再见!")
                break
            elif line.lower() == 'help':
                print("命令:")
                print("  <emon 代码>  — 对输入执行词法分析")
                print("  quit         — 退出 REPL")
                print("  help         — 显示此帮助")
                continue
            else:
                # 对用户输入的代码执行词法分析
                lexer = Lexer(line)
                tokens = lexer.tokenize()
                errors = lexer.errors.get_errors()
                for token in tokens:
                    print(f"  {format_token(token)}")
                if errors:
                    for error in errors:
                        print(f"  {_red(str(error))}")
        except (EOFError, KeyboardInterrupt):
            print()
            break


# ===================================================================
# 主函数：命令行参数解析和分发
# ===================================================================

def main():
    """
    命令行入口函数。
    
    使用 argparse 解析命令行参数，根据子命令调用对应的处理函数。
    """
    parser = argparse.ArgumentParser(
        description="Emon DSL —— eBPF 可观测性领域特定语言编译器",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python3 main.py lex examples/syscall_count.emon      词法分析
  python3 main.py parse examples/syscall_count.emon    语法分析
  python3 main.py check examples/syscall_count.emon    语义检查
  python3 main.py ir examples/syscall_count.emon       IR 构建
  python3 main.py compile examples/syscall_count.emon  完整编译
  python3 main.py compile examples/syscall_count.emon -o output/  指定输出目录
  python3 main.py                                      交互式 REPL
        """
    )

    # 定义子命令
    subparsers = parser.add_subparsers(dest="command", help="可用子命令")

    # lex 子命令：词法分析
    lex_parser = subparsers.add_parser("lex", help="词法分析：将源代码拆分为 Token")
    lex_parser.add_argument("file", help=".emon 源文件路径")

    # parse 子命令：语法分析
    parse_parser = subparsers.add_parser("parse", help="语法分析：构建抽象语法树")
    parse_parser.add_argument("file", help=".emon 源文件路径")

    # check 子命令：语义检查
    check_parser = subparsers.add_parser("check", help="语义检查：验证程序逻辑")
    check_parser.add_argument("file", help=".emon 源文件路径")

    # ir 子命令：IR 构建
    ir_parser = subparsers.add_parser("ir", help="IR 构建：生成中间表示")
    ir_parser.add_argument("file", help=".emon 源文件路径")

    # compile 子命令：完整编译
    compile_parser = subparsers.add_parser("compile", help="完整编译：生成 .bpf.c + _loader.c + .yaml")
    compile_parser.add_argument("file", help=".emon 源文件路径")
    compile_parser.add_argument("-o", "--output", default=".", help="输出目录（默认当前目录）")

    # 解析命令行参数
    args = parser.parse_args()

    # 如果没有指定子命令，进入 REPL 模式
    if args.command is None:
        cmd_repl()
        return

    # 读取源文件
    try:
        with open(args.file, "r", encoding="utf-8") as f:
            source = f.read()
    except FileNotFoundError:
        print(_red(f"错误: 文件不存在 '{args.file}'"))
        sys.exit(1)
    except Exception as e:
        print(_red(f"错误: 无法读取文件 '{args.file}': {e}"))
        sys.exit(1)

    # 根据子命令分发
    if args.command == "lex":
        cmd_lex(source, args.file)
    elif args.command == "parse":
        cmd_parse(source, args.file)
    elif args.command == "check":
        ok = cmd_check(source, args.file)
        sys.exit(0 if ok else 1)
    elif args.command == "ir":
        cmd_ir(source, args.file)
    elif args.command == "compile":
        output_dir = args.output if hasattr(args, 'output') else "."
        result = cmd_compile(args.file, output_dir)
        if result is None:
            sys.exit(1)


if __name__ == "__main__":
    main()
