"""
Emon DSL CLI —— 完整编译器前端 + 后端

Usage:
    python3 main.py lex <source.emon>      词法分析模式
    python3 main.py parse <source.emon>    语法分析 + AST 输出
    python3 main.py check <source.emon>    语义检查
    python3 main.py ir <source.emon>       IR 构建 + JSON 输出
    python3 main.py compile <source.emon>  完整编译（生成 .bpf.c / _loader.c / .yaml）
    python3 main.py compile <source.emon> -o out/  指定输出目录
    python3 main.py                        交互式 REPL（词法分析）
"""

import sys
import os
import argparse

from emon.lexer import Lexer, tokenize
from emon.tokens import TokenType


# =============================================================================
# Display Helpers
# =============================================================================

def _green(text: str) -> str:
    return f"\033[32m{text}\033[0m"


def _yellow(text: str) -> str:
    return f"\033[33m{text}\033[0m"


def _red(text: str) -> str:
    return f"\033[31m{text}\033[0m"


def _bold(text: str) -> str:
    return f"\033[1m{text}\033[0m"


def format_token(token) -> str:
    """Format a token for display."""
    if token.type == TokenType.EOF:
        return "EOF"
    return (
        f"{token.type.name:14} {repr(token.value):24} "
        f"L{token.line}:C{token.column}"
    )


# =============================================================================
# Commands
# =============================================================================

def cmd_lex(source: str, filepath: str = "<stdin>"):
    """Run lexical analysis and display tokens."""
    lexer = Lexer(source)
    tokens = lexer.tokenize()
    errors = lexer.errors.get_errors()

    print(f"{_bold('=== Emon DSL Lexer ===')}  {filepath}")
    print()
    print(f"{_bold('Tokens:')} ({len([t for t in tokens if t.type != TokenType.EOF])})")
    print("-" * 60)
    for token in tokens:
        print(format_token(token))

    if errors:
        print(f"\n{_red(_bold('Errors:'))} ({len(errors)})")
        print("-" * 60)
        for error in errors:
            print(f"  {_red(str(error))}")

    token_counts = {}
    for token in tokens:
        if token.type != TokenType.EOF:
            name = token.type.name
            token_counts[name] = token_counts.get(name, 0) + 1
    if token_counts:
        print(f"\n{_bold('Statistics:')}")
        for name, count in sorted(token_counts.items()):
            print(f"  {name}: {count}")

    return tokens, errors


def cmd_parse(source: str, filepath: str = "<stdin>"):
    """Run parser and display typed AST."""
    from emon.parser import parse

    print(f"{_bold('=== Emon DSL Parser ===')}  {filepath}")
    print()
    ast = parse(source)
    print(_bold("Typed AST:"))
    print("-" * 60)
    print(ast.dump())

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
    print(f"\n{_bold('Node Counts:')} (total: {sum(stats.values())})")
    for name, count in sorted(stats.items()):
        print(f"  {name}: {count}")

    return ast


def cmd_check(source: str, filepath: str = "<stdin>"):
    """Run semantic analysis and display errors."""
    from emon.parser import parse
    from emon.semantic import analyze

    print(f"{_bold('=== Emon DSL Semantic Check ===')}  {filepath}")
    print()

    ast = parse(source)
    errors = analyze(ast)

    if errors:
        print(_red(_bold(f"Found {len(errors)} semantic error(s):")))
        print("-" * 60)
        for e in errors:
            print(f"  {_red(str(e))}")
        return False
    else:
        print(_green(_bold("No semantic errors found.")))
        print(_green("  - All context variables are available"))
        print(_green("  - All aggregation functions have correct arguments"))
        print(_green("  - All identifiers are properly scoped"))
        print(_green("  - Phase restrictions are respected"))
        return True


def cmd_ir(source: str, filepath: str = "<stdin>"):
    """Build IR and display as JSON."""
    from emon.ir import build_ir_from_source

    print(f"{_bold('=== Emon DSL IR Builder ===')}  {filepath}")
    print()

    ir = build_ir_from_source(source)

    print(f"Tool: {ir.tool_name}")
    print(f"Options: {len(ir.options)}")
    print(f"Maps: {len(ir.maps)}")
    print(f"Events: {len(ir.events)}")
    print(f"Probes: {len(ir.probes)}")
    print(f"Every tasks: {len(ir.every_tasks)}")
    print()

    print(_bold("IR (JSON):"))
    print("-" * 60)
    print(ir.to_json())

    return ir


def cmd_compile(source_path: str, output_dir: str = "."):
    """Full compilation pipeline: .emon → .bpf.c / _loader.c / .yaml."""
    from emon.ir import compile_file

    print(f"{_bold('=== Emon DSL Compiler ===')}")
    print(f"Source: {source_path}")
    print(f"Output: {output_dir}")
    print()

    try:
        results = compile_file(source_path, output_dir)
    except ValueError as e:
        print(_red(_bold("Compilation failed:")))
        print(_red(str(e)))
        return None

    print(_green(_bold("Compilation successful!")))
    print()
    print(_bold("Generated files:"))
    for kind, path in results.items():
        size = os.path.getsize(path)
        print(f"  {_green(f'[{kind}]')} {path} ({size} bytes)")

    safe_name = os.path.splitext(os.path.basename(source_path))[0]
    safe_name = safe_name.replace("-", "_").replace(".", "_")
    print()
    print(_bold("Next steps:"))
    # Use the actual generated file basenames from results
    bpf_base = os.path.basename(results["bpf_c"]).replace(".bpf.c", "")
    print(f"  1. Compile BPF:  clang -O2 -g -target bpf -c {bpf_base}.bpf.c -o {bpf_base}.bpf.o")
    print(f"  2. Gen skeleton: bpftool gen skeleton {bpf_base}.bpf.o > {bpf_base}.skel.h")
    print(f"  3. Build loader: gcc {os.path.basename(results['loader_c'])} -o {bpf_base}_loader -lbpf -lelf -lz")
    print(f"  4. Run:          sudo ./{bpf_base}_loader")

    return results


def cmd_repl():
    """Interactive REPL mode."""
    print(_bold("Emon DSL Interactive REPL"))
    print("Enter Emon DSL code, type 'quit' to exit, 'help' for commands.")
    print("-" * 60)

    while True:
        try:
            line = input("\n> ").strip()
            if not line:
                continue

            if line.lower() == 'quit':
                print("Goodbye!")
                break
            elif line.lower() == 'help':
                print("Commands:")
                print("  <emon code>  — Run lexer on the input")
                print("  quit         — Exit REPL")
                print("  help         — Show this message")
                continue
            else:
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


# =============================================================================
# Main
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Emon DSL Compiler — eBPF observability made simple",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 main.py lex examples/syscall_count.emon
  python3 main.py parse examples/syscall_count.emon
  python3 main.py check examples/syscall_count.emon
  python3 main.py ir examples/syscall_count.emon
  python3 main.py compile examples/syscall_count.emon
  python3 main.py compile examples/syscall_count.emon -o build/
  python3 main.py
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Subcommands")

    lex_parser = subparsers.add_parser("lex", help="Run lexical analysis")
    lex_parser.add_argument("file", help="Emon DSL source file (.emon)")

    parse_parser = subparsers.add_parser("parse", help="Parse and display AST")
    parse_parser.add_argument("file", help="Emon DSL source file (.emon)")

    check_parser = subparsers.add_parser("check", help="Run semantic analysis")
    check_parser.add_argument("file", help="Emon DSL source file (.emon)")

    ir_parser = subparsers.add_parser("ir", help="Build and display IR (JSON)")
    ir_parser.add_argument("file", help="Emon DSL source file (.emon)")

    compile_parser = subparsers.add_parser("compile", help="Compile to BPF C + loader + manifest")
    compile_parser.add_argument("file", help="Emon DSL source file (.emon)")
    compile_parser.add_argument("-o", "--output", default=".", help="Output directory (default: .)")

    args = parser.parse_args()

    if not args.command:
        cmd_repl()
        return

    filepath = args.file
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            source = f.read()
    except FileNotFoundError:
        print(_red(f"Error: file '{filepath}' not found"))
        sys.exit(1)

    if args.command == "lex":
        cmd_lex(source, filepath)
    elif args.command == "parse":
        cmd_parse(source, filepath)
    elif args.command == "check":
        ok = cmd_check(source, filepath)
        if not ok:
            sys.exit(1)
    elif args.command == "ir":
        cmd_ir(source, filepath)
    elif args.command == "compile":
        output_dir = getattr(args, 'output', '.')
        result = cmd_compile(filepath, output_dir)
        if result is None:
            sys.exit(1)


if __name__ == '__main__':
    main()
