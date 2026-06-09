"""
Emon DSL CLI

Usage:
    python3 main.py <source.emon>           Lexer mode (default)
    python3 main.py --parse <source.emon>   Parser mode (AST)
    python3 main.py                         Interactive REPL (lexer only)
"""

import sys
from emon.lexer import Lexer, tokenize
from emon.tokens import TokenType


def format_token(token) -> str:
    """Format a token for display."""
    if token.type == TokenType.EOF:
        return "EOF"
    return (
        f"{token.type.name:14} {repr(token.value):24} "
        f"L{token.line}:C{token.column}"
    )


def analyze_source(source: str, show_errors: bool = True):
    """Analyze Emon DSL source and print results."""
    lexer = Lexer(source)
    tokens = lexer.tokenize()
    errors = lexer.errors.get_errors()

    print("=" * 60)
    print("Emon DSL Lexer Results")
    print("=" * 60)
    print("\nTokens:")
    print("-" * 60)
    for token in tokens:
        print(format_token(token))

    if show_errors and errors:
        print("\nErrors:")
        print("-" * 60)
        for error in errors:
            print(f"  {error}")

    print("\nStatistics:")
    print("-" * 60)
    token_counts = {}
    for token in tokens:
        if token.type != TokenType.EOF:
            name = token.type.name
            token_counts[name] = token_counts.get(name, 0) + 1
    for name, count in sorted(token_counts.items()):
        print(f"  {name}: {count}")
    non_eof = [t for t in tokens if t.type != TokenType.EOF]
    print(f"  Total: {len(non_eof)} tokens")
    if errors:
        print(f"\n{len(errors)} lexer error(s) found.")

    return tokens, errors


def parse_source(source: str):
    """Parse Emon DSL source and print the typed AST."""
    from emon.parser import parse

    print("=" * 60)
    print("Emon DSL Parser Results")
    print("=" * 60)

    ast = parse(source)
    print("\nTyped AST:")
    print("-" * 60)
    print(ast.dump())

    # Summary statistics
    def count_nodes(node) -> dict:
        counts = {}
        tname = type(node).__name__
        counts[tname] = counts.get(tname, 0) + 1
        if hasattr(node, '__dataclass_fields__'):
            for field_name in node.__dataclass_fields__:
                val = getattr(node, field_name)
                if isinstance(val, list):
                    for item in val:
                        sub = count_nodes(item)
                        for k, v in sub.items():
                            counts[k] = counts.get(k, 0) + v
                elif hasattr(val, '__dataclass_fields__'):
                    sub = count_nodes(val)
                    for k, v in sub.items():
                        counts[k] = counts.get(k, 0) + v
        return counts

    stats = count_nodes(ast)
    print(f"\n  Nodes: {sum(stats.values())}")
    for name, count in sorted(stats.items()):
        print(f"    {name}: {count}")

    return ast


def main():
    if len(sys.argv) > 1:
        parse_mode = sys.argv[1] == '--parse'
        filename = sys.argv[2] if parse_mode else sys.argv[1]
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                source = f.read()
            if parse_mode:
                print(f"Parsing: {filename}")
                parse_source(source)
            else:
                print(f"Analyzing: {filename}")
                analyze_source(source)
        except FileNotFoundError:
            print(f"Error: file '{filename}' not found")
            sys.exit(1)
        except ImportError as e:
            print(f"Error: missing dependency - {e}")
            print("Install with: pip install lark-parser")
            sys.exit(1)
    else:
        print("Emon DSL Lexer - Interactive REPL")
        print("Enter Emon DSL code, type 'quit' to exit.")
        print("-" * 60)
        while True:
            try:
                line = input("\n> ")
                if line.strip().lower() == 'quit':
                    break
                if line.strip():
                    analyze_source(line)
            except (EOFError, KeyboardInterrupt):
                print()
                break


if __name__ == '__main__':
    main()
