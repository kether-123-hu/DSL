"""
词法分析器主程序
提供命令行界面和交互式测试
"""

import sys
from lexer import Lexer, tokenize
from tokens import TokenType


def format_token(token) -> str:
    """格式化输出 Token"""
    type_name = token.type.name
    if token.type == TokenType.EOF:
        return f"EOF"
    return f"{type_name:12} {repr(token.value):20} @ L{token.line}:C{token.column}"


def analyze_source(source: str, show_errors: bool = True) -> None:
    """分析源代码并输出结果"""
    lexer = Lexer(source)
    tokens = lexer.tokenize()
    errors = lexer.errors.get_errors()

    print("=" * 60)
    print("词法分析结果")
    print("=" * 60)

    print("\nTokens:")
    print("-" * 60)
    for token in tokens:
        print(format_token(token))

    if show_errors and errors:
        print("\n错误:")
        print("-" * 60)
        for error in errors:
            print(f"  {error}")

    print("\n统计:")
    print("-" * 60)
    token_counts = {}
    for token in tokens:
        if token.type != TokenType.EOF:
            type_name = token.type.name
            token_counts[type_name] = token_counts.get(type_name, 0) + 1

    for type_name, count in sorted(token_counts.items()):
        print(f"  {type_name}: {count}")
    print(f"  总计: {len([t for t in tokens if t.type != TokenType.EOF])} tokens")

    if errors:
        print(f"\n共发现 {len(errors)} 个词法错误")

    return tokens, errors


def main():
    """主函数"""
    if len(sys.argv) > 1:
        # 从文件读取
        filename = sys.argv[1]
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                source = f.read()
            print(f"分析文件: {filename}")
            analyze_source(source)
        except FileNotFoundError:
            print(f"错误: 文件 '{filename}' 未找到")
            sys.exit(1)
        except IOError as e:
            print(f"错误: 无法读取文件 - {e}")
            sys.exit(1)
    else:
        # 交互式测试
        print("词法分析器 - 交互式测试")
        print("输入源代码进行词法分析，输入 'quit' 退出")
        print("-" * 60)

        while True:
            try:
                print("\n> ", end="")
                line = input()
                if line.strip().lower() == 'quit':
                    break
                if line.strip():
                    analyze_source(line)
            except EOFError:
                break
            except KeyboardInterrupt:
                print("\n")
                break


if __name__ == '__main__':
    main()
