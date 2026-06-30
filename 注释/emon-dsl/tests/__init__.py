# ===================================================================
# __init__.py —— Emon DSL 测试包标识文件
# ===================================================================
#
# 【本文件的作用】
# 这是一个空的 Python 文件，它的存在告诉 Python 解释器：
# "tests/ 目录是一个 Python 包（package）"。
#
# 有了这个文件，测试可以被 unittest 的 discover 机制自动发现：
#   cd emon-dsl && python3 -m unittest discover tests/ -v
#
# 【测试文件清单】
#   tests/test_lexer.py     — 词法分析测试（Token 识别）
#   tests/test_parser.py    — 语法分析测试（AST 构建）
#   tests/test_semantic.py  — 语义分析测试（类型/作用域检查）
#   tests/test_ir.py        — IR 构建测试（AST→IR 转换）
#   tests/test_codegen.py   — 代码生成测试（C/YAML 输出）
# ===================================================================
