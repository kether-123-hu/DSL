# Emon DSL —— 测试
# 全部测试已迁移至 Python（unittest）。
# Python 测试运行方式:
#   cd emon-dsl && python3 -m unittest discover tests/ -v
#
# 测试覆盖:
#   tests/test_lexer.py     — 词法分析 (Token 识别)
#   tests/test_parser.py    — 语法分析 (AST 构建)
#   tests/test_semantic.py  — 语义分析 (类型/作用域检查)
#   tests/test_ir.py        — IR 构建 (AST→IR 转换)
#   tests/test_codegen.py   — 代码生成 (C/YAML 输出)
message(STATUS "[tests] Python 测试就绪 (152 tests)")
message(STATUS "[tests] 运行: python3 -m unittest discover tests/ -v")
