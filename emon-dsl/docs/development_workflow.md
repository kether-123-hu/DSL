# 开发流程

本目录对应项目开发流程对应《项目开发计划书模板 v0.01(7) 中的工作流：

| 阶段 | 周 | 目录 / 代码模块
--- | --- | ---
需求分析与技术调研 | 1–2 | docs/requirements.md
语言定义与语义设计 | 3 | grammar/emon.lark (Lark) / EmonLexer.g4 / EmonParser.g4 (ANTLR)
编译器前端实现 | 4 | emon/lexer.py, parser.py, ast_nodes.py, semantic.py
上下文推导与目标代码生成 | 5–6 | emon/ir.py, bpfc_gen.py, loader_gen.py, manifest_gen.py
运行时支持与常见工具示例 | 7 | src/runtime/{loader,output,map}, examples/*.emon
测试评估与报告完善 | 8 | tests/{test_lexer,test_parser,test_semantic,test_ir,test_codegen}.py

> **架构变更说明**：原计划第 4–6 周的 C++ 编译器前端/后端已全部改为 Python 实现。
> 编译器全流程（词法→语法→语义→IR→代码生成）统一使用 Python，
> 仅 C 运行时库 (`src/runtime/`) 保留 C 实现以链接 libbpf。

每个阶段都有对应的单元测试与集成测试覆盖，测试通过后方可进入下一阶段。
