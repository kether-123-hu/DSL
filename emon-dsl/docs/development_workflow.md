# 开发流程

本目录对应项目开发流程对应《项目开发计划书模板 v0.01(7) 中的工作流：

| 阶段 | 周 | 目录 / 代码模块
--- | --- | ---
需求分析与技术调研 | 1–2 | docs/requirements.md
语言定义与语义设计 | 3 | grammar/ EmonLexer.g4 / EmonParser.g4
编译器前端实现 | 4 | src/compiler/lexer, parser, ast, semantic
上下文推导与目标代码生成 | 5–6 | src/compiler/ir, codegen
运行时支持与常见工具示例 | 7 | src/runtime/{loader,output,map
测试评估与报告完善 | 8 | tests/{unit,integration}, examples/*.emon

每个阶段都有对应的单元测试与集成测试覆盖，测试通过后方可进入下一阶段。
