# 词法分析器 (Lexer) 规格文档

## 1. 项目概述

- **项目名称**: Lexer - 词法分析器
- **项目类型**: 编译原理教学/实用工具
- **核心功能**: 对源代码进行词法分析，识别并提取各类词法单元（Token），生成包含类型、值、位置信息的输出
- **目标用户**: 编译器学习者、教学工具开发者

## 2. 词法规则定义

### 2.1 Token 类型

| Token类型 | 说明 | 示例 |
|-----------|------|------|
| KEYWORD | 关键字 | if, else, while, for, return, int, float, void, etc. |
| IDENTIFIER | 标识符 | variable, function_name, count, etc. |
| INTEGER | 整数常量 | 42, -17, 0xFF, 0b1010 |
| FLOAT | 浮点常量 | 3.14, -2.5, 1e10, 1.5e-3 |
| STRING | 字符串常量 | "hello", 'world' |
| OPERATOR | 运算符 | +, -, *, /, =, ==, !=, <, >, <=, >=, &&, \|\|, !, etc. |
| DELIMITER | 分隔符 | (, ), {, }, [, ], ,, ;, :, . |
| COMMENT | 注释 | // single line, /* multi-line */ |
| WHITESPACE | 空白字符 | space, tab, newline (通常被忽略) |
| NEWLINE | 换行符 | \n |
| ERROR | 错误Token | 非法字符 |

### 2.2 关键字列表

```
if, else, while, for, do, switch, case, default, break, continue,
return, goto, sizeof, typeof,
int, long, short, char, float, double, void, signed, unsigned,
const, static, extern, register, volatile,
struct, union, enum, typedef,
TRUE, FALSE, NULL
```

### 2.3 运算符列表

```
+, -, *, /, %, =, ==, !=, <, >, <=, >=,
++, --, +=, -=, *=, /=, %=,
&&, ||, !, &, |, ^, ~, <<, >>,
<<=, >>=, &=, |=, ^=
```

### 2.4 分隔符列表

```
(, ), {, }, [, ], ,, ;, :, ., ?, ...
```

### 2.5 标识符规则

- 首字符: 字母(A-Z, a-z) 或下划线(_)
- 后续字符: 字母、数字(0-9) 或下划线(_)
- 区分大小写
- 不能与关键字相同

### 2.6 常量规则

- **整数**: 十进制(0-9), 十六进制(0x/0X开头), 二进制(0b/0B开头)
- **浮点数**: 包含小数点或指数部分
- **字符串**: 双引号或单引号包围，支持转义字符(\n, \t, \r, \\, \", \')

### 2.7 注释规则

- **单行注释**: // 开头，到行尾结束
- **多行注释**: /* */ 包裹，可跨行

## 3. 功能需求

### 3.1 核心功能

- [x] 逐字符扫描源代码
- [x] 识别各类Token
- [x] 记录Token位置信息（行号、列号）
- [x] 处理注释（忽略）
- [x] 处理空白字符（忽略，但保留换行符位置）
- [x] 错误恢复机制（遇到错误继续扫描）

### 3.2 输入输出

- **输入**: 源代码字符串
- **输出**: Token列表，每个Token包含:
  - `type`: Token类型
  - `value`: Token值
  - `line`: 行号（从1开始）
  - `column`: 列号（从1开始）
  - `length`: Token长度

### 3.3 错误处理

- [x] 识别非法字符
- [x] 识别未闭合的字符串
- [x] 识别未闭合的注释
- [x] 生成错误信息，包含错误位置

## 4. 技术实现

### 4.1 项目结构

```
/home/liuyanze/dsl/
├── SPEC.md
├── lexer.py           # 词法分析器核心实现
├── token.py           # Token类型定义
├── error.py           # 错误处理
├── test_lexer.py      # 测试用例
└── main.py            # 主程序入口
```

### 4.2 关键类/函数

- `Token` - Token数据结构
- `TokenType` - Token类型枚举
- `LexerError` - 词法错误异常
- `Lexer` - 词法分析器主类
  - `__init__(source: str)` - 初始化
  - `tokenize() -> List[Token]` - 执行词法分析
  - `_advance()` - 前进到下一个字符
  - `_peek()` - 查看当前字符
  - `_skip_whitespace()` - 跳过空白字符
  - `_read_identifier()` - 读取标识符
  - `_read_number()` - 读取数字
  - `_read_string()` - 读取字符串
  - `_read_operator()` - 读取运算符
  - `_read_comment()` - 读取注释

## 5. 测试计划

### 5.1 正常情况测试

- 关键字识别
- 标识符识别
- 整数常量识别
- 浮点常量识别
- 字符串常量识别
- 运算符识别
- 分隔符识别
- 注释处理

### 5.2 边界情况测试

- 空输入
- 仅有空白字符
- 仅有注释
- 非法字符
- 未闭合字符串
- 未闭合注释
- 混合代码测试

## 6. 验收标准

- [x] 成功识别所有关键字
- [x] 成功识别标识符
- [x] 成功识别整数和浮点数
- [x] 成功识别字符串
- [x] 成功处理注释
- [x] 正确报告词法错误
- [x] 位置信息准确
- [x] 测试覆盖核心功能
