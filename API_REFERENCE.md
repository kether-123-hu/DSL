# Emon DSL Frontend API Reference

> Version: 0.1.0 | Python 3.10+

---

## 目录

1. [架构概览](#1-架构概览)
2. [快速开始](#2-快速开始)
3. [模块 API](#3-模块-api)
   - [emon.lexer — 词法分析](#31-emonlexer--词法分析)
   - [emon.parser — 语法分析](#32-emonparser--语法分析)
   - [emon.semantic — 语义分析](#33-emonsemantic--语义分析)
   - [emon.ast_nodes — AST 节点类型](#34-emonast_nodes--ast-节点类型)
   - [emon.tokens — Token 类型](#35-emontokens--token-类型)
   - [emon.error — 错误类型](#36-emonerror--错误类型)
4. [CLI 使用](#4-cli-使用)
5. [完整示例](#5-完整示例)

---

## 1. 架构概览

```
.emon 源文件
    │
    ▼
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   lexer.py   │ ──→ │  parser.py   │ ──→ │ semantic.py  │
│   词法分析    │     │   语法分析    │     │   语义分析    │
└──────────────┘     └──────────────┘     └──────────────┘
  Token 列表           类型化 AST          错误列表 (空=合法)
```

三层流水线，每层独立可调用。

---

## 2. 快速开始

```bash
# 进入项目目录
cd emon-dsl

# 安装依赖
pip install -r requirements.txt

# 运行测试
python -m unittest tests.test_lexer tests.test_parser tests.test_semantic
```

```python
from emon.lexer import tokenize
from emon.parser import parse
from emon.semantic import analyze

source = '''
tool my_monitor {
    option threshold = 1ms;
}
observe syscall("read", "write")
measure latency
{
    @avg_lat[pid] = avg(latency);
}
'''

# 词法分析
tokens, errors = tokenize(source)

# 语法分析（返回类型化 AST）
ast = parse(source)
print(ast.tool.name)   # "my_monitor"

# 语义分析
issues = analyze(ast)
if issues:
    for e in issues:
        print(e)
else:
    print("Valid Emon DSL program.")
```

---

## 3. 模块 API

### 3.1 `emon.lexer` — 词法分析

将 Emon DSL 源码转换为 Token 流。

#### 快速函数

```python
def tokenize(source: str) -> tuple[list[Token], list[LexerError]]:
    """
    Returns:
        (tokens, errors) — 即使有错误也会尽可能多地生成 Token。
        Token 列表末尾总是包含一个 EOF token。
    """
```

#### Lexer 类

```python
class Lexer:
    def __init__(self, source: str): ...
    def tokenize(self) -> list[Token]: ...
    # errors 通过 lexer.errors.get_errors() 获取
```

#### 使用示例

```python
from emon.lexer import tokenize

src = 'tool t {} observe syscall("read") { @c[pid] = count(); }'
tokens, errors = tokenize(src)

for t in tokens:
    print(f"{t.type.name:12} {t.value:24} L{t.line}:C{t.column}")

# KEYWORD      'tool'                   L1:C1
# IDENTIFIER   't'                      L1:C6
# DELIMITER    '{'                      L1:C8
# ...
# EOF                                   L1:C53

print(f"Total: {len([t for t in tokens if t.type.name != 'EOF'])} tokens")
print(f"Errors: {len(errors)}")
```

---

### 3.2 `emon.parser` — 语法分析

将 Emon DSL 源码解析为类型化 AST。基于 Lark LALR 解析器。

#### 公共函数

```python
def parse(source: str) -> Program:
    """
    解析 Emon DSL 源码字符串，返回 Program AST 根节点。
    
    Raises:
        lark.exceptions.LarkError: 语法错误时抛出。
    """

def parse_file(filepath: str) -> Program:
    """
    解析 .emon 文件，返回 Program AST 根节点。
    """
```

#### Program AST 结构

```
Program
├── tool: ToolDecl
│   ├── name: str                    # 工具名称
│   └── options: list[(str, Expr)]   # option 名 → 常量值
└── stmts: list[TopStmt]
    ├── ObserveRule
    │   ├── hook: Hook               # 监控目标
    │   ├── wheres: list[WhereClause]
    │   ├── measures: list[MeasureClause]
    │   ├── whens: list[WhenClause]
    │   └── actions: list            # AggregationStmt | EmitStmt | ...
    ├── EveryStmt
    │   ├── interval: Expr
    │   └── actions: list
    ├── BeginStmt
    │   └── actions: list
    └── EndStmt
        └── actions: list
```

#### 使用示例

```python
from emon.parser import parse

src = '''
tool demo { option x = 100; }
observe syscall("read") where pid > 0 measure latency {
    @avg[pid] = avg(latency);
}
'''

ast = parse(src)

# 遍历 AST
print(ast.tool.name)                             # "demo"
print(ast.tool.options)                           # [("x", LitInt(100))]

rule = ast.stmts[0]                               # ObserveRule
print(rule.hook.kind)                             # HookKind.SYSCALL
print(rule.hook.targets)                          # ["read"]
print(rule.wheres[0].cond.op)                     # BinOp.GT
print(rule.measures[0].metrics)                   # [Metric.LATENCY]

agg = rule.actions[0]                              # AggregationStmt
print(agg.target)                                 # "avg"
print(agg.fn)                                     # AggFn.AVG

# 打印完整 AST 树
print(ast.dump())
```

---

### 3.3 `emon.semantic` — 语义分析

对类型化 AST 执行 9 类语义检查，返回错误列表。

#### 公共函数

```python
def analyze(program: Program) -> list[SemanticError]:
    """
    对 Program AST 执行全部语义检查。
    
    Returns:
        SemanticError 列表。空列表表示程序合法。
        每个错误包含 .message (str) 和 .category (str)。
    """
```

#### 检查类别

| category | 说明 | 示例触发条件 |
|----------|------|-------------|
| `unknown` | 未定义的标识符 | `where foobar > 0` |
| `scope` | 上下文变量在错误的 hook 中使用 | `observe kernel` 中使用 `syscall` |
| `measure` | 使用了未声明的 measure 变量 | `where latency > 0` 但没有 `measure latency` |
| `phase` | 变量在不允许的阶段使用 | `where retval == 0`（retval 只在 when/action 可用） |
| `aggregation` | 聚合函数参数错误 | `count(latency)` 或 `sum()` |
| `duplicate` | 重复标识符 | 同一 block 中 `@c` 定义两次 |
| `lifecycle` | `every` 间隔类型错误 | `every 100`（应为时间字面量） |

#### SemanticError 结构

```python
@dataclass
class SemanticError:
    message: str     # 人类可读的错误描述
    category: str    # 错误类别（见上表）
```

#### 使用示例

```python
from emon.parser import parse
from emon.semantic import analyze

# 合法程序 — 无错误
ast = parse('tool t {} observe syscall("r") { @c[pid] = count(); }')
errors = analyze(ast)
print(len(errors))  # 0

# 非法程序 — 检测到问题
src = 'tool t {} observe kernel("f") where syscall == "r" { @c[pid] = count(); }'
ast = parse(src)
errors = analyze(ast)

for e in errors:
    print(f"[{e.category}] {e.message}")
# [scope] 'syscall' is only available in observe SYSCALL contexts, not in observe KERNEL
```

---

### 3.4 `emon.ast_nodes` — AST 节点类型

所有类型化 AST 节点定义。由 `parser.parse()` 返回。

#### 表达式节点

| 类 | 字段 | 说明 |
|----|------|------|
| `LitInt(value: int)` | — | 整数字面量 |
| `LitStr(value: str)` | — | 字符串字面量（不含引号） |
| `LitBool(value: bool)` | — | 布尔字面量 |
| `LitTime(value: str)` | — | 时间字面量，如 `"100us"` |
| `LitSize(value: str)` | — | 大小字面量，如 `"256KB"` |
| `VarRef(name: str)` | — | 变量引用 |
| `AggRef(name: str)` | — | 聚合变量引用（不含 @） |
| `BinOpExpr(op, lhs, rhs)` | `BinOp` 枚举 | 二元运算 |
| `UnaryOpExpr(op, operand)` | `UnaryOp` 枚举 | 一元运算 |
| `FuncCall(name, args)` | `args: list[Expr]` | 函数调用 |

#### 语句节点

| 类 | 关键字段 |
|----|---------|
| `ObserveRule` | `hook, wheres, measures, whens, actions` |
| `AggregationStmt` | `target, keys, fn, arg` |
| `EmitStmt` | `fields: list[EmitField]` |
| `EmitField` | `name, value` |
| `PrintStmt` | `expr` |
| `LetStmt` | `name, value` |
| `IfStmt` | `cond, then_actions, else_actions` |
| `EveryStmt` | `interval, actions` |
| `BeginStmt` | `actions` |
| `EndStmt` | `actions` |

#### 枚举

| 枚举 | 值 |
|------|----|
| `HookKind` | `SYSCALL, KERNEL, TRACEPOINT, UPROBE, SCHED, FILE, NET` |
| `Metric` | `LATENCY, COUNT, SIZE, RETVAL, STACK` |
| `AggFn` | `COUNT, SUM, AVG, MIN, MAX, HIST, LHIST` |
| `BinOp` | `ADD, SUB, MUL, DIV, MOD, LT, GT, LE, GE, EQ, NE, AND, OR` |
| `UnaryOp` | `NOT, NEG` |

---

### 3.5 `emon.tokens` — Token 类型

#### TokenType 枚举

| 值 | 说明 |
|----|------|
| `KEYWORD` | Emon DSL 关键字（`tool`, `observe`, `emit`, ...） |
| `IDENTIFIER` | 用户自定义标识符 |
| `AGG_IDENT` | 聚合变量标识符（`@count`, `@avg_latency`） |
| `INTEGER` | 整数 |
| `STRING` | 字符串 |
| `TIME_LIT` | 时间字面量（`100us`, `1ms`） |
| `SIZE_LIT` | 大小字面量（`256KB`） |
| `BOOL_LIT` | 布尔字面量（`true`, `false`） |
| `OPERATOR` | 运算符（`+`, `==`, `&&`, ...） |
| `DELIMITER` | 分隔符（`{`, `;`, `,`, ...） |
| `COMMENT` | 注释（`//...` 或 `/*...*/`） |
| `EOF` | 文件结束标记 |

#### Token 数据类

```python
@dataclass
class Token:
    type: TokenType
    value: str       # 原始文本
    line: int        # 行号 (1-based)
    column: int      # 列号 (1-based)
    length: int      # 字符长度

    def is_keyword(self) -> bool: ...
    def is_identifier(self) -> bool: ...
    def is_literal(self) -> bool: ...
    def is_operator(self, op: str = None) -> bool: ...
    def is_context_var(self) -> bool: ...
```

---

### 3.6 `emon.error` — 错误类型

#### LexerError 子类

| 类 | 触发条件 |
|----|---------|
| `IllegalCharacterError` | 源码中出现非法字符 |
| `UnclosedStringError` | 字符串未闭合 |
| `UnclosedCommentError` | 块注释 `/*...` 未闭合 |
| `InvalidNumberError` | 数字格式错误 |
| `InvalidTimeLiteralError` | 时间字面量单位无效 |
| `InvalidSizeLiteralError` | 大小字面量单位无效 |

---

## 4. CLI 使用

```bash
# 词法分析模式（默认）
python main.py examples/syscall_latency.emon

# 语法分析模式（输出类型化 AST）
python main.py --parse examples/syscall_latency.emon

# 交互式 REPL（词法分析）
python main.py
```

---

## 5. 完整示例

```python
from emon.lexer import tokenize
from emon.parser import parse, parse_file
from emon.semantic import analyze
from emon.error import LexerError

# ===== 1. 词法分析 =====
source = 'tool demo { option threshold = 1ms; }'
tokens, lex_errors = tokenize(source)

print(f"Tokens: {len(tokens)}, Errors: {len(lex_errors)}")
for t in tokens[:5]:
    print(f"  {t.type.name:12} {t.value}")

# ===== 2. 语法分析 =====
program = '''
tool network_monitor {
    option port = 8080;
}
observe syscall("read", "write")
where pid > 0
measure latency, retval
when latency > 1ms
{
    @count[pid, comm] = count();
    @avg_lat[pid, comm] = avg(latency);

    emit {
        time    = nsecs;
        pid     = pid;
        latency = latency;
    };

    let slow = latency > 1000000;
    if (slow) {
        @slow_count[pid] = count();
    }
}

every 1s {
    print("--- report ---");
    print(@count);
}
'''

ast = parse(program)

# 访问 AST 字段
print(f"\nTool: {ast.tool.name}")
print(f"Options: {ast.tool.options}")

for i, stmt in enumerate(ast.stmts):
    match stmt:
        case ObserveRule() as r:
            print(f"[{i}] observe {r.hook.kind.name} {r.hook.targets}")
            print(f"    where: {len(r.wheres)}, measure: {len(r.measures)}, when: {len(r.whens)}")
            for a in r.actions:
                match a:
                    case AggregationStmt() as agg:
                        print(f"    agg @{agg.target}[...] = {agg.fn.name}()")
                    case EmitStmt() as em:
                        print(f"    emit {{ {' ,'.join(f.name for f in em.fields)} }}")
                    case LetStmt() as l:
                        print(f"    let {l.name}")
                    case IfStmt() as ifs:
                        print(f"    if (...) then={len(ifs.then_actions)} else={len(ifs.else_actions or [])}")
        case EveryStmt() as ev:
            print(f"[{i}] every {ev.interval}")

# ===== 3. 语义分析 =====
errors = analyze(ast)
if errors:
    print(f"\nSemantic errors: {len(errors)}")
    for e in errors:
        print(f"  [{e.category}] {e.message}")
else:
    print("\nSemantic analysis: PASSED")

# ===== 4. 打印完整 AST =====
# print(ast.dump())
```

输出：

```
Tokens: 8, Errors: 0
  KEYWORD      tool
  IDENTIFIER   demo
  DELIMITER    {
  KEYWORD      option
  IDENTIFIER   threshold

Tool: network_monitor
Options: [('port', LitInt(8080))]
[0] observe SYSCALL ['read', 'write']
    where: 1, measure: 1, when: 1
    agg @count[...] = COUNT()
    agg @avg_lat[...] = AVG()
    emit { time , pid , latency }
    let slow
    if (...) then=1 else=0
[1] every LitTime(1s)

Semantic analysis: PASSED
```
