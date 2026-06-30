# ===================================================================
# parser.py —— Emon DSL 语法分析器（编译器第二阶段）
# ===================================================================
#
# 【本文件的作用】
# 语法分析器（Parser）将词法分析器输出的 Token 序列，
# 按照语法规则构建为抽象语法树（AST）。
#
# 【技术方案】
# 本解析器使用 Lark 解析框架。Lark 是一个 Python 的通用解析库，
# 它根据 .lark 语法文件自动生成解析器。我们只需要编写 Transformer
# （转换器），将 Lark 的通用解析树转换为我们的类型化 AST。
#
# 【工作流程】
#   1. _load_grammar() 读取 grammar/emon.lark 语法文件
#   2. Lark 根据语法文件生成 LALR 解析器
#   3. parse(source) 调用解析器得到 Lark 解析树
#   4. EmonTransformer.transform() 将解析树递归转换为 AST 节点
#   5. 返回 Program 根节点
#
# 【为什么使用 Lark？】
# - LALR(1) 解析算法高效且确定性强
# - .lark 语法文件可读性好，接近 EBNF 标准表示法
# - Transformer 模式使 AST 构建代码清晰
# ===================================================================

from pathlib import Path              # 用于构建语法文件路径
from typing import Optional

from lark import Lark, Token, Transformer  # Lark 解析框架的核心类

# 导入所有 AST 节点类型（从 ast_nodes.py）
from emon.ast_nodes import (
    Program, ToolDecl,
    ObserveRule, EveryStmt, BeginStmt, EndStmt,
    Hook, HookKind,
    WhereClause, WhenClause, MeasureClause,
    Metric, AggFn,
    AggregationStmt, EmitStmt, EmitField,
    PrintStmt, LetStmt, IfStmt,
    Expr, LitInt, LitStr, LitBool, LitTime, LitSize,
    VarRef, AggRef, BinOpExpr, UnaryOpExpr, FuncCall,
    BinOp, UnaryOp,
)


# ===================================================================
# 第一部分：加载 Lark 语法文件
# ===================================================================

def _load_grammar() -> Lark:
    """
    加载 grammar/emon.lark 语法文件并创建 Lark 解析器。
    
    这个函数只会在首次调用时执行一次（通过 _get_parser 的缓存机制），
    之后复用已创建的解析器实例。
    
    返回:
        Lark 解析器对象，配置为:
          - start="program": 从 program 规则开始解析
          - parser="lalr":   使用 LALR(1) 解析算法
          - keep_all_tokens=True: 保留所有 Token（用于运算符的表达式构建）
    """
    # 构建语法文件的绝对路径
    # __file__ 是当前文件路径，.parent.parent 回到 emon-dsl/ 目录
    grammar_path = Path(__file__).parent.parent / "grammar" / "emon.lark"
    
    # 读取语法文件内容
    with open(grammar_path, "r", encoding="utf-8") as f:
        grammar_text = f.read()
    
    # 创建 Lark 解析器
    return Lark(
        grammar_text,                    # 语法定义文本
        start="program",                 # 起始规则名（对应 emon.lark 中的 program 规则）
        parser="lalr",                   # 使用 LALR(1) 解析器（高效、确定性）
        propagate_positions=True,        # 在 Token 上保留位置信息
        maybe_placeholders=False,        # 不使用 maybe_placeholders（减少歧义）
        keep_all_tokens=True,            # 保留所有 Token（即使是分隔符），用于构建表达式树
    )


# ===================================================================
# 第二部分：映射表（字符串 → AST 枚举值）
# ===================================================================
# 这些映射表将解析器中的字符串符号映射为 AST 中的枚举值。

# 二元运算符字符串 → BinOp 枚举映射
_BINOP_MAP = {
    "+": BinOp.ADD, "-": BinOp.SUB,
    "*": BinOp.MUL, "/": BinOp.DIV, "%": BinOp.MOD,
    "<": BinOp.LT, ">": BinOp.GT,
    "<=": BinOp.LE, ">=": BinOp.GE,
    "==": BinOp.EQ, "!=": BinOp.NE,
    "&&": BinOp.AND, "||": BinOp.OR,
}

# 一元运算符字符串 → UnaryOp 枚举映射
_UNARYOP_MAP = {"!": UnaryOp.NOT, "-": UnaryOp.NEG}

# 测量指标字符串 → Metric 枚举映射
_METRIC_MAP = {
    "latency": Metric.LATENCY, "count": Metric.COUNT,
    "size": Metric.SIZE, "retval": Metric.RETVAL, "stack": Metric.STACK,
}

# 聚合函数字符串 → AggFn 枚举映射
_AGGFN_MAP = {
    "count": AggFn.COUNT, "sum": AggFn.SUM, "avg": AggFn.AVG,
    "min": AggFn.MIN, "max": AggFn.MAX, "hist": AggFn.HIST, "lhist": AggFn.LHIST,
}

# Lark Token 类型名 → 实际字符映射
# 因为 Lark 将运算符和分隔符的内部名称做了转换（如 LPAR 代表 '('），
# 我们需要这个映射来回溯原始字符。
_TOKEN_TYPE_MAP = {
    "LPAR": "(", "RPAR": ")",
    "LBRACE": "{", "RBRACE": "}",
    "LSQB": "[", "RSQB": "]",
    "EQUAL": "=", "SEMICOLON": ";",
    "COMMA": ",", "COLON": ":",
    "PLUS": "+", "MINUS": "-",
    "STAR": "*", "SLASH": "/", "PERCENT": "%",
    "MORETHAN": ">", "LESSTHAN": "<",
    "LESSEQUAL": "<=", "MOREEQUAL": ">=",
    "EQEQUAL": "==", "NOTEQUAL": "!=",
    "AND": "&&", "OR": "||", "NOT": "!",
}


# ===================================================================
# 第三部分：辅助函数
# ===================================================================

def _token_val(token: Token) -> str:
    """
    获取 Lark Token 的实际字符值。
    
    Lark 将某些特殊符号重命名了（如 '=' 变成 'EQUAL'），
    这个函数将 Token 类型名映射回原始字符。
    
    参数:
        token: Lark 的 Token 对象
    
    返回:
        Token 代表的原始字符（如 '(', '&&', '=='）
    """
    if token.type in _TOKEN_TYPE_MAP:
        return _TOKEN_TYPE_MAP[token.type]
    return token.value


def _build_binary(items: list) -> Expr:
    """
    将扁平的项目列表构建为左结合的二元运算表达式树。
    
    例如输入列表: [VarRef("a"), Token("+"), VarRef("b"), Token("*"), VarRef("c")]
    会构建出: BinOpExpr(ADD, VarRef("a"), BinOpExpr(MUL, VarRef("b"), VarRef("c")))
    
    这正确处理了运算符优先级（由语法规则保证）和左结合性。
    
    参数:
        items: 交替包含表达式和运算符 Token 的列表
    
    返回:
        构建好的表达式树根节点
    """
    if len(items) == 1:
        # 只有一个元素，直接返回（没有运算符）
        return items[0]
    
    # 从左到右构建左结合的表达式树
    result = items[0]          # 第一个操作数
    i = 1                      # 从第二个元素开始
    while i < len(items):
        op_str = _token_val(items[i])     # 运算符
        rhs = items[i + 1]                # 右操作数
        result = BinOpExpr(op=_BINOP_MAP[op_str], lhs=result, rhs=rhs)
        i += 2  # 跳过运算符和右操作数，处理下一对
    
    return result


def _filter_tokens(items: list) -> list:
    """
    从列表中过滤掉 Lark Token 对象，只保留 AST 节点。
    
    这在处理 Lark 解析树时很有用，因为 Lark 的 items 列表中会混合
    AST 节点和原始的 Token 对象（如分隔符、关键字等）。
    
    参数:
        items: 混合了 AST 节点和 Token 的列表
    
    返回:
        仅包含 AST 节点的列表
    """
    return [item for item in items if not isinstance(item, Token)]


# ===================================================================
# 第四部分：EmonTransformer —— 将 Lark 解析树转换为 AST
# ===================================================================

class EmonTransformer(Transformer):
    """
    Lark Transformer 的子类，将 Lark 通用解析树转换为我们的类型化 AST。
    
    Lark 的 Transformer 工作原理:
      语法文件中的每条规则对应这里的一个同名方法。
      当 Lark 解析完某条规则后，会调用对应的 Transformer 方法，
      传入该规则匹配到的所有子元素，该方法的返回值会成为父规则的元素。
      
    方法命名规则:
      规则名        → 方法名
      program       → def program(self, items)
      tool_decl     → def tool_decl(self, items)
      observe_stmt  → def observe_stmt(self, items)
      等等...
    """

    # ----------------------------------------------------------------
    # 程序顶层结构
    # ----------------------------------------------------------------

    def program(self, items):
        """
        构建 Program 根节点。
        
        语法规则: program: tool_decl top_stmt*
        items[0] = ToolDecl（工具声明）
        items[1:] = 顶层语句列表（ObserveRule/EveryStmt/BeginStmt/EndStmt）
        """
        return Program(tool=items[0], stmts=list(items[1:]))

    def tool_decl(self, items):
        """
        构建 ToolDecl 节点。
        
        语法规则: tool_decl: "tool" IDENT "{" option_decl* "}"
        items[0] = Token("tool")
        items[1] = Token(IDENT) — 工具名称
        items[2] = Token("{")
        items[3:-1] = option_decl 列表
        items[-1] = Token("}")
        """
        name = items[1].value  # 提取工具名称字符串
        # 过滤掉 Token 对象，只保留 option 的 (name, value) 元组
        options = [item for item in items[3:-1] if not isinstance(item, Token)]
        return ToolDecl(name=name, options=options)

    def option_decl(self, items):
        """
        解析选项声明。
        
        语法规则: option_decl: "option" IDENT "=" const_expr ";"
        返回 (选项名, 选项值表达式) 的元组。
        """
        return (items[1].value, items[3])

    # ----------------------------------------------------------------
    # 常量表达式（options 中的值）
    # ----------------------------------------------------------------

    def const_int(self, items):
        """整型常量: 42 → LitInt(42)"""
        return LitInt(int(items[0].value))

    def const_string(self, items):
        """字符串常量: "hello" → LitStr("hello")"""
        raw = items[0].value
        # 去掉包围的双引号
        return LitStr(raw[1:-1] if raw.startswith('"') else raw)

    def const_bool(self, items):
        """布尔常量: true → LitBool(True), false → LitBool(False)"""
        return LitBool(items[0].value == "true")

    def const_time(self, items):
        """时间常量: 100us → LitTime("100us")"""
        return LitTime(items[0].value)

    def const_size(self, items):
        """大小常量: 256KB → LitSize("256KB")"""
        return LitSize(items[0].value)

    # ----------------------------------------------------------------
    # 顶层语句
    # ----------------------------------------------------------------

    def top_stmt(self, items):
        """顶层语句：直接返回子元素（observe/every/begin/end 之一）"""
        return items[0]

    def observe_stmt(self, items):
        """
        构建 ObserveRule 节点。
        
        语法规则: observe_stmt: "observe" observe_target [where_clause] [measure_clause] [when_clause] block
        items[0] = Token("observe")
        items[1] = Hook（观测目标）
        items[2:] = 可选的 where/measure/when 子句和 block
        
        block 中的 actions 是一个列表，其他子句是单独的对象。
        """
        hook = items[1]
        wheres, measures, whens, actions = [], [], [], []
        for item in items[2:]:
            if isinstance(item, WhereClause):
                wheres.append(item)
            elif isinstance(item, MeasureClause):
                measures.append(item)
            elif isinstance(item, WhenClause):
                whens.append(item)
            elif isinstance(item, list):
                actions = item  # block 中的动作列表
        return ObserveRule(hook=hook, wheres=wheres, measures=measures, whens=whens, actions=actions)

    # ----------------------------------------------------------------
    # 观测目标
    # ----------------------------------------------------------------

    def observe_target(self, items):
        """观测目标：直接返回子元素（七种目标类型之一）"""
        return items[0]

    def syscall_target(self, items):
        """系统调用目标: syscall("read", "write") → Hook(SYSCALL, ["read", "write"])"""
        return Hook(kind=HookKind.SYSCALL, targets=items[2])

    def kernel_target(self, items):
        """内核函数目标: kernel("tcp_v4_connect") → Hook(KERNEL, ["tcp_v4_connect"])"""
        return Hook(kind=HookKind.KERNEL, targets=items[2])

    def tracepoint_target(self, items):
        """跟踪点目标: tracepoint("sched:sched_switch") → Hook(TRACEPOINT, ["sched:sched_switch"])"""
        return Hook(kind=HookKind.TRACEPOINT, targets=items[2])

    def sched_target(self, items):
        """调度器目标"""
        return Hook(kind=HookKind.SCHED, targets=items[2])

    def file_target(self, items):
        """文件系统目标"""
        return Hook(kind=HookKind.FILE, targets=items[2])

    def net_target(self, items):
        """网络目标"""
        return Hook(kind=HookKind.NET, targets=items[2])

    def uprobe_target(self, items):
        """
        用户态探针目标。
        
        语法: uprobe("/bin/bash", "readline", "malloc")
        items[2] = 二进制文件路径字符串
        items[4] = 函数名列表
        """
        raw = items[2].value
        # 去掉双引号
        binary = raw[1:-1] if raw.startswith('"') else raw
        return Hook(kind=HookKind.UPROBE, targets=items[4], binary_path=binary)

    def string_list(self, items):
        """
        解析字符串列表。
        
        语法: STRING ("," STRING)*
        返回去掉引号的字符串列表。
        """
        result = []
        for item in items:
            if isinstance(item, Token):
                val = item.value
                if val == ",":  # 跳过逗号分隔符
                    continue
                # 去掉包围的双引号
                if val.startswith('"') and val.endswith('"'):
                    val = val[1:-1]
                result.append(val)
        return result

    # ----------------------------------------------------------------
    # 子句
    # ----------------------------------------------------------------

    def where_clause(self, items):
        """Where 子句: where expr → WhereClause(expr)"""
        return WhereClause(cond=items[1])

    def when_clause(self, items):
        """When 子句: when expr → WhenClause(expr)"""
        return WhenClause(cond=items[1])

    def measure_clause(self, items):
        """Measure 子句: measure item1, item2 → MeasureClause([Metric, ...])"""
        metrics = [item for item in items[1:] if isinstance(item, Metric)]
        return MeasureClause(metrics=metrics)

    def measure_item(self, items):
        """单个测量项: "latency" → Metric.LATENCY"""
        return _METRIC_MAP[items[0].value]

    # ----------------------------------------------------------------
    # 代码块和动作语句
    # ----------------------------------------------------------------

    def block(self, items):
        """
        代码块: "{" action_stmt* "}"
        返回动作语句列表（去掉花括号 Token）
        """
        return list(items[1:-1])

    def action_stmt(self, items):
        """动作语句：直接返回子元素"""
        return items[0]

    # -- 聚合语句 --
    def aggregation_stmt(self, items):
        """
        聚合语句。
        
        语法: AGG_IDENT "[" key_list "]" "=" agg_func "(" [expr] ")" ";"
        
        示例: @count[comm, pid, syscall] = count();
              @avg_latency[comm, pid] = avg(latency);
        
        items[0] = AGG_IDENT Token（如 @count）
        items[2] = key 列表
        items[5] = 聚合函数（AggFn 枚举值）
        items[7:] = 可选的聚合参数
        """
        name = items[0].value.lstrip("@")  # 去掉 @ 前缀
        keys = items[2]
        fn = items[5]
        arg = None
        # 查找可选的聚合参数
        for item in items[7:]:
            if isinstance(item, Expr):
                arg = item
                break
        return AggregationStmt(target=name, keys=keys, fn=fn, arg=arg)

    def key_list(self, items):
        """Key 列表: expr, expr, ... → [Expr, ...]"""
        return [item for item in items if isinstance(item, Expr)]

    def agg_func(self, items):
        """聚合函数: "count" → AggFn.COUNT, "avg" → AggFn.AVG 等"""
        return _AGGFN_MAP[items[0].value]

    # -- Emit 语句 --
    def emit_stmt(self, items):
        """
        Emit 语句。
        
        语法: "emit" "{" field_assign ";" ... "}" ";"
        """
        fields = [item for item in items if isinstance(item, EmitField)]
        return EmitStmt(fields=fields)

    def field_assign(self, items):
        """
        Emit 字段赋值: IDENT "=" expr
        例如: time = nsecs; → EmitField(name="time", value=VarRef("nsecs"))
        """
        return EmitField(name=items[0].value, value=items[2])

    # -- Print 语句 --
    def print_stmt(self, items):
        """Print 语句: "print" "(" expr ")" ";" """
        for item in items:
            if isinstance(item, Expr):
                return PrintStmt(expr=item)
        # 如果没有表达式，创建空字符串打印
        return PrintStmt(expr=LitStr(""))

    # -- Let 语句 --
    def let_stmt(self, items):
        """Let 语句: "let" IDENT "=" expr ";" """
        return LetStmt(name=items[1].value, value=items[3])

    # -- If 语句 --
    def if_stmt(self, items):
        """
        If 语句: "if" "(" expr ")" block ["else" block]
        
        items[0] = Token("if")
        items[1] = Token("(")
        items[2] = 条件表达式
        items[3] = Token(")")
        items[4] = then 分支代码块（action 列表）
        items[5:] = 可选的 else 部分
        """
        cond = items[2]
        then_block = items[4]
        else_block = None
        # 检查是否有 else 分支
        if len(items) > 5:
            rest = _filter_tokens(items[5:])
            if rest:
                else_block = rest[0]
        return IfStmt(cond=cond, then_actions=then_block, else_actions=else_block)

    # ----------------------------------------------------------------
    # 生命周期语句
    # ----------------------------------------------------------------

    def every_stmt(self, items):
        """Every 语句: "every" expr block → EveryStmt(interval, actions)"""
        return EveryStmt(interval=items[1], actions=items[2])

    def begin_stmt(self, items):
        """Begin 语句: "begin" block → BeginStmt(actions)"""
        return BeginStmt(actions=items[1])

    def end_stmt(self, items):
        """End 语句: "end" block → EndStmt(actions)"""
        return EndStmt(actions=items[1])

    # ----------------------------------------------------------------
    # 表达式（按优先级从高到低）
    # ----------------------------------------------------------------

    def var_ref(self, items):
        """变量引用: IDENT → VarRef(name)"""
        return VarRef(name=items[0].value)

    def int_lit(self, items):
        """整数字面量: 42 → LitInt(42)"""
        return LitInt(int(items[0].value))

    def string_lit(self, items):
        """字符串字面量: "hello" → LitStr("hello")"""
        raw = items[0].value
        return LitStr(raw[1:-1] if raw.startswith('"') else raw)

    def bool_lit(self, items):
        """布尔字面量: true → LitBool(True)"""
        return LitBool(items[0].value == "true")

    def time_lit(self, items):
        """时间字面量: 100us → LitTime("100us")"""
        return LitTime(items[0].value)

    def size_lit(self, items):
        """大小字面量: 256KB → LitSize("256KB")"""
        return LitSize(items[0].value)

    def agg_ref(self, items):
        """聚合引用: @count → AggRef("count")"""
        return AggRef(name=items[0].value.lstrip("@"))

    def func_call(self, items):
        """
        函数调用: IDENT "(" [arg_list] ")"
        例如: top(@count, 10), count()
        """
        name = items[0].value
        args = []
        # 查找参数列表
        for item in items:
            if isinstance(item, list):
                args = item
                break
        return FuncCall(name=name, args=args)

    def arg_list(self, items):
        """参数列表: expr, expr, ... → [Expr, ...]"""
        return [item for item in items if isinstance(item, Expr)]

    def unary_op(self, items):
        """一元运算: "!" expr 或 "-" expr → UnaryOpExpr"""
        return UnaryOpExpr(op=_UNARYOP_MAP[_token_val(items[0])], operand=items[1])

    # ----------------------------------------------------------------
    # 表达式优先级层（按 Lark 语法从低到高排列）
    # 每一层使用 _build_binary 构建左结合的表达式树
    # ----------------------------------------------------------------

    def or_expr(self, items):
        """逻辑或: a || b → BinOpExpr(OR, a, b)"""
        return _build_binary(items)

    def and_expr(self, items):
        """逻辑与: a && b → BinOpExpr(AND, a, b)"""
        return _build_binary(items)

    def eq_expr(self, items):
        """相等比较: a == b, a != b"""
        return _build_binary(items)

    def rel_expr(self, items):
        """关系比较: a < b, a <= b, a > b, a >= b"""
        return _build_binary(items)

    def add_expr(self, items):
        """加减: a + b, a - b"""
        return _build_binary(items)

    def mul_expr(self, items):
        """乘除取模: a * b, a / b, a % b"""
        return _build_binary(items)


# ===================================================================
# 第五部分：解析器缓存和公共接口
# ===================================================================

# 全局解析器实例（懒加载，首次使用时创建）
_parser: Optional[Lark] = None

# 全局 Transformer 实例（无状态，可安全复用）
_transformer = EmonTransformer()


def _get_parser() -> Lark:
    """
    获取 Lark 解析器实例（带缓存）。
    
    首次调用时加载语法文件并创建解析器，之后直接返回缓存的实例。
    这样可以避免每次解析都重新加载语法文件。
    """
    global _parser
    if _parser is None:
        _parser = _load_grammar()
    return _parser


def parse(source: str) -> Program:
    """
    解析 Emon DSL 源代码，返回 Program AST。
    
    这是解析器的主要对外接口。一行代码即可完成语法分析：
      ast = parse(source_code)
    
    参数:
        source: Emon DSL 源代码字符串
    
    返回:
        Program 根节点（AST 的根）
    
    工作流程:
        1. 获取 Lark 解析器
        2. Lark 解析源代码 → 通用解析树
        3. EmonTransformer 转换解析树 → 类型化 AST
        4. 返回 Program 根节点
    """
    p = _get_parser()              # 步骤1: 获取解析器
    tree = p.parse(source)         # 步骤2: 解析源代码
    return _transformer.transform(tree)  # 步骤3 & 4: 转换并返回


def parse_file(filepath: str) -> Program:
    """
    从文件解析 Emon DSL 源代码。
    
    参数:
        filepath: .emon 文件的路径
    
    返回:
        Program 根节点
    """
    with open(filepath, "r", encoding="utf-8") as f:
        source = f.read()
    return parse(source)
