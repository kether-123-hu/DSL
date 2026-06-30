# ===================================================================
# lexer.py —— Emon DSL 词法分析器（编译器第一阶段）
# ===================================================================
#
# 【本文件的作用】
# 词法分析器（Lexer，也叫扫描器 Scanner）是编译器的第一个阶段。
# 它读入原始的源代码文本（一个长字符串），
# 按照 Emon DSL 的词法规则，将文本拆分为一个 Token（词法单元）序列。
#
# 【生活类比】
# 就像把一段英文句子拆成一个个单词：
#   "I love programming" → ["I", "love", "programming"]
# 词法分析器做的事类似：
#   'observe syscall("read")' → [KEYWORD("observe"), KEYWORD("syscall"), 
#                                  DELIMITER("("), STRING('"read"'), DELIMITER(")")]
#
# 【词法分析器支持的特性】
#   - Emon DSL 关键字识别（tool, observe, emit, every 等）
#   - 聚合标识符识别（@count, @avg_latency 等以 @ 开头的变量）
#   - 时间字面量识别（100us, 1ms, 2s 等数字+时间单位）
#   - 大小字面量识别（256KB, 1MB 等数字+大小单位）
#   - 内置上下文变量识别（pid, comm, cpu 等）
#   - 注释处理（// 单行注释 和 /* 块注释 */）
#   - 错误恢复（遇到非法字符不崩溃，记录错误后继续扫描）
# ===================================================================

from typing import Optional  # Optional[X] 表示值可以是 X 类型或 None

# 从 tokens.py 导入 Token 类型定义和相关常量
from emon.tokens import (
    Token, TokenType,
    EMON_KEYWORDS, SINGLE_CHAR_OPERATORS, MULTI_CHAR_OPERATORS,
    DELIMITERS, TIME_UNITS, SIZE_UNITS,
)
# 从 error.py 导入错误类型
from emon.error import (
    LexerError, IllegalCharacterError, UnclosedStringError,
    UnclosedCommentError, InvalidNumberError,
    InvalidTimeLiteralError, InvalidSizeLiteralError,
    ErrorRecorder,
)


# ===================================================================
# Lexer 类 —— 词法分析器主类
# ===================================================================
class Lexer:
    """
    Emon DSL 词法分析器。
    
    使用方法:
        lexer = Lexer(source_code_string)  # 创建词法分析器，传入源代码
        tokens = lexer.tokenize()          # 执行词法分析，返回 Token 列表
    
    工作原理:
        词法分析器维护一个"读取指针" position，从源代码的第 0 个字符开始，
        逐个字符地扫描。每识别出一个完整的 Token，就将其加入结果列表，
        然后继续扫描下一个。当 position 到达源代码末尾时，扫描结束。
    """

    def __init__(self, source: str):
        """
        初始化词法分析器。

        参数:
            source: 要分析的 Emon DSL 源代码字符串
        """
        self.source = source            # 保存源代码的引用
        self.length = len(source)       # 源代码的总字符数
        self.position = 0               # 当前读取位置（指向下一个待读取的字符索引）
        self.line = 1                   # 当前行号（从 1 开始，用于错误定位）
        self.column = 1                 # 当前列号（从 1 开始，用于错误定位）
        self.tokens: list[Token] = []   # 存储分析结果的 Token 列表
        self.errors = ErrorRecorder()   # 错误收集器

    # ================================================================
    # 主入口：执行词法分析
    # ================================================================

    def tokenize(self) -> list[Token]:
        """
        执行完整的词法分析，将源代码转换为 Token 列表。
        
        这是词法分析器的"主函数"。它从头到尾扫描源代码，
        每识别出一个 Token 就加入列表，直到源代码结束。
        最后添加一个 EOF（文件结束）Token 作为标记。

        返回:
            Token 列表（包含 EOF Token）

        副作用:
            错误被收集到 self.errors 中（不会中断分析过程）
        """
        # 重置内部状态（支持同一个 Lexer 对象多次调用 tokenize）
        self.tokens = []
        self.errors.clear()
        self.position = 0
        self.line = 1
        self.column = 1

        # 主循环：只要还有字符没读完，就继续扫描
        while self.position < self.length:
            try:
                self._scan_token()    # 尝试识别下一个 Token
            except LexerError as e:
                self.errors.record(e) # 记录错误
                self._advance()       # 跳过当前有问题的字符，继续扫描

        # 在所有 Token 末尾添加 EOF（End Of File）标记
        # EOF Token 告诉后续的语法分析器"源代码到此结束"
        self.tokens.append(Token(
            type=TokenType.EOF, value='',
            line=self.line, column=self.column, length=0
        ))
        return self.tokens

    # ================================================================
    # 字符读取辅助函数
    # ================================================================

    def _current_char(self) -> Optional[str]:
        """
        获取当前指针位置的字符，但不移动指针。
        如果已经读到源代码末尾，返回 None。
        
        类比：看书时，眼睛看着当前这个字，但还没翻页。
        """
        if self.position >= self.length:
            return None
        return self.source[self.position]

    def _peek(self, offset: int = 0) -> Optional[str]:
        """
        向前偷看指定偏移量处的字符，但不移动指针。
        
        参数:
            offset: 向前看的偏移量。0 表示当前位置，1 表示下一个字符，以此类推。
        
        用途:
            用于判断多字符 Token，比如看到 '/' 后 peek(1) 看是不是 '/'（注释）
            或 '*'（块注释）。

        类比：看书时，偷看后面几个字是什么，但眼睛位置不变。
        """
        pos = self.position + offset
        if pos >= self.length:
            return None
        return self.source[pos]

    def _advance(self) -> Optional[str]:
        """
        读取当前字符并向前移动指针（消费一个字符）。
        
        这是词法分析器最核心的操作之一。每次调用 _advance()：
        1. 获取当前字符
        2. 将 position 指针向前移动 1
        3. 更新行号和列号（遇到换行符时行号+1，列号归1）

        返回:
            被消费的字符，如果已到末尾则返回 None

        类比：看书时，读完当前这个字，翻到下一个字。
        """
        char = self._current_char()
        if char is not None:
            self.position += 1          # 指针前移
            if char == '\n':            # 遇到换行符
                self.line += 1          # 行号加 1
                self.column = 1         # 列号重置为 1
            else:
                self.column += 1        # 列号加 1
        return char

    def _skip_whitespace(self):
        """
        跳过连续的空白字符（空格、制表符、回车符）。
        注意：换行符不在这里处理（在 _scan_token 中单独处理）。
        
        空白字符在 Emon DSL 中只起分隔作用，没有实际语义，
        所以词法分析器直接跳过它们，不产生 Token。
        """
        while True:
            char = self._current_char()
            if char is None or char not in ' \t\r':
                break
            self._advance()

    # ================================================================
    # 核心扫描函数：根据当前字符识别 Token 类型并分发到对应的处理函数
    # ================================================================

    def _scan_token(self):
        """
        识别下一个 Token 的"调度中心"。
        
        它查看当前字符是什么，然后根据字符类型决定调用哪个专门的
        Token 读取函数。这是典型的"查表分发"模式。

        字符 → Token 类型 映射关系：
          字母/_   → 标识符或关键字        (_read_identifier)
          数字     → 整数/时间/大小字面量   (_read_number)
          @        → 聚合标识符             (_read_agg_ident)
          "        → 字符串字面量           (_read_string)
          /        → 注释（如果后跟 / 或 *） (_read_comment)
          运算符   → 运算符 Token           (_read_operator)
          分隔符   → 分隔符 Token           (_read_delimiter)
          空白     → 跳过                   (_skip_whitespace)
          换行     → 跳过                   (_advance)
          其他     → 非法字符错误
        """
        char = self._current_char()
        if char is None:
            return  # 已经到达源代码末尾，停止扫描

        # 记录 Token 的起始位置（用于错误报告和 Token 位置信息）
        start_line = self.line
        start_column = self.column

        # ---- 跳过空白字符（空格、制表符等） ----
        if char in ' \t\r':
            self._skip_whitespace()
            return

        # ---- 跳过换行符 ----
        if char == '\n':
            self._advance()
            return

        # ---- 聚合标识符: @name（如 @count, @avg_latency） ----
        if char == '@':
            token = self._read_agg_ident()
            self.tokens.append(token)
            return

        # ---- 标识符或关键字 ----
        # 以字母或下划线开头的是标识符或关键字
        # _read_identifier 内部会判断是否是关键字
        if char.isalpha() or char == '_':
            token = self._read_identifier()
            self.tokens.append(token)
            return

        # ---- 数字（可能是整数、时间字面量、大小字面量） ----
        if char.isdigit():
            token = self._read_number()
            self.tokens.append(token)
            return

        # ---- 字符串字面量 ----
        if char == '"':
            token = self._read_string()
            self.tokens.append(token)
            return

        # ---- 注释 ----
        # 如果当前字符是 '/' 且下一个字符是 '/' 或 '*'，则是注释
        if char == '/' and self._peek(1) in ('/', '*'):
            token = self._read_comment()
            self.tokens.append(token)
            return

        # ---- 运算符 ----
        if char in SINGLE_CHAR_OPERATORS or char in '|&':
            token = self._read_operator()
            self.tokens.append(token)
            return

        # ---- 分隔符 ----
        if char in DELIMITERS:
            token = self._read_delimiter()
            self.tokens.append(token)
            return

        # ---- 非法字符 ----
        # 如果以上所有条件都不匹配，说明遇到了 Emon DSL 不识别的字符
        self._advance()
        error = IllegalCharacterError(char, start_line, start_column)
        self.errors.record(error)  # 记录非法字符错误
        # 仍然创建一个 ERROR 类型的 Token 放入列表
        self.tokens.append(Token(
            type=TokenType.ERROR, value=char,
            line=start_line, column=start_column, length=1
        ))

    # ================================================================
    # 聚合标识符读取: @name
    # ================================================================

    def _read_agg_ident(self) -> Token:
        """
        读取以 @ 开头的聚合标识符。
        
        聚合标识符用于在 eBPF map 中存储统计数据。
        例如: @count, @avg_latency, @latency_hist
        
        格式: @ 后跟至少一个字母/数字/下划线
        
        示例:
          @count         → AGG_IDENT Token, value="@count"
          @avg_latency   → AGG_IDENT Token, value="@avg_latency"
          @              → ERROR Token（@ 后面没有名字）
        """
        start_line = self.line
        start_column = self.column
        start_pos = self.position

        self._advance()  # 消费 '@' 字符
        value = '@'      # 聚合标识符值以 @ 开头

        # 读取 @ 后面的名称部分（字母、数字、下划线）
        while True:
            char = self._current_char()
            if char is None or not (char.isalnum() or char == '_'):
                break    # 遇到非名称字符（空格、运算符等），名称结束
            value += char
            self._advance()

        # 如果 @ 后面没有跟任何名称字符（只有单独的 @）
        if len(value) == 1:  # just '@' with no name
            return Token(
                type=TokenType.ERROR, value=value,
                line=start_line, column=start_column,
                length=self.position - start_pos
            )

        # 正常的聚合标识符
        return Token(
            type=TokenType.AGG_IDENT, value=value,
            line=start_line, column=start_column,
            length=self.position - start_pos  # Token 占用的字符长度
        )

    # ================================================================
    # 标识符/关键字读取
    # ================================================================

    def _read_identifier(self) -> Token:
        """
        读取一个标识符（可能是用户变量名或 Emon 关键字）。
        
        标识符规则: 以字母或下划线开头，后跟字母、数字或下划线。
        
        读取完成后，检查该标识符是否是 Emon DSL 的保留关键字：
          - 如果是关键字 → KEYWORD 类型 Token
          - 如果是 true/false → BOOL_LIT 类型 Token
          - 否则 → IDENTIFIER 类型 Token（普通用户变量名）
        
        示例:
          tool     → KEYWORD Token, value="tool"
          my_var   → IDENTIFIER Token, value="my_var"
          true     → BOOL_LIT Token, value="true"
        """
        start_line = self.line
        start_column = self.column
        start_pos = self.position
        value = ''

        # 读取完整的标识符字符串（字母+数字+下划线的连续序列）
        while True:
            char = self._current_char()
            if char is None or not (char.isalnum() or char == '_'):
                break    # 标识符结束
            value += char
            self._advance()

        # 判断 Token 类型：关键字？布尔字面量？还是普通标识符？
        if value in EMON_KEYWORDS:
            # 是 Emon 关键字
            if value in ('true', 'false'):
                tt = TokenType.BOOL_LIT  # true/false 是布尔字面量
            else:
                tt = TokenType.KEYWORD   # 其他关键字
        else:
            tt = TokenType.IDENTIFIER    # 不是关键字，就是普通标识符

        return Token(
            type=tt, value=value,
            line=start_line, column=start_column,
            length=self.position - start_pos
        )

    # ================================================================
    # 数字读取（整数 / 时间字面量 / 大小字面量）
    # ================================================================

    def _read_number(self) -> Token:
        """
        读取一个数字 Token。根据后缀的不同，可能被识别为：
          - 整数（没有单位后缀）: 42, 100
          - 时间字面量（时间单位后缀）: 100us, 1ms, 2s
          - 大小字面量（大小单位后缀）: 256KB, 1MB
        
        特殊处理：允许数字和单位之间有空格（如 "100 us" 是合法的时间字面量），
        这使语法更宽松、更友好。
        """
        start_line = self.line
        start_column = self.column
        start_pos = self.position
        value = ''

        # 第一步：读取连续的数字字符
        while True:
            char = self._current_char()
            if char is None or not char.isdigit():
                break
            value += char
            self._advance()

        # 第二步：跳过数字和单位之间可能存在的空白字符
        # 例如 "100 us" 中的空格
        ws_start = self.position  # 记录空白开始位置（用于回滚）
        while True:
            char = self._current_char()
            if char is None or char not in ' \t':
                break
            self._advance()

        # 第三步：尝试读取单位后缀（纯字母序列）
        suffix_start = self.position
        suffix = ''
        while True:
            char = self._current_char()
            if char is None or not char.isalpha():
                break
            suffix += char
            self._advance()

        # 第四步：根据后缀类型决定 Token 类型
        if suffix in TIME_UNITS:
            # 是合法的时间单位（ns, us, ms, s）
            return Token(
                type=TokenType.TIME_LIT, value=value + suffix,
                line=start_line, column=start_column,
                length=self.position - start_pos
            )
        elif suffix in SIZE_UNITS:
            # 是合法的大小单位（B, KB, MB）
            return Token(
                type=TokenType.SIZE_LIT, value=value + suffix,
                line=start_line, column=start_column,
                length=self.position - start_pos
            )
        elif suffix:
            # 后缀不是任何合法单位 → 回滚到空白位置，当作普通整数
            # 例如 "100xx" 中的 xx 不是合法单位，只取 "100" 作为整数
            self.position = ws_start
            return Token(
                type=TokenType.INTEGER, value=value,
                line=start_line, column=start_column,
                length=self.position - start_pos
            )

        # 没有任何后缀 → 普通整数
        return Token(
            type=TokenType.INTEGER, value=value,
            line=start_line, column=start_column,
            length=self.position - start_pos
        )

    # ================================================================
    # 字符串字面量读取
    # ================================================================

    def _read_string(self) -> Token:
        """
        读取双引号包围的字符串字面量。
        
        支持转义字符（以反斜杠 \ 开头）。
        例如: "hello\nworld" — \n 表示换行符
        
        错误处理:
          - 如果字符串跨行（在行尾没有闭合引号）→ UnclosedStringError
          - 如果文件在字符串中间结束 → UnclosedStringError
        """
        start_line = self.line
        start_column = self.column
        start_pos = self.position

        self._advance()  # 消费开头的双引号 "
        result = '"'     # 结果字符串包含开头的引号

        while True:
            char = self._current_char()

            # 情况1: 到达文件末尾，字符串未闭合
            if char is None:
                error = UnclosedStringError(start_line, start_column)
                self.errors.record(error)
                return Token(
                    type=TokenType.ERROR, value=result,
                    line=start_line, column=start_column,
                    length=self.position - start_pos
                )

            # 情况2: 遇到反斜杠 \ → 转义字符
            # 将 \ 和下一个字符都原样保留（如 \" → 字面双引号, \\ → 字面反斜杠）
            if char == '\\':
                result += self._advance()   # 添加反斜杠
                next_c = self._current_char()
                if next_c is not None:
                    result += self._advance() # 添加被转义的字符
                continue

            # 情况3: 遇到闭合双引号 → 字符串结束
            if char == '"':
                result += self._advance()   # 添加闭合引号
                return Token(
                    type=TokenType.STRING, value=result,
                    line=start_line, column=start_column,
                    length=self.position - start_pos
                )

            # 情况4: 遇到换行符（字符串不能跨行）
            if char == '\n':
                error = UnclosedStringError(start_line, start_column)
                self.errors.record(error)
                self._advance()
                return Token(
                    type=TokenType.ERROR, value=result,
                    line=start_line, column=start_column,
                    length=self.position - start_pos
                )

            # 情况5: 普通字符 → 继续读
            result += self._advance()

    # ================================================================
    # 注释读取
    # ================================================================

    def _read_comment(self) -> Token:
        """
        读取注释。
        
        支持两种注释格式：
          1. 单行注释: // 开头，到行尾结束
          2. 块注释:   /* 开头，到 */ 结束（可以跨多行）
        
        注释在词法分析阶段被识别但通常被语法分析器忽略。
        这里我们仍然创建 COMMENT Token（便于调试和格式化工具使用）。
        """
        start_line = self.line
        start_column = self.column
        start_pos = self.position

        self._advance()  # 消费第一个 '/'
        second_char = self._current_char()

        # ---- 单行注释: // ----
        if second_char == '/':
            value = '//'
            self._advance()  # 消费第二个 '/'
            # 一直读到行尾或文件末尾
            while True:
                char = self._current_char()
                if char is None or char == '\n':
                    break
                value += self._advance()
            return Token(
                type=TokenType.COMMENT, value=value,
                line=start_line, column=start_column,
                length=self.position - start_pos
            )

        # ---- 块注释: /* ... */ ----
        if second_char == '*':
            value = '/*'
            self._advance()  # 消费 '*'
            # 一直读到遇到 */ 或文件末尾
            while True:
                char = self._current_char()
                if char is None:
                    # 文件在注释中间结束了 → 未闭合的块注释错误
                    error = UnclosedCommentError(start_line, start_column)
                    self.errors.record(error)
                    return Token(
                        type=TokenType.ERROR, value=value,
                        line=start_line, column=start_column,
                        length=self.position - start_pos
                    )
                # 检查是否是 */ 结束标记
                if char == '*' and self._peek(1) == '/':
                    value += self._advance()  # 消费 '*'
                    value += self._advance()  # 消费 '/'
                    return Token(
                        type=TokenType.COMMENT, value=value,
                        line=start_line, column=start_column,
                        length=self.position - start_pos
                    )
                value += self._advance()  # 消费注释内容中的字符

        # 不应该到达这里（因为 _scan_token 已经检查了后一个字符是 / 或 *）
        return Token(
            type=TokenType.ERROR, value='/',
            line=start_line, column=start_column, length=1
        )

    # ================================================================
    # 运算符读取
    # ================================================================

    def _read_operator(self) -> Token:
        """
        读取运算符 Token。
        
        先尝试匹配双字符运算符（如 ==, !=, <=, >=, &&, ||），
        如果匹配不上，再尝试单字符运算符（如 +, -, *, /, <, >, !）。
        
        例如:
          == → OPERATOR Token, value="=="  （双字符，优先匹配）
          =  → ERROR Token                  （单独的 = 不是 Emon 运算符）
          +  → OPERATOR Token, value="+"
        """
        start_line = self.line
        start_column = self.column
        start_pos = self.position
        char = self._current_char()

        # 先尝试双字符运算符（因为可能是 "==" 而不是两个 "="）
        two_char = char + (self._peek(1) or '')
        if two_char in MULTI_CHAR_OPERATORS:
            self._advance()  # 消费第一个字符
            self._advance()  # 消费第二个字符
            return Token(
                type=TokenType.OPERATOR, value=two_char,
                line=start_line, column=start_column, length=2
            )

        # 不是双字符运算符 → 尝试单字符运算符
        if char in SINGLE_CHAR_OPERATORS:
            self._advance()
            return Token(
                type=TokenType.OPERATOR, value=char,
                line=start_line, column=start_column, length=1
            )

        # 都不匹配 → 错误
        return Token(
            type=TokenType.ERROR, value=char,
            line=start_line, column=start_column, length=1
        )

    # ================================================================
    # 分隔符读取
    # ================================================================

    def _read_delimiter(self) -> Token:
        """
        读取分隔符 Token。
        
        分隔符包括: ( ) { } [ ] , ; : .
        这些符号在语法中起结构作用（包围参数、分隔列表项、结束语句等）。
        """
        start_line = self.line
        start_column = self.column
        start_pos = self.position
        char = self._current_char()

        if char in DELIMITERS:
            self._advance()
            return Token(
                type=TokenType.DELIMITER, value=char,
                line=start_line, column=start_column, length=1
            )

        # 不应该到达这里
        return Token(
            type=TokenType.ERROR, value=char,
            line=start_line, column=start_column, length=1
        )


# ===================================================================
# 便捷函数：一行调用完成词法分析
# ===================================================================
def tokenize(source: str) -> tuple[list[Token], list[LexerError]]:
    """
    对源代码执行词法分析，返回 (Token列表, 错误列表)。

    这是最常用的对外接口。一行代码即可完成词法分析：
      tokens, errors = tokenize(source_code)

    参数:
        source: Emon DSL 源代码字符串

    返回:
        (tokens, errors) 元组
        - tokens: Token 对象列表（包括最后的 EOF Token）
        - errors: LexerError 对象列表（如果没有错误则为空列表）
    """
    lexer = Lexer(source)
    tokens = lexer.tokenize()
    return tokens, lexer.errors.get_errors()
