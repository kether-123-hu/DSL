// =====================================================================
// Emon DSL 语法分析器（EmonParser.g4）
// 对应文档章节 4.1.2 —— 句法定义
// 顶层结构：
//   program := toolDecl optionDecl* observeRule* everyRule*
//   observeRule := observe hook '{' where? measure? when? statement* '}'
// =====================================================================
parser grammar EmonParser;

options { tokenVocab = EmonLexer; }

// ---- 顶层程序 ----
program
    : toolDecl optionDecl* statement* EOF
    ;

// ---- 工具声明（文档 4.1.2 ToolDecl）----
toolDecl
    : TOOL IDENT LBRACE optionDecl* ruleDecl* RBRACE
    ;

optionDecl
    : OPTION IDENT ASSIGN expr SEMI
    ;

// ---- 监控规则（文档 4.1.2 核心文法）----
ruleDecl
    : OBSERVE hook LBRACE ruleBody RBRACE
    ;

hook
    : SYSCALL    LPAREN stringList RPAREN            # hookSyscall
    | TRACEPOINT LPAREN STRING COMMA STRING RPAREN   # hookTracepoint
    | KPROBE     LPAREN STRING RPAREN                # hookKprobe
    | KRETPROBE  LPAREN STRING RPAREN                # hookKretprobe
    | UPROBE     LPAREN STRING (COLON STRING)? RPAREN# hookUprobe
    | FENTRY     LPAREN STRING RPAREN                # hookFentry
    | FEXIT      LPAREN STRING RPAREN                # hookFexit
    | NET        LPAREN STRING? RPAREN               # hookNet
    | FILE       LPAREN STRING? RPAREN               # hookFile
    | PROC       LPAREN STRING? RPAREN               # hookProc
    ;

stringList
    : STRING (COMMA STRING)*
    ;

ruleBody
    : clause*
    ;

clause
    : WHERE  expr SEMI?      # clauseWhere
    | MEASURE metric SEMI?   # clauseMeasure
    | WHEN   expr SEMI?      # clauseWhen
    | aggregation            # clauseAgg
    | emitStmt               # clauseEmit
    | letStmt                # clauseLet
    | ifStmt                 # clauseIf
    ;

metric
    : LATENCY                # metricLatency
    | COUNT                  # metricCount
    | SIZE                   # metricSize
    ;

// ---- 聚合语句（文档 4.1.2 / 5.6：@count、@avg、@hist 等）----
aggregation
    : AGG_IDENT ASSIGN aggFunc LPAREN keyExpr? RPAREN SEMI
    ;

aggFunc
    : COUNT | SUM | AVG | HIST | MIN | MAX
    ;

keyExpr
    : expr (COMMA expr)*
    ;

// ---- 事件输出（emit { ... }）----
emitStmt
    : EMIT LBRACE emitField (COMMA emitField)* RBRACE SEMI
    ;

emitField
    : IDENT COLON expr
    ;

// ---- 周期性任务（every interval { ... }）----
statement
    : ruleDecl
    | optionDecl
    | everyStmt
    | letStmt
    | ifStmt
    | aggregation
    | emitStmt
    | expr SEMI
    ;

everyStmt
    : EVERY expr LBRACE statement* RBRACE
    ;

letStmt
    : LET IDENT ASSIGN expr SEMI
    ;

ifStmt
    : IF expr THEN LBRACE statement* RBRACE (ELSE LBRACE statement* RBRACE)?
    ;

// ---- 表达式（受限布尔/算术语法）----
expr
    : LPAREN expr RPAREN                           # exprParen
    | unary=(NOT|MINUS) expr                       # exprUnary
    | expr op=(STAR|SLASH|PERCENT) expr            # exprMul
    | expr op=(PLUS|MINUS) expr                    # exprAdd
    | expr op=(LSHIFT|RSHIFT) expr                 # exprShift
    | expr op=(LT|GT|LE|GE) expr                   # exprCmp
    | expr op=(EQ|NEQ) expr                        # exprEq
    | expr op=BITAND expr                          # exprBitAnd
    | expr op=BITXOR expr                          # exprBitXor
    | expr op=BITOR  expr                          # exprBitOr
    | expr op=AND expr                             # exprAnd
    | expr op=OR  expr                             # exprOr
    | primary                                      # exprPrimary
    ;

primary
    : INTEGER                   # litInt
    | FLOAT                     # litFloat
    | STRING                    # litStr
    | TRUE                      # litTrue
    | FALSE                     # litFalse
    | TIME_LIT                  # litTime
    | SIZE_LIT                  # litSize
    | AGG_IDENT                 # litAgg
    | IDENT                     # litIdent
    | PID | TID | UID | GID | CPU | COMM | RETVAL
    | SYSCALL_NAME              # ctxIdent
    | ARG0 | ARG1 | ARG2 | ARG3 | ARG4 | ARG5
    ;
