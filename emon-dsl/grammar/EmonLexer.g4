// =====================================================================
// Emon DSL 词法分析器（EmonLexer.g4）
// 对应文档章节 4.1.1 —— 词法定义
//   - UTF-8 源程序
//   - 关键字、运算符、字面量（整数/浮点/字符串/时间/大小）
//   - 聚合变量 @name
//   - 注释：// 单行 与 /* 多行 */
// =====================================================================
lexer grammar EmonLexer;

// ---- 关键字（按文档 4.1.1 中的 Language keywords）----
TOOL        : 'tool' ;
OPTION      : 'option' ;
OBSERVE     : 'observe' ;
WHERE       : 'where' ;
MEASURE     : 'measure' ;
WHEN        : 'when' ;
EMIT        : 'emit' ;
EVERY       : 'every' ;
LET         : 'let' ;
IF          : 'if' ;
THEN        : 'then' ;
ELSE        : 'else' ;
TRUE        : 'true' ;
FALSE       : 'false' ;
COUNT       : 'count' ;
SUM         : 'sum' ;
AVG         : 'avg' ;
HIST        : 'hist' ;
MIN         : 'min' ;
MAX         : 'max' ;
LATENCY     : 'latency' ;
SIZE        : 'size' ;

// ---- 插装点类型（对应文档 4.1.1 的 hook 分类）----
SYSCALL     : 'syscall' ;
TRACEPOINT  : 'tracepoint' ;
KPROBE      : 'kprobe' ;
KRETPROBE   : 'kretprobe' ;
UPROBE      : 'uprobe' ;
URETPROBE   : 'uretprobe' ;
FENTRY      : 'fentry' ;
FEXIT       : 'fexit' ;
NET         : 'net' ;
FILE        : 'file' ;
PROC        : 'proc' ;

// ---- 内置上下文变量（对应文档 5.1-5.7 示例中使用）----
PID         : 'pid' ;
TID         : 'tid' ;
UID         : 'uid' ;
GID         : 'gid' ;
CPU         : 'cpu' ;
COMM        : 'comm' ;
RETVAL      : 'retval' ;
SYSCALL_NAME : 'syscall' ;
ARG0        : 'arg0' ; ARG1 : 'arg1' ; ARG2 : 'arg2' ;
ARG3        : 'arg3' ; ARG4 : 'arg4' ; ARG5 : 'arg5' ;

// ---- 运算符（按文档 4.1.1）----
LPAREN      : '(' ; RPAREN : ')' ;
LBRACE      : '{' ; RBRACE : '}' ;
LBRACKET    : '[' ; RBRACKET : ']' ;
COMMA       : ',' ; SEMI : ';' ; COLON : ':' ; DOT : '.' ;
ASSIGN      : '=' ;
PLUS        : '+' ; MINUS : '-' ; STAR : '*' ; SLASH : '/' ; PERCENT : '%' ;
EQ          : '==' ; NEQ : '!=' ;
LT          : '<'  ; GT  : '>'  ; LE  : '<=' ; GE  : '>=' ;
AND         : '&&' ; OR  : '||' ; NOT : '!' ;
BITAND      : '&'  ; BITOR : '|' ; BITXOR : '^' ; LSHIFT : '<<' ; RSHIFT : '>>' ;
PIPE        : '|>' ;

// ---- 字面量 ----
INTEGER     : [0-9]+ ;
FLOAT       : [0-9]+ '.' [0-9]+ (('e'|'E') ('+'|'-')? [0-9]+)? ;

STRING      : '"' ( ESCAPE | ~["\\\r\n] )* '"' ;
fragment ESCAPE : '\\' ( '"' | '\\' | 'n' | 'r' | 't' | '0' ) ;

TIME_LIT    : INTEGER ('us' | 'usec' | 'ms' | 'msec' | 's' | 'sec' | 'min' | 'hr') ;
SIZE_LIT    : INTEGER ('KB' | 'MB' | 'GB' | 'TB' | 'B') ;

// ---- 聚合变量（如 @count、@latency_hist）----
AGG_IDENT   : '@' [a-zA-Z_][a-zA-Z0-9_]* ;
IDENT       : [a-zA-Z_][a-zA-Z0-9_]* ;

// ---- 空白与注释 ----
WS          : [ \t\r\n]+ -> skip ;
LINE_COMMENT: '//' ~[\r\n]*      -> skip ;
BLOCK_COMMENT
    : '/*' .*? '*/' -> skip ;
