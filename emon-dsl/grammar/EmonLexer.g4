// =====================================================================
// Emon DSL Lexer Grammar (ANTLR4)
// Aligned with project plan sections 4.1.1 and language spec v0.01.
// =====================================================================
lexer grammar EmonLexer;

// ---- Program Structure Keywords ----
TOOL        : 'tool' ;
OPTION      : 'option' ;
OBSERVE     : 'observe' ;
BEGIN       : 'begin' ;
END         : 'end' ;

// ---- Clause Keywords ----
WHERE       : 'where' ;
MEASURE     : 'measure' ;
WHEN        : 'when' ;

// ---- Action Statement Keywords ----
EMIT        : 'emit' ;
PRINT       : 'print' ;
EVERY       : 'every' ;
LET         : 'let' ;
IF          : 'if' ;
ELSE        : 'else' ;

// ---- Boolean Literals ----
TRUE        : 'true' ;
FALSE       : 'false' ;

// ---- Aggregation Function Keywords ----
COUNT       : 'count' ;
SUM         : 'sum' ;
AVG         : 'avg' ;
HIST        : 'hist' ;
LHIST       : 'lhist' ;
MIN         : 'min' ;
MAX         : 'max' ;

// ---- Measure Item Keywords ----
LATENCY     : 'latency' ;
RETVAL_KW   : 'retval' ;
SIZE_KW     : 'size' ;
STACK_KW    : 'stack' ;

// ---- Observation Target Keywords (7 types) ----
SYSCALL     : 'syscall' ;
KERNEL      : 'kernel' ;
TRACEPOINT  : 'tracepoint' ;
UPROBE      : 'uprobe' ;
SCHED       : 'sched' ;
FILE_KW     : 'file' ;
NET         : 'net' ;

// ---- Context Variable Keywords ----
PID         : 'pid' ;
TID         : 'tid' ;
UID         : 'uid' ;
GID         : 'gid' ;
CPU         : 'cpu' ;
COMM        : 'comm' ;
NSECS       : 'nsecs' ;
FUNC        : 'func' ;
ARG0        : 'arg0' ; ARG1 : 'arg1' ; ARG2 : 'arg2' ;
ARG3        : 'arg3' ; ARG4 : 'arg4' ; ARG5 : 'arg5' ;

// ---- Operators ----
LPAREN      : '(' ; RPAREN : ')' ;
LBRACE      : '{' ; RBRACE : '}' ;
LBRACKET    : '[' ; RBRACKET : ']' ;
COMMA       : ',' ; SEMI : ';' ; COLON : ':' ; DOT : '.' ;
ASSIGN      : '=' ;
PLUS        : '+' ; MINUS : '-' ; STAR : '*' ; SLASH : '/' ; PERCENT : '%' ;
EQ          : '==' ; NEQ : '!=' ;
LT          : '<'  ; GT  : '>'  ; LE  : '<=' ; GE  : '>=' ;
AND         : '&&' ; OR  : '||' ; NOT : '!' ;

// ---- Literals ----
// TIME_LIT and SIZE_LIT must be defined before INTEGER so that
// inputs like "100us" or "100 us" (with optional whitespace)
// are matched as a single token.  This matches the Lark grammar
// behaviour (TIME_LIT.2: /\d+\s*(ns|us|ms|s)/).
TIME_LIT    : [0-9]+ [ \t]* ( 'ns' | 'us' | 'ms' | 's' ) ;
SIZE_LIT    : [0-9]+ [ \t]* ( 'B' | 'KB' | 'MB' ) ;
INTEGER     : [0-9]+ ;
STRING      : '"' ( ESCAPE | ~["\\\r\n] )* '"' ;
fragment ESCAPE : '\\' ( '"' | '\\' | 'n' | 'r' | 't' | '0' ) ;

// ---- Aggregation Variable Identifier ----
AGG_IDENT   : '@' [a-zA-Z_][a-zA-Z0-9_]* ;

// ---- Regular Identifier ----
IDENT       : [a-zA-Z_][a-zA-Z0-9_]* ;

// ---- Whitespace and Comments ----
WS          : [ \t\r\n]+ -> skip ;
LINE_COMMENT: '//' ~[\r\n]*      -> skip ;
BLOCK_COMMENT
    : '/*' .*? '*/' -> skip ;
