// =====================================================================
// Emon DSL Parser Grammar (ANTLR4)
// Aligned with project plan section 4.1.2 and language spec v0.01.
//
// Top-level structure:
//   program := toolDecl { topStmt }
//   topStmt := observeStmt | everyStmt | beginStmt | endStmt
// =====================================================================
parser grammar EmonParser;

options { tokenVocab = EmonLexer; }

// ---- Top-level Program ----
program
    : toolDecl topStmt* EOF
    ;

// ---- Tool Declaration ----
toolDecl
    : TOOL IDENT LBRACE optionDecl* RBRACE
    ;

optionDecl
    : OPTION varIdent ASSIGN constExpr SEMI
    ;

constExpr
    : INTEGER
    | STRING
    | TRUE
    | FALSE
    | TIME_LIT
    | SIZE_LIT
    ;

// ---- Top-level Statements ----
topStmt
    : observeStmt
    | everyStmt
    | beginStmt
    | endStmt
    ;

// ---- Observe Statement ----
observeStmt
    : OBSERVE observeTarget whereClause? measureClause? whenClause? block
    ;

// ObserveTarget: 7 observation target types.
observeTarget
    : SYSCALL     LPAREN stringList RPAREN     # targetSyscall
    | KERNEL      LPAREN stringList RPAREN     # targetKernel
    | TRACEPOINT  LPAREN stringList RPAREN     # targetTracepoint
    | UPROBE      LPAREN STRING COMMA stringList RPAREN  # targetUprobe
    | SCHED       LPAREN stringList RPAREN     # targetSched
    | FILE_KW     LPAREN stringList RPAREN     # targetFile
    | NET         LPAREN stringList RPAREN     # targetNet
    ;

stringList
    : STRING (COMMA STRING)*
    ;

whereClause
    : WHERE expr
    ;

measureClause
    : MEASURE measureItem (COMMA measureItem)*
    ;

measureItem
    : LATENCY
    | COUNT
    | SIZE_KW
    | RETVAL_KW
    | STACK_KW
    ;

whenClause
    : WHEN expr
    ;

// ---- Code Block and Action Statements ----
block
    : LBRACE actionStmt* RBRACE
    ;

actionStmt
    : aggregationStmt
    | emitStmt
    | printStmt
    | letStmt
    | ifStmt
    ;

// -- Aggregation Statement --
aggregationStmt
    : AGG_IDENT LBRACKET keyList RBRACKET ASSIGN aggFunc LPAREN expr? RPAREN SEMI
    ;

keyList
    : expr (COMMA expr)*
    ;

aggFunc
    : COUNT | SUM | AVG | HIST | LHIST | MIN | MAX
    ;

// -- Emit Statement --
emitStmt
    : EMIT LBRACE (fieldAssign SEMI)+ RBRACE SEMI
    ;

fieldAssign
    : varIdent ASSIGN expr
    ;

// -- Print Statement --
printStmt
    : PRINT LPAREN expr RPAREN SEMI
    ;

// -- Let Statement --
letStmt
    : LET varIdent ASSIGN expr SEMI
    ;

// -- If Statement --
ifStmt
    : IF LPAREN expr RPAREN block (ELSE block)?
    ;

// ---- Lifecycle Statements ----
everyStmt
    : EVERY expr block
    ;

beginStmt
    : BEGIN block
    ;

endStmt
    : END block
    ;

// ---- Expression System (in order of increasing precedence) ----
expr
    : LPAREN expr RPAREN                           # exprParen
    | <assoc=right> unary=(NOT|MINUS) expr         # exprUnary
    | expr op=(STAR|SLASH|PERCENT) expr            # exprMul
    | expr op=(PLUS|MINUS) expr                    # exprAdd
    | expr op=(LT|GT|LE|GE) expr                   # exprCmp
    | expr op=(EQ|NEQ) expr                        # exprEq
    | expr op=AND expr                             # exprAnd
    | expr op=OR  expr                             # exprOr
    | primary                                      # exprPrimary
    ;

// ---- Primary Expressions ----
primary
    : funcCall                  # litFuncCall
    | INTEGER                   # litInt
    | STRING                    # litStr
    | TRUE                      # litTrue
    | FALSE                     # litFalse
    | TIME_LIT                  # litTime
    | SIZE_LIT                  # litSize
    | AGG_IDENT                 # litAgg
    | contextVar                # litCtx
    | IDENT                     # litIdent
    ;

// ---- Context Variables ----
contextVar
    : PID | TID | UID | GID | CPU | COMM | NSECS
    | SYSCALL | FUNC | LATENCY | RETVAL_KW | SIZE_KW | STACK_KW
    | ARG0 | ARG1 | ARG2 | ARG3 | ARG4 | ARG5
    ;

// ---- Variable-like Identifier (IDENT or context var token) ----
// ANTLR4 lexer defines context vars as separate tokens, so they
// cannot be matched by IDENT.  This rule allows context var tokens
// to be used wherever an ordinary identifier is expected (field
// names, option names, let bindings, etc.).
varIdent
    : IDENT
    | PID | TID | UID | GID | CPU | COMM | NSECS
    | SYSCALL | FUNC | LATENCY | RETVAL_KW | SIZE_KW | STACK_KW
    | ARG0 | ARG1 | ARG2 | ARG3 | ARG4 | ARG5
    ;

// ---- Function Call ----
funcCall
    : IDENT LPAREN argList? RPAREN
    ;

argList
    : expr (COMMA expr)*
    ;
