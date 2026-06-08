# Emon DSL 语言参考

## 顶层结构
```
tool <name> {
    (option <ident> = <expr>;)*
    (observe <hook> { <clause>* })*
    (every <interval> { <stmt>* } )*
}
```

## 支持的 Hook 类型
- `syscall("read", "write", ...)`       —— 系统调用 tracepoint
- `kprobe("func")` / `kretprobe("func")` —— 内核函数探针
- `uprobe("/path:func")`                 —— 用户态函数探针
- `fentry("func")` / `fexit("func")`     —— BPF fentry/fexit
- `tracepoint("cat", "name")`            —— tracepoint
- `net` / `file` / `proc`                —— 高层抽象

## 观察子句
- `where <cond>`    —— 事件触发前过滤（上下文）
- `measure latency` —— 测量事件对象执行时长
- `measure count`   —— 事件计数
- `measure size`    —— 事件相关大小
- `when <cond>`     —— 测量后过滤（可使用 `latency` / `retval`）
- `@<name> = <agg-fn>(key, ...)`  —— 聚合：`count` / `sum` / `avg` / `hist` / `min` / `max`
- `emit { f: expr, ... }`         —— 将事件提交到 ring buffer
- `let <name> = <expr>`            —— 临时变量

## 周期任务
```
every <interval> {
    print top 10 @count;
}
```
由编译器生成用户态 loader 中的周期轮询与 map 读取逻辑。

## 字面量
- 整数：`123`
- 字符串：`"hello"`
- 时间：`100us` / `1ms` / `1s`
- 大小：`4KB` / `1MB`
- 聚合变量：`@count`、`@latency_hist`

## 内置上下文变量
`pid`、`tid`、`uid`、`gid`、`cpu`、`comm`、`retval`、`syscall`、`arg0..arg5`
