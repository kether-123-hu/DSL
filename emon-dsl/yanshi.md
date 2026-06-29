# 演示用例

## 目录
- 系统调用演示：`benchmark/system_calls/clone.emon`
- 事件演示：`benchmark/events/sched_switch.emon`
- 数据结构演示：`benchmark/data_structures/task_struct.emon`
- 函数演示：`benchmark/functions/kmalloc.emon`

## 演示步骤

先进入项目根目录：

```bash
cd /home/mxr/桌面/bianyi/emon-dsl
```

### 1. 系统调用演示

```bash
python3 main.py compile benchmark/system_calls/clone.emon -o demo/clone
python3 main.py run benchmark/system_calls/clone.emon --duration 5 --sudo
```

### 2. 事件演示

```bash
python3 main.py compile benchmark/events/sched_switch.emon -o demo/sched_switch
python3 main.py run benchmark/events/sched_switch.emon --duration 5 --sudo
```

### 3. 数据结构演示

```bash
python3 main.py compile benchmark/data_structures/task_struct.emon -o demo/task_struct
python3 main.py run benchmark/data_structures/task_struct.emon --duration 5 --sudo
```

### 4. 函数演示

```bash
python3 main.py compile benchmark/functions/kmalloc.emon -o demo/kmalloc
python3 main.py run benchmark/functions/kmalloc.emon --duration 5 --sudo
```

## 说明

- `compile` 命令会生成 BPF C、loader C 和 manifest
- `run` 命令会直接构建并运行 loader
- 如果当前是 root 用户，可以省略 `--sudo`
