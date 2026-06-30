# Emon DSL Frontend

> 基于 Streamlit + Altair 的 eBPF 可观测性实时监控仪表盘

## 快速开始

```bash
# 1. 安装依赖
cd frontend
pip install -r requirements.txt

# 2. 启动 Streamlit 仪表盘
streamlit run app.py

# 3. 浏览器访问 http://localhost:8501
```

## 文件说明

```
frontend/
├── app.py              # Streamlit 主应用 (实时监控仪表盘)
├── bpf_reader.py       # BPF Map 数据读取器
├── config.yaml         # 配置文件
├── requirements.txt    # Python 依赖
└── README.md           # 本文件

../frontier.py          # 用户态数据桥接脚本 (独立运行)
```

## 功能特性

| 功能 | 说明 |
|------|------|
| 📈 实时面积图 | 展示 Linux VFS 各操作的执行频率 (每秒) |
| 🔍 交互式 Tooltip | 鼠标悬停查看具体数值 |
| 📊 操作排名 | 柱状图展示最活跃的文件系统操作 |
| 🏗️ 架构可视化 | Mermaid 流程图展示完整数据流 |
| ⚙️ 灵活配置 | 可调节时间窗口、刷新频率、数据源 |
| 🎮 模拟模式 | 无需 root 权限即可预览完整功能 |

## 数据源

- **模拟模式** (默认): 使用 `MockDataGenerator` 生成 15 种 VFS 操作的仿真数据
- **BPF Map 模式**: 通过 `bpftool map dump` 读取实际 eBPF 程序的 map 数据

## 配置

编辑 `config.yaml` 可自定义:

- 监控工具列表
- BPF Map 映射
- 图表窗口大小
- 告警阈值
