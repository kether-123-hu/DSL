"""
Emon DSL Frontend —— Streamlit 实时监控仪表盘
启动方式:
    cd frontend
    streamlit run app.py
"""

from __future__ import annotations

import os
import sys
import time

import altair as alt
import pandas as pd
import streamlit as st

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bpf_reader import MockDataGenerator


# =============================================================================
# 页面配置
# =============================================================================

st.set_page_config(
    page_title="Emon DSL - 实时监控",
    page_icon="",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# =============================================================================
# 常量
# =============================================================================

VFS_OPS = [
    "create", "getattr", "getxattr", "lookup", "mkdir",
    "open", "opendir", "read", "readdir", "release",
    "releasedir", "rename", "setattr", "unlink", "write",
]

COLOR_SCHEME = "category20"


# =============================================================================
# 会话初始化
# =============================================================================

def init_session():
    defaults = {
        "mock_gen": MockDataGenerator(seed=42),
        "history_df": pd.DataFrame(),
        "running": True,
        "window_seconds": 20,
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v


def tick():
    """追加一圈模拟数据."""
    mock = st.session_state.mock_gen
    new_df = mock.generate_snapshot()
    new_df = new_df.rename(columns={"operation": "操作类型", "count": "执行次数/秒"})

    hist = st.session_state.history_df
    if hist.empty:
        base_ts = new_df["timestamp"].min()
    else:
        base_ts = hist["timestamp"].min()

    new_df["time"] = new_df["timestamp"] - base_ts
    st.session_state.history_df = pd.concat([hist, new_df], ignore_index=True)

    # 只保留窗口内数据
    cutoff = time.time() - st.session_state.window_seconds - base_ts
    st.session_state.history_df = st.session_state.history_df[
        st.session_state.history_df["time"] >= cutoff
    ]


# =============================================================================
# 堆叠面积图
# =============================================================================

def render_chart(df: pd.DataFrame, window_seconds: int = 20):
    if df.empty:
        st.info("等待数据...")
        return

    max_time = df["time"].max()
    min_time = max(max_time - window_seconds, df["time"].min())
    chart_df = df[df["time"] >= min_time].copy()
    chart_df["time_bucket"] = chart_df["time"].round(0).astype(int)

    # 以 time_bucket + 操作类型聚合, 消除同一秒内同一操作的重复点
    chart_df = (
        chart_df.groupby(["操作类型", "time_bucket"])["执行次数/秒"]
        .sum()
        .reset_index()
    )

    color_scale = alt.Scale(domain=sorted(set(VFS_OPS)), scheme=COLOR_SCHEME)

    area = (
        alt.Chart(chart_df)
        .mark_area(opacity=0.25)
        .encode(
            x=alt.X("time_bucket:Q", title="时间 (秒)"),
            y=alt.Y("执行次数/秒:Q", title="执行次数/秒", stack=None),
            color=alt.Color(
                "操作类型:N",
                scale=color_scale,
                legend=alt.Legend(orient="right", title="操作类型", labelFontSize=11),
            ),
            tooltip=[
                alt.Tooltip("操作类型:N", title="操作类型"),
                alt.Tooltip("执行次数/秒:Q", title="执行次数", format=",.0f"),
                alt.Tooltip("time_bucket:Q", title="时间 (秒)", format=".0f"),
            ],
        )
    )

    line = area.mark_line(opacity=0.8)

    # hover 交互: 竖直线 + 数值标注
    nearest = alt.selection_point(
        fields=["time_bucket"], nearest=True, on="pointerover", empty=False
    )

    selectors = (
        alt.Chart(chart_df)
        .mark_point(size=80, filled=True, opacity=0)
        .encode(x="time_bucket:Q", y="执行次数/秒:Q", color=alt.Color("操作类型:N", legend=None))
        .add_params(nearest)
    )

    rules = (
        alt.Chart(chart_df)
        .mark_rule(color="gray", strokeDash=[5, 5], opacity=0.5)
        .encode(x="time_bucket:Q")
        .transform_filter(nearest)
    )

    tip_text = (
        alt.Chart(chart_df)
        .mark_text(align="left", dx=5, dy=-5, fontSize=11, fontWeight="bold")
        .encode(
            x="time_bucket:Q",
            y="执行次数/秒:Q",
            text=alt.Text("执行次数/秒:Q", format=",.0f"),
            color=alt.Color("操作类型:N", legend=None),
        )
        .transform_filter(nearest)
    )

    chart = (
        alt.layer(area, line, selectors, rules, tip_text)
        .properties(
            width="container",
            height=450,
            title=alt.TitleParams("实时监控图表（最近20秒）", fontSize=16),
        )
        .interactive()
        .configure_axis(labelFontSize=11, titleFontSize=12, gridColor="#e0e0e0")
        .configure_legend(titleFontSize=12, labelFontSize=11, padding=10)
        .configure_view(strokeWidth=0)
    )

    st.altair_chart(chart, use_container_width=True)


# =============================================================================
# 主入口
# =============================================================================

def main():
    init_session()

    # 隐藏 sidebar, 只留空壳
    st.sidebar.empty()

    # 控制栏: 紧凑一行
    c1, c2, c3, c4 = st.columns([1, 1, 1, 2])
    with c1:
        if st.button("暂停 / 继续", use_container_width=True):
            st.session_state.running = not st.session_state.running
    with c2:
        new_win = st.selectbox("时间窗口", [10, 20, 30, 60], index=1)
        st.session_state.window_seconds = new_win
    with c3:
        st.caption(f"状态: {'运行中' if st.session_state.running else '已暂停'}")
    with c4:
        pass  # 占位, 保持布局

    st.markdown("---")

    if st.session_state.running:
        tick()
        render_chart(st.session_state.history_df, st.session_state.window_seconds)
        time.sleep(1)
        st.rerun()
    else:
        render_chart(st.session_state.history_df, st.session_state.window_seconds)


if __name__ == "__main__":
    main()
