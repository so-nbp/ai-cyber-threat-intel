"""
AI Cyber Threat Intelligence — Overview Dashboard (Home Page).

Run with:
    streamlit run src/dashboard/app.py
or via CLI:
    python -m src.main dashboard
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import plotly.graph_objects as go
import streamlit as st

from _shared import (
    CATEGORY_COLORS,
    CATEGORY_LABELS,
    SEVERITY_COLORS,
    format_date,
    get_db,
)

# ── Page config ─────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="AI Threat Intel Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.title("🛡️ AI Cyber Threat Intelligence")
st.caption("AI×サイバーセキュリティ 脅威インテリジェンス ダッシュボード")

db = get_db()

# ── Fetch data ───────────────────────────────────────────────────────────────
stats = db.get_statistics()
daily_trend = db.get_daily_trend(days=30)

total_items: int = stats.get("total_items", 0)
ai_related: int = stats.get("ai_related_items", 0)
by_severity: dict = stats.get("by_severity", {})
by_category: dict = stats.get("by_category", {})
by_source: dict = stats.get("by_source", {})

critical_high = by_severity.get("critical", 0) + by_severity.get("high", 0)
ai_pct = round(ai_related / total_items * 100, 1) if total_items else 0.0

since_24h = datetime.now(timezone.utc) - timedelta(hours=24)
_, new_24h = db.search_items(since=since_24h, limit=1)

# ── KPI Cards ────────────────────────────────────────────────────────────────
st.subheader("現状サマリー")
col1, col2, col3, col4 = st.columns(4)
col1.metric("総収集件数", f"{total_items:,}")
col2.metric("Critical / High", f"{critical_high:,}", help="Critical + High の合計件数")
col3.metric("AI関連割合", f"{ai_pct}%", help="is_ai_related = true の割合")
col4.metric("過去24h 新着", f"{new_24h:,}")

st.divider()

# ── Row 1: Donut (Category) + Bar (Severity) ─────────────────────────────────
st.subheader("脅威分布")
left, right = st.columns(2)

with left:
    st.markdown("**カテゴリ別内訳**")
    if by_category:
        labels = [CATEGORY_LABELS.get(k, k) for k in by_category]
        values = list(by_category.values())
        colors = [CATEGORY_COLORS.get(k, "#9e9e9e") for k in by_category]
        fig = go.Figure(go.Pie(
            labels=labels,
            values=values,
            hole=0.45,
            marker_colors=colors,
            textinfo="label+percent",
            hovertemplate="%{label}: %{value} 件<extra></extra>",
        ))
        fig.update_layout(
            showlegend=True,
            legend=dict(orientation="h", yanchor="bottom", y=-0.3),
            margin=dict(t=10, b=10, l=10, r=10),
            height=320,
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("データがありません")

with right:
    st.markdown("**深刻度分布**")
    if by_severity:
        sev_order = ["critical", "high", "medium", "low", "info", "unknown"]
        sev_labels = [s.upper() for s in sev_order if s in by_severity]
        sev_values = [by_severity[s] for s in sev_order if s in by_severity]
        sev_colors = [SEVERITY_COLORS.get(s, "#9e9e9e") for s in sev_order if s in by_severity]
        fig = go.Figure(go.Bar(
            x=sev_labels,
            y=sev_values,
            marker_color=sev_colors,
            hovertemplate="%{x}: %{y} 件<extra></extra>",
        ))
        fig.update_layout(
            xaxis_title=None,
            yaxis_title="件数",
            margin=dict(t=10, b=10, l=10, r=10),
            height=320,
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("データがありません")

st.divider()

# ── Row 2: Line (Trend) + Bar (Source) ───────────────────────────────────────
st.subheader("収集状況")
left2, right2 = st.columns(2)

with left2:
    st.markdown("**過去30日間 収集件数推移**")
    if daily_trend:
        days_list = [row["day"] for row in daily_trend]
        counts = [row["count"] for row in daily_trend]
        fig = go.Figure(go.Scatter(
            x=days_list,
            y=counts,
            mode="lines+markers",
            line=dict(color="#1e88e5", width=2),
            marker=dict(size=5),
            hovertemplate="%{x}: %{y} 件<extra></extra>",
        ))
        fig.update_layout(
            xaxis_title=None,
            yaxis_title="件数",
            margin=dict(t=10, b=10, l=10, r=10),
            height=280,
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("トレンドデータがありません（収集を実行してください）")

with right2:
    st.markdown("**ソース別収集件数**")
    if by_source:
        src_labels = list(by_source.keys())
        src_values = list(by_source.values())
        fig = go.Figure(go.Bar(
            x=src_values,
            y=src_labels,
            orientation="h",
            marker_color="#26a69a",
            hovertemplate="%{y}: %{x} 件<extra></extra>",
        ))
        fig.update_layout(
            xaxis_title="件数",
            yaxis_title=None,
            margin=dict(t=10, b=10, l=10, r=10),
            height=280,
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("データがありません")

st.divider()

# ── Recent collection runs ────────────────────────────────────────────────────
st.subheader("直近の収集実行")
recent_runs = stats.get("recent_runs", [])
if recent_runs:
    run_data = []
    for r in recent_runs[:10]:
        run_data.append({
            "ソース": r.get("source", ""),
            "開始日時": format_date(r.get("started_at")),
            "収集件数": r.get("items_collected", 0),
            "新規": r.get("items_new", 0),
            "状態": "✅ 成功" if r.get("success") else "❌ 失敗",
        })
    st.dataframe(run_data, use_container_width=True, hide_index=True)
else:
    st.info("収集履歴がありません")
