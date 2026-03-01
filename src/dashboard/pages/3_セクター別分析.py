"""
Sector Analysis Page — sector-specific threat breakdown.

Allows users to select an industry sector and view threats
targeted at that sector, fulfilling BR-9-2.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import plotly.graph_objects as go
import streamlit as st

_ROOT = Path(__file__).parent.parent.parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from src.dashboard._shared import (  # noqa: E402
    CATEGORY_COLORS,
    CATEGORY_LABELS,
    SECTOR_COLORS,
    SECTOR_LABELS,
    SEVERITY_BADGE,
    SEVERITY_COLORS,
    format_date,
    get_db,
    severity_badge_html,
)

# ── Page config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="セクター別分析 | AI Threat Intel",
    page_icon="🏭",
    layout="wide",
)

st.title("🏭 産業セクター別 脅威分析")
st.caption("産業セクターを選択して、そのセクターに向けられた AI 脅威の状況を確認できます。")

db = get_db()

# ── Sector selector (URL param support for bookmarking) ──────────────────────
SECTOR_OPTIONS = [k for k in SECTOR_LABELS if k != "unknown"]
SECTOR_DISPLAY = [SECTOR_LABELS[k] for k in SECTOR_OPTIONS]

# URLパラメータからセクターを復元（BR-9-2: ?sector=FINANCIAL 対応）
url_sector = st.query_params.get("sector", "").lower()
default_idx = SECTOR_OPTIONS.index(url_sector) if url_sector in SECTOR_OPTIONS else 0

selected_display = st.selectbox(
    "セクターを選択",
    SECTOR_DISPLAY,
    index=default_idx,
)
selected_sector = SECTOR_OPTIONS[SECTOR_DISPLAY.index(selected_display)]

# URLパラメータを同期
st.query_params["sector"] = selected_sector

# ── Fetch sector data ─────────────────────────────────────────────────────────
items, total = db.get_items_by_sector(selected_sector, limit=20)
recent_7d = db.get_recent_by_sector(selected_sector, days=7)

# 深刻度・カテゴリ集計（Python側で集計）
severity_counts: dict[str, int] = {}
category_counts: dict[str, int] = {}
for item in items:
    sev = item.get("severity", "unknown")
    cat = item.get("threat_category", "unknown")
    severity_counts[sev] = severity_counts.get(sev, 0) + 1
    category_counts[cat] = category_counts.get(cat, 0) + 1

critical_high = severity_counts.get("critical", 0) + severity_counts.get("high", 0)
top_category = (
    max(category_counts, key=lambda k: category_counts[k])
    if category_counts
    else "unknown"
)

# ── KPI Cards ─────────────────────────────────────────────────────────────────
st.subheader(f"{SECTOR_LABELS.get(selected_sector, selected_sector)} — 現状サマリー")

col1, col2, col3, col4 = st.columns(4)
col1.metric("総件数（このセクター）", f"{total:,}")
col2.metric("Critical / High", f"{critical_high:,}", help="表示中 20 件内での集計")
col3.metric("過去7日間 新着", f"{recent_7d:,}")
col4.metric(
    "最多脅威カテゴリ",
    CATEGORY_LABELS.get(top_category, top_category) if total > 0 else "—",
)

st.divider()

# ── Severity + Category charts ────────────────────────────────────────────────
if total == 0:
    st.info(
        f"このセクター（{SECTOR_LABELS.get(selected_sector, selected_sector)}）の"
        "脅威データが見つかりませんでした。\n\n"
        "セクター分類が未実施の場合は、CLI から "
        "`python -m src.main migrate-sectors` を実行してください。"
    )
else:
    left, right = st.columns(2)

    with left:
        st.markdown("**深刻度分布**（表示中データ）")
        sev_order = ["critical", "high", "medium", "low", "info", "unknown"]
        sev_labels = [s.upper() for s in sev_order if s in severity_counts]
        sev_values = [severity_counts[s] for s in sev_order if s in severity_counts]
        sev_colors = [SEVERITY_COLORS.get(s, "#9e9e9e") for s in sev_order if s in severity_counts]
        if sev_labels:
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
                height=300,
            )
            st.plotly_chart(fig, use_container_width=True)

    with right:
        st.markdown("**脅威カテゴリ分布**（表示中データ）")
        if category_counts:
            cat_labels = [CATEGORY_LABELS.get(k, k) for k in category_counts]
            cat_values = list(category_counts.values())
            cat_colors = [CATEGORY_COLORS.get(k, "#9e9e9e") for k in category_counts]
            fig = go.Figure(go.Pie(
                labels=cat_labels,
                values=cat_values,
                hole=0.45,
                marker_colors=cat_colors,
                textinfo="label+percent",
                hovertemplate="%{label}: %{value} 件<extra></extra>",
            ))
            fig.update_layout(
                showlegend=True,
                legend=dict(orientation="h", yanchor="bottom", y=-0.4),
                margin=dict(t=10, b=10, l=10, r=10),
                height=300,
            )
            st.plotly_chart(fig, use_container_width=True)

    st.divider()

    # ── Recent threats list ────────────────────────────────────────────────────
    st.markdown(f"**直近の脅威一覧**（{min(20, total)} 件 / 全 {total:,} 件）")

    hdr = st.columns([1.2, 1.2, 1.0, 5.0, 1.2, 0.6])
    for col, label in zip(hdr, ["深刻度", "カテゴリ", "ソース", "タイトル", "公開日", "詳細"]):
        col.markdown(f"**{label}**")
    st.divider()

    for item in items:
        sev = item.get("severity", "unknown")
        cat = item.get("threat_category", "unknown")
        row = st.columns([1.2, 1.2, 1.0, 5.0, 1.2, 0.6])

        row[0].markdown(severity_badge_html(sev), unsafe_allow_html=True)
        row[1].markdown(
            f"<small>{CATEGORY_LABELS.get(cat, cat)}</small>",
            unsafe_allow_html=True,
        )
        row[2].markdown(
            f"<small>{item.get('source', '')}</small>",
            unsafe_allow_html=True,
        )
        title = item.get("title", "")
        if len(title) > 90:
            title = title[:87] + "..."
        row[3].markdown(f"<small>{title}</small>", unsafe_allow_html=True)
        row[4].markdown(
            f"<small>{format_date(item.get('published_at'))}</small>",
            unsafe_allow_html=True,
        )
        item_id = item.get("id")
        if item_id and row[5].button("→", key=f"sec_detail_{item_id}"):
            st.session_state["detail_item_id"] = item_id
            st.switch_page("pages/2_脅威詳細.py")

    if total > 20:
        st.caption(
            f"残り {total - 20:,} 件は「脅威一覧」ページでセクターフィルターを使って確認できます。"
        )
