"""
Threat List Page — filterable / searchable table of all collected threats.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import streamlit as st

_ROOT = Path(__file__).parent.parent.parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from src.dashboard._shared import (  # noqa: E402
    CATEGORY_LABELS,
    SEVERITY_BADGE,
    SEVERITY_COLORS,
    format_date,
    get_db,
    severity_badge_html,
)

# ── Page config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="脅威一覧 | AI Threat Intel",
    page_icon="📋",
    layout="wide",
)

st.title("📋 脅威一覧")

db = get_db()
PAGE_SIZE = 25

# ── Sidebar filters ──────────────────────────────────────────────────────────
with st.sidebar:
    st.header("絞り込み条件")

    search_text = st.text_input("🔍 キーワード検索", placeholder="タイトル・説明文を検索")

    category_opts = ["（すべて）"] + list(CATEGORY_LABELS.keys())
    selected_category = st.selectbox("カテゴリ", category_opts)

    severity_opts = ["（すべて）", "critical", "high", "medium", "low", "info", "unknown"]
    selected_severity = st.selectbox("深刻度", severity_opts)

    source_opts = ["（すべて）", "nvd", "cisa_kev", "github_advisory", "arxiv", "rss_feeds", "otx"]
    selected_source = st.selectbox("ソース", source_opts)

    ai_only = st.checkbox("AI関連のみ")

    st.markdown("**期間（収集日）**")
    date_preset = st.radio(
        "期間プリセット",
        ["すべて", "過去7日", "過去30日", "過去90日"],
        horizontal=True,
    )
    since_dt: datetime | None = None
    if date_preset == "過去7日":
        since_dt = datetime.now(timezone.utc) - timedelta(days=7)
    elif date_preset == "過去30日":
        since_dt = datetime.now(timezone.utc) - timedelta(days=30)
    elif date_preset == "過去90日":
        since_dt = datetime.now(timezone.utc) - timedelta(days=90)

    if st.button("🔄 フィルタをリセット", use_container_width=True):
        st.query_params.clear()
        st.rerun()

# ── Pagination state ─────────────────────────────────────────────────────────
if "list_page" not in st.session_state:
    st.session_state["list_page"] = 0

# フィルタ変更時はページを先頭に戻す
filter_key = (search_text, selected_category, selected_severity, selected_source, ai_only, date_preset)
if st.session_state.get("_prev_filter") != filter_key:
    st.session_state["list_page"] = 0
    st.session_state["_prev_filter"] = filter_key

current_page: int = st.session_state["list_page"]
offset = current_page * PAGE_SIZE

# ── Query ────────────────────────────────────────────────────────────────────
items, total = db.search_items(
    source=None if selected_source == "（すべて）" else selected_source,
    threat_category=None if selected_category == "（すべて）" else selected_category,
    severity=None if selected_severity == "（すべて）" else selected_severity,
    ai_only=ai_only,
    since=since_dt,
    search=search_text or None,
    limit=PAGE_SIZE,
    offset=offset,
)

total_pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)

# ── Header ───────────────────────────────────────────────────────────────────
st.markdown(
    f"**{total:,} 件** が見つかりました　"
    f"（ページ {current_page + 1} / {total_pages}）"
)

# ── Table ────────────────────────────────────────────────────────────────────
if not items:
    st.info("条件に合う脅威情報が見つかりません。フィルタを変更してください。")
else:
    # ヘッダー行
    hdr = st.columns([0.5, 1.2, 1.2, 1.0, 4.5, 1.2, 0.6])
    for col, label in zip(hdr, ["#", "深刻度", "カテゴリ", "ソース", "タイトル", "公開日", "詳細"]):
        col.markdown(f"**{label}**")
    st.divider()

    for i, item in enumerate(items, start=offset + 1):
        sev = item.get("severity", "unknown")
        cat = item.get("threat_category", "unknown")
        row = st.columns([0.5, 1.2, 1.2, 1.0, 4.5, 1.2, 0.6])

        row[0].markdown(f"<small>{i}</small>", unsafe_allow_html=True)
        row[1].markdown(severity_badge_html(sev), unsafe_allow_html=True)
        row[2].markdown(
            f"<small>{CATEGORY_LABELS.get(cat, cat)}</small>",
            unsafe_allow_html=True,
        )
        row[3].markdown(
            f"<small>{item.get('source', '')}</small>",
            unsafe_allow_html=True,
        )

        title = item.get("title", "")
        if len(title) > 80:
            title = title[:77] + "..."
        row[4].markdown(f"<small>{title}</small>", unsafe_allow_html=True)
        row[5].markdown(
            f"<small>{format_date(item.get('published_at'))}</small>",
            unsafe_allow_html=True,
        )

        item_id = item.get("id")
        if item_id and row[6].button("→", key=f"detail_{item_id}_{i}"):
            st.session_state["detail_item_id"] = item_id
            st.switch_page("pages/2_脅威詳細.py")

    st.divider()

# ── Pagination controls ──────────────────────────────────────────────────────
pcol1, pcol2, pcol3 = st.columns([1, 3, 1])
with pcol1:
    if current_page > 0 and st.button("← 前のページ"):
        st.session_state["list_page"] -= 1
        st.rerun()
with pcol2:
    st.markdown(
        f"<div style='text-align:center'>{current_page + 1} / {total_pages}</div>",
        unsafe_allow_html=True,
    )
with pcol3:
    if current_page < total_pages - 1 and st.button("次のページ →"):
        st.session_state["list_page"] += 1
        st.rerun()
