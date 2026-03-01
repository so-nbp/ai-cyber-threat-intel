"""
Threat Detail Page — full information for a single threat item.
URL: ?id=<item_id>
"""

from __future__ import annotations

import sys
from pathlib import Path

import streamlit as st

_ROOT = Path(__file__).parent.parent.parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from src.dashboard._shared import (  # noqa: E402
    CATEGORY_LABELS,
    SEVERITY_COLORS,
    format_date,
    get_db,
    parse_json_field,
    severity_badge_html,
)

# ── Page config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="脅威詳細 | AI Threat Intel",
    page_icon="🔍",
    layout="wide",
)

db = get_db()

# ── Read ?id from query params ───────────────────────────────────────────────
params = st.query_params
raw_id = params.get("id")

if not raw_id:
    st.warning("URLに ?id=<ID> を指定してください。")
    if st.button("← 一覧に戻る"):
        st.switch_page("pages/1_脅威一覧.py")
    st.stop()

try:
    item_id = int(raw_id)
except ValueError:
    st.error(f"無効な ID: {raw_id}")
    st.stop()

item = db.get_item_by_id(item_id)
if item is None:
    st.error(f"ID {item_id} の脅威情報が見つかりません。")
    if st.button("← 一覧に戻る"):
        st.switch_page("pages/1_脅威一覧.py")
    st.stop()

# ── Adjacent IDs for prev/next navigation ────────────────────────────────────
prev_id, next_id = db.get_adjacent_ids(item_id)

# ── Navigation bar ───────────────────────────────────────────────────────────
nav_left, nav_center, nav_right = st.columns([1, 6, 1])

with nav_left:
    if st.button("← 一覧に戻る"):
        st.switch_page("pages/1_脅威一覧.py")

with nav_center:
    pass  # title area

with nav_right:
    pass  # placeholder

# Prev / Next
prev_col, _, next_col = st.columns([1, 8, 1])
with prev_col:
    if prev_id is not None and st.button("◀ 前"):
        st.query_params["id"] = str(prev_id)
        st.rerun()
with next_col:
    if next_id is not None and st.button("次 ▶"):
        st.query_params["id"] = str(next_id)
        st.rerun()

st.divider()

# ── Header ───────────────────────────────────────────────────────────────────
sev = item.get("severity", "unknown")
cat = item.get("threat_category", "unknown")
sev_color = SEVERITY_COLORS.get(sev, "#9e9e9e")

st.markdown(
    f"<h2 style='margin-bottom:4px'>{item.get('title', '（タイトルなし）')}</h2>",
    unsafe_allow_html=True,
)

badge_row = st.columns([1.5, 1.5, 1.5, 5])
badge_row[0].markdown(severity_badge_html(sev), unsafe_allow_html=True)
badge_row[1].markdown(
    f'<span style="background:#455a64;color:white;padding:2px 8px;'
    f'border-radius:4px;font-size:0.8em">'
    f'{CATEGORY_LABELS.get(cat, cat)}</span>',
    unsafe_allow_html=True,
)
badge_row[2].markdown(
    f'<span style="background:#37474f;color:#cfd8dc;padding:2px 8px;'
    f'border-radius:4px;font-size:0.8em">'
    f'{item.get("source", "")}</span>',
    unsafe_allow_html=True,
)

st.divider()

# ── Meta info ────────────────────────────────────────────────────────────────
m1, m2, m3, m4 = st.columns(4)

cvss = item.get("cvss_score")
m1.metric("公開日", format_date(item.get("published_at")))
m2.metric("収集日", format_date(item.get("collected_at")))
m3.metric("CVSS スコア", f"{cvss:.1f}" if cvss is not None else "—")
m4.metric("信頼度", item.get("confidence", "—"))

ai_flag = "✅ AI関連" if item.get("is_ai_related") else "⬜ 非AI関連"
st.markdown(f"**AI関連フラグ**: {ai_flag}")

st.divider()

# ── Description ──────────────────────────────────────────────────────────────
st.subheader("説明")
description = item.get("description") or "（説明なし）"
st.markdown(description)

st.divider()

# ── CVE IDs ──────────────────────────────────────────────────────────────────
cve_ids = parse_json_field(item.get("cve_ids"))
if cve_ids:
    st.subheader("関連 CVE")
    st.markdown("  ".join(f"`{c}`" for c in cve_ids))
    st.divider()

# ── Affected products ────────────────────────────────────────────────────────
products = parse_json_field(item.get("affected_products"))
if products:
    st.subheader("影響製品")
    prod_data = []
    for p in products:
        if isinstance(p, dict):
            prod_data.append({
                "ベンダー": p.get("vendor", "—"),
                "製品": p.get("product", "—"),
                "バージョン": p.get("version", "—"),
            })
    if prod_data:
        st.dataframe(prod_data, use_container_width=True, hide_index=True)
    st.divider()

# ── Tags & Keywords ──────────────────────────────────────────────────────────
tags = parse_json_field(item.get("tags"))
keywords = parse_json_field(item.get("keywords"))

if tags or keywords:
    st.subheader("タグ・キーワード")
    tk_col1, tk_col2 = st.columns(2)
    with tk_col1:
        if tags:
            st.markdown("**タグ**")
            st.markdown(
                " ".join(
                    f'<span style="background:#e0e0e0;padding:2px 6px;'
                    f'border-radius:3px;margin:2px;display:inline-block;font-size:0.8em">{t}</span>'
                    for t in tags
                ),
                unsafe_allow_html=True,
            )
    with tk_col2:
        if keywords:
            st.markdown("**キーワード**")
            st.markdown(
                " ".join(
                    f'<span style="background:#e3f2fd;padding:2px 6px;'
                    f'border-radius:3px;margin:2px;display:inline-block;font-size:0.8em">{k}</span>'
                    for k in keywords
                ),
                unsafe_allow_html=True,
            )
    st.divider()

# ── Source URL ───────────────────────────────────────────────────────────────
source_url = item.get("source_url")
if source_url:
    st.subheader("ソースリンク")
    st.markdown(f"[🔗 原文を開く]({source_url}){{target='_blank'}}", unsafe_allow_html=False)
    st.caption(source_url)
    st.divider()

# ── References ───────────────────────────────────────────────────────────────
references = parse_json_field(item.get("references_json"))
if references:
    st.subheader("参考リンク")
    for ref in references:
        if isinstance(ref, dict):
            url = ref.get("url", "")
            label = ref.get("title") or ref.get("source") or url
            if url:
                st.markdown(f"- [{label}]({url})")
        elif isinstance(ref, str):
            st.markdown(f"- {ref}")
    st.divider()

# ── Raw source ID ────────────────────────────────────────────────────────────
with st.expander("技術情報（デバッグ用）"):
    st.markdown(f"**内部ID**: `{item.get('id')}`")
    st.markdown(f"**item_hash**: `{item.get('item_hash')}`")
    st.markdown(f"**source_id**: `{item.get('source_id')}`")
    st.markdown(f"**source_type**: `{item.get('source_type')}`")
