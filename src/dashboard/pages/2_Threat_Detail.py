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
    category_badge_html,
    format_date,
    get_db,
    inject_global_css,
    parse_json_field,
    section_header_html,
    severity_badge_html,
    source_badge_html,
)

# ── Page config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Threat Detail | AI Threat Intel",
    page_icon="🔍",
    layout="wide",
)

inject_global_css()

db = get_db()

# ── Read item ID (query param or session_state fallback) ─────────────────────
raw_id = st.query_params.get("id")

if not raw_id:
    session_id = st.session_state.pop("detail_item_id", None)
    if session_id is not None:
        raw_id = str(session_id)

if not raw_id:
    st.warning("Specify ?id=<ID> in the URL to view a threat.")
    if st.button("← Back to Threats"):
        st.switch_page("pages/1_Threats.py")
    st.stop()

try:
    item_id = int(raw_id)
except ValueError:
    st.error(f"Invalid ID: {raw_id}")
    st.stop()

item = db.get_item_by_id(item_id)
if item is None:
    st.error(f"Threat ID {item_id} not found.")
    if st.button("← Back to Threats"):
        st.switch_page("pages/1_Threats.py")
    st.stop()

# ── Adjacent IDs for prev/next navigation ────────────────────────────────────
prev_id, next_id = db.get_adjacent_ids(item_id)

# ── Navigation bar ───────────────────────────────────────────────────────────
nav_left, _, nav_right = st.columns([1, 6, 1])
with nav_left:
    if st.button("← Back to Threats"):
        st.switch_page("pages/1_Threats.py")

prev_col, _, next_col = st.columns([1, 8, 1])
with prev_col:
    if prev_id is not None and st.button("◀ Prev"):
        st.query_params["id"] = str(prev_id)
        st.rerun()
with next_col:
    if next_id is not None and st.button("Next ▶"):
        st.query_params["id"] = str(next_id)
        st.rerun()

st.divider()

# ── Header ───────────────────────────────────────────────────────────────────
sev = item.get("severity", "unknown")
cat = item.get("threat_category", "unknown")

st.markdown(
    f"<h2 style='margin-bottom:8px;color:#1A1A2E'>"
    f"{item.get('title', '(No title)')}</h2>",
    unsafe_allow_html=True,
)

badge_row = st.columns([1.5, 1.8, 1.5, 5])
badge_row[0].markdown(severity_badge_html(sev), unsafe_allow_html=True)
badge_row[1].markdown(category_badge_html(cat), unsafe_allow_html=True)
badge_row[2].markdown(source_badge_html(item.get("source", "")), unsafe_allow_html=True)

st.divider()

# ── Meta info ────────────────────────────────────────────────────────────────
m1, m2, m3, m4 = st.columns(4)

cvss = item.get("cvss_score")
m1.metric("Published", format_date(item.get("published_at")))
m2.metric("Collected", format_date(item.get("collected_at")))
m3.metric("CVSS Score", f"{cvss:.1f}" if cvss is not None else "—")
m4.metric("Confidence", item.get("confidence", "—"))

ai_flag = "AI-Related" if item.get("is_ai_related") else "Non-AI"
ai_color = "#002F6C" if item.get("is_ai_related") else "#757575"
st.markdown(
    f'<p style="font-size:12px;margin-top:8px">'
    f'<span style="font-weight:700;color:{ai_color};font-size:10px;'
    f'letter-spacing:0.5px;text-transform:uppercase">AI Flag</span>&nbsp;&nbsp;'
    f'<span style="color:#1A1A2E">{ai_flag}</span></p>',
    unsafe_allow_html=True,
)

st.divider()

# ── Description ──────────────────────────────────────────────────────────────
st.markdown(section_header_html("DESCRIPTION"), unsafe_allow_html=True)
description = item.get("description") or "(No description available)"
st.markdown(description)

# ── CVE IDs ──────────────────────────────────────────────────────────────────
cve_ids = parse_json_field(item.get("cve_ids"))
if cve_ids:
    st.divider()
    st.markdown(section_header_html("RELATED CVEs"), unsafe_allow_html=True)
    st.markdown("  ".join(f"`{c}`" for c in cve_ids))

# ── Affected products ────────────────────────────────────────────────────────
products = parse_json_field(item.get("affected_products"))
if products:
    st.divider()
    st.markdown(section_header_html("AFFECTED PRODUCTS"), unsafe_allow_html=True)
    prod_data = []
    for p in products:
        if isinstance(p, dict):
            prod_data.append({
                "Vendor": p.get("vendor", "—"),
                "Product": p.get("product", "—"),
                "Version": p.get("version", "—"),
            })
    if prod_data:
        st.dataframe(prod_data, use_container_width=True, hide_index=True)

# ── Tags & Keywords ──────────────────────────────────────────────────────────
tags = parse_json_field(item.get("tags"))
keywords = parse_json_field(item.get("keywords"))

if tags or keywords:
    st.divider()
    st.markdown(section_header_html("TAGS & KEYWORDS"), unsafe_allow_html=True)
    tk_col1, tk_col2 = st.columns(2)
    with tk_col1:
        if tags:
            st.markdown(
                '<p style="font-size:10px;font-weight:700;color:#5C5C72;'
                'letter-spacing:0.5px;text-transform:uppercase;margin-bottom:6px">Tags</p>',
                unsafe_allow_html=True,
            )
            st.markdown(
                " ".join(
                    f'<span style="background:#F0F0EC;color:#5C5C72;padding:2px 7px;'
                    f'border-radius:2px;margin:2px;display:inline-block;'
                    f'font-size:11px;font-family:Inter,sans-serif">{t}</span>'
                    for t in tags
                ),
                unsafe_allow_html=True,
            )
    with tk_col2:
        if keywords:
            st.markdown(
                '<p style="font-size:10px;font-weight:700;color:#5C5C72;'
                'letter-spacing:0.5px;text-transform:uppercase;margin-bottom:6px">Keywords</p>',
                unsafe_allow_html=True,
            )
            st.markdown(
                " ".join(
                    f'<span style="background:#E8EEF5;color:#002F6C;padding:2px 7px;'
                    f'border-radius:2px;margin:2px;display:inline-block;'
                    f'font-size:11px;font-family:Inter,sans-serif">{k}</span>'
                    for k in keywords
                ),
                unsafe_allow_html=True,
            )

# ── Source URL ───────────────────────────────────────────────────────────────
source_url = item.get("source_url")
if source_url:
    st.divider()
    st.markdown(section_header_html("SOURCE"), unsafe_allow_html=True)
    st.markdown(f"[Open original source]({source_url}){{target='_blank'}}", unsafe_allow_html=False)
    st.caption(source_url)

# ── References ───────────────────────────────────────────────────────────────
references = parse_json_field(item.get("references_json"))
if references:
    st.divider()
    st.markdown(section_header_html("REFERENCES"), unsafe_allow_html=True)
    for ref in references:
        if isinstance(ref, dict):
            url = ref.get("url", "")
            label = ref.get("title") or ref.get("source") or url
            if url:
                st.markdown(f"- [{label}]({url})")
        elif isinstance(ref, str):
            st.markdown(f"- {ref}")

# ── Technical details ─────────────────────────────────────────────────────────
st.divider()
with st.expander("Technical Details"):
    st.markdown(f"**Internal ID**: `{item.get('id')}`")
    st.markdown(f"**item_hash**: `{item.get('item_hash')}`")
    st.markdown(f"**source_id**: `{item.get('source_id')}`")
    st.markdown(f"**source_type**: `{item.get('source_type')}`")
