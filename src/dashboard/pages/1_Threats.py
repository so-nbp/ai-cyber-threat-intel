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
    SECTOR_LABELS,
    SEVERITY_LABELS,
    category_badge_html,
    format_date,
    get_db,
    inject_global_css,
    severity_badge_html,
)

# ── Page config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Threats | AI Threat Intel",
    page_icon="📋",
    layout="wide",
)

inject_global_css()

st.title("Threats")

db = get_db()
PAGE_SIZE = 25

# ── Sidebar filters ──────────────────────────────────────────────────────────
with st.sidebar:
    st.header("Filters")

    search_text = st.text_input("Search", placeholder="Search title or description…")

    category_keys = list(CATEGORY_LABELS.keys())
    category_display_opts = ["All categories"] + [CATEGORY_LABELS[k] for k in category_keys]
    selected_category_display = st.selectbox("Category", category_display_opts)
    selected_category = (
        None
        if selected_category_display == "All categories"
        else category_keys[category_display_opts.index(selected_category_display) - 1]
    )

    severity_display_opts = ["All severities"] + list(SEVERITY_LABELS.values())
    severity_key_opts = [None] + list(SEVERITY_LABELS.keys())
    selected_severity_display = st.selectbox("Severity", severity_display_opts)
    selected_severity = severity_key_opts[severity_display_opts.index(selected_severity_display)]

    source_display_opts = ["All sources", "NVD", "CISA KEV", "GitHub Advisory", "arXiv", "RSS Feeds", "OTX"]
    source_value_opts = [None, "nvd", "cisa_kev", "github_advisory", "arxiv", "rss_feeds", "otx"]
    selected_source_display = st.selectbox("Source", source_display_opts)
    selected_source = source_value_opts[source_display_opts.index(selected_source_display)]

    sector_keys = [k for k in SECTOR_LABELS.keys() if k != "unknown"]
    sector_display_opts = ["All sectors"] + [SECTOR_LABELS[k] for k in sector_keys]
    selected_sector_display = st.selectbox("Industry Sector", sector_display_opts)
    selected_sector = (
        None
        if selected_sector_display == "All sectors"
        else sector_keys[sector_display_opts.index(selected_sector_display) - 1]
    )

    ai_only = st.checkbox("AI-Related Only")

    st.markdown("---")
    date_preset = st.radio(
        "Date Range",
        ["All time", "Last 7 days", "Last 30 days", "Last 90 days"],
        horizontal=False,
    )
    since_dt: datetime | None = None
    if date_preset == "Last 7 days":
        since_dt = datetime.now(timezone.utc) - timedelta(days=7)
    elif date_preset == "Last 30 days":
        since_dt = datetime.now(timezone.utc) - timedelta(days=30)
    elif date_preset == "Last 90 days":
        since_dt = datetime.now(timezone.utc) - timedelta(days=90)

    st.markdown("---")
    if st.button("Reset Filters", use_container_width=True):
        st.query_params.clear()
        st.rerun()

# ── Pagination state ─────────────────────────────────────────────────────────
if "list_page" not in st.session_state:
    st.session_state["list_page"] = 0

filter_key = (
    search_text, selected_category, selected_severity,
    selected_source, selected_sector, ai_only, date_preset,
)
if st.session_state.get("_prev_filter") != filter_key:
    st.session_state["list_page"] = 0
    st.session_state["_prev_filter"] = filter_key

current_page: int = st.session_state["list_page"]
offset = current_page * PAGE_SIZE

# ── Query ────────────────────────────────────────────────────────────────────
items, total = db.search_items(
    source=selected_source,
    threat_category=selected_category,
    severity=selected_severity,
    sector=selected_sector,
    ai_only=ai_only,
    since=since_dt,
    search=search_text or None,
    limit=PAGE_SIZE,
    offset=offset,
)

total_pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)

# ── Result summary ────────────────────────────────────────────────────────────
st.markdown(
    f'<p style="font-size:13px;color:#5C5C72;margin-bottom:12px">'
    f'<strong style="color:#1A1A2E">{total:,}</strong> items found'
    f'&nbsp;&nbsp;—&nbsp;&nbsp;Page {current_page + 1} of {total_pages}'
    f'</p>',
    unsafe_allow_html=True,
)

# ── Table ────────────────────────────────────────────────────────────────────
if not items:
    st.info("No threats match your current filters. Try adjusting the criteria.")
else:
    # Header row
    hdr = st.columns([0.5, 1.2, 1.4, 1.0, 4.3, 1.1, 0.6])
    for col, label in zip(hdr, ["#", "SEVERITY", "CATEGORY", "SOURCE", "TITLE", "DATE", ""]):
        col.markdown(
            f'<span style="font-size:10px;font-weight:700;letter-spacing:0.7px;'
            f'color:#5C5C72;text-transform:uppercase">{label}</span>',
            unsafe_allow_html=True,
        )
    st.markdown(
        '<hr style="border-color:#002F6C;border-width:1.5px;margin:4px 0 8px 0">',
        unsafe_allow_html=True,
    )

    for i, item in enumerate(items, start=offset + 1):
        sev = item.get("severity", "unknown")
        cat = item.get("threat_category", "unknown")
        row = st.columns([0.5, 1.2, 1.4, 1.0, 4.3, 1.1, 0.6])

        row[0].markdown(
            f'<span style="font-size:11px;color:#9E9E9E">{i}</span>',
            unsafe_allow_html=True,
        )
        row[1].markdown(severity_badge_html(sev), unsafe_allow_html=True)
        row[2].markdown(category_badge_html(cat), unsafe_allow_html=True)
        row[3].markdown(
            f'<span style="font-size:11px;color:#5C5C72">{item.get("source", "")}</span>',
            unsafe_allow_html=True,
        )

        title = item.get("title", "")
        if len(title) > 80:
            title = title[:77] + "…"
        row[4].markdown(
            f'<span style="font-size:12px;color:#1A1A2E">{title}</span>',
            unsafe_allow_html=True,
        )
        row[5].markdown(
            f'<span style="font-size:11px;color:#5C5C72">'
            f'{format_date(item.get("published_at"))}</span>',
            unsafe_allow_html=True,
        )

        item_id = item.get("id")
        if item_id and row[6].button("→", key=f"detail_{item_id}_{i}"):
            st.session_state["detail_item_id"] = item_id
            st.switch_page("pages/2_Threat_Detail.py")

    st.markdown(
        '<hr style="border-color:#E0E0DA;margin:8px 0">',
        unsafe_allow_html=True,
    )

# ── Pagination controls ──────────────────────────────────────────────────────
pcol1, pcol2, pcol3 = st.columns([1, 3, 1])
with pcol1:
    if current_page > 0 and st.button("← Previous"):
        st.session_state["list_page"] -= 1
        st.rerun()
with pcol2:
    st.markdown(
        f'<div style="text-align:center;font-size:12px;color:#5C5C72;padding-top:8px">'
        f'{current_page + 1} / {total_pages}</div>',
        unsafe_allow_html=True,
    )
with pcol3:
    if current_page < total_pages - 1 and st.button("Next →"):
        st.session_state["list_page"] += 1
        st.rerun()
