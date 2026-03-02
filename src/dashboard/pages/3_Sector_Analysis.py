"""
Sector Analysis Page — sector-specific threat breakdown.

Allows users to select an industry sector and view threats
targeted at that sector, fulfilling BR-9-2.
"""

from __future__ import annotations

import sys
from pathlib import Path

import plotly.graph_objects as go
import streamlit as st

_ROOT = Path(__file__).parent.parent.parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from src.dashboard._shared import (  # noqa: E402
    CATEGORY_COLORS,
    CATEGORY_LABELS,
    PLOTLY_TEMPLATE,
    SECTOR_LABELS,
    SEVERITY_COLORS,
    category_badge_html,
    format_date,
    get_db,
    inject_global_css,
    section_header_html,
    severity_badge_html,
)

# ── Page config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Sector Analysis | AI Threat Intel",
    page_icon="🏭",
    layout="wide",
)

inject_global_css()

st.title("Sector Analysis")
st.caption("Select an industry sector to view AI threats targeted at that sector.")

db = get_db()

# ── Sector selector (URL param support for bookmarking) ──────────────────────
SECTOR_OPTIONS = [k for k in SECTOR_LABELS if k != "unknown"]
SECTOR_DISPLAY = [SECTOR_LABELS[k] for k in SECTOR_OPTIONS]

# Restore sector from URL param (BR-9-2: ?sector=financial)
url_sector = st.query_params.get("sector", "").lower()
default_idx = SECTOR_OPTIONS.index(url_sector) if url_sector in SECTOR_OPTIONS else 0

selected_display = st.selectbox(
    "Select Sector",
    SECTOR_DISPLAY,
    index=default_idx,
)
selected_sector = SECTOR_OPTIONS[SECTOR_DISPLAY.index(selected_display)]

# Sync URL param
st.query_params["sector"] = selected_sector

# ── Fetch sector data ─────────────────────────────────────────────────────────
items, total = db.get_items_by_sector(selected_sector, limit=20)
recent_7d = db.get_recent_by_sector(selected_sector, days=7)

# Aggregate severity / category (from current page of items)
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
st.markdown(section_header_html("SECTOR OVERVIEW"), unsafe_allow_html=True)

col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Threats", f"{total:,}")
col2.metric("Critical / High", f"{critical_high:,}", help="Aggregated from top 20 items")
col3.metric("New (7 Days)", f"{recent_7d:,}")
col4.metric(
    "Top Category",
    CATEGORY_LABELS.get(top_category, top_category) if total > 0 else "—",
)

st.divider()

# ── Severity + Category charts ────────────────────────────────────────────────
if total == 0:
    st.info(
        f"No threats found for the **{SECTOR_LABELS.get(selected_sector, selected_sector)}** sector.\n\n"
        "If sector classification has not been run, execute "
        "`python -m src.main migrate-sectors` from the CLI."
    )
else:
    left, right = st.columns(2)

    with left:
        st.markdown(
            '<p style="font-size:11px;font-weight:600;color:#5C5C72;letter-spacing:0.5px;'
            'text-transform:uppercase;margin-bottom:8px">Severity Distribution</p>',
            unsafe_allow_html=True,
        )
        sev_order = ["critical", "high", "medium", "low", "info", "unknown"]
        sev_labels = [s.upper() for s in sev_order if s in severity_counts]
        sev_values = [severity_counts[s] for s in sev_order if s in severity_counts]
        sev_colors = [SEVERITY_COLORS.get(s, "#9E9E9E") for s in sev_order if s in severity_counts]
        if sev_labels:
            fig = go.Figure(go.Bar(
                x=sev_labels,
                y=sev_values,
                marker_color=sev_colors,
                hovertemplate="%{x}: %{y:,}<extra></extra>",
            ))
            fig.update_layout(
                template=PLOTLY_TEMPLATE,
                xaxis_title=None,
                yaxis_title="Count",
                margin=dict(t=10, b=10, l=10, r=10),
                height=300,
            )
            st.plotly_chart(fig, use_container_width=True)

    with right:
        st.markdown(
            '<p style="font-size:11px;font-weight:600;color:#5C5C72;letter-spacing:0.5px;'
            'text-transform:uppercase;margin-bottom:8px">Threat Category</p>',
            unsafe_allow_html=True,
        )
        if category_counts:
            cat_labels = [CATEGORY_LABELS.get(k, k) for k in category_counts]
            cat_values = list(category_counts.values())
            cat_colors = [CATEGORY_COLORS.get(k, "#9E9E9E") for k in category_counts]
            fig = go.Figure(go.Pie(
                labels=cat_labels,
                values=cat_values,
                hole=0.45,
                marker_colors=cat_colors,
                textinfo="label+percent",
                hovertemplate="%{label}: %{value:,}<extra></extra>",
            ))
            fig.update_layout(
                template=PLOTLY_TEMPLATE,
                showlegend=True,
                legend=dict(orientation="h", yanchor="bottom", y=-0.4),
                margin=dict(t=10, b=10, l=10, r=10),
                height=300,
            )
            st.plotly_chart(fig, use_container_width=True)

    st.divider()

    # ── Recent threats list ────────────────────────────────────────────────────
    st.markdown(
        section_header_html(
            "RECENT THREATS",
            f"Showing {min(20, total)} of {total:,} total items",
        ),
        unsafe_allow_html=True,
    )

    hdr = st.columns([1.2, 1.4, 1.0, 5.0, 1.2, 0.6])
    for col, label in zip(hdr, ["SEVERITY", "CATEGORY", "SOURCE", "TITLE", "DATE", ""]):
        col.markdown(
            f'<span style="font-size:10px;font-weight:700;letter-spacing:0.7px;'
            f'color:#5C5C72;text-transform:uppercase">{label}</span>',
            unsafe_allow_html=True,
        )
    st.markdown(
        '<hr style="border-color:#002F6C;border-width:1.5px;margin:4px 0 8px 0">',
        unsafe_allow_html=True,
    )

    for item in items:
        sev = item.get("severity", "unknown")
        cat = item.get("threat_category", "unknown")
        row = st.columns([1.2, 1.4, 1.0, 5.0, 1.2, 0.6])

        row[0].markdown(severity_badge_html(sev), unsafe_allow_html=True)
        row[1].markdown(category_badge_html(cat), unsafe_allow_html=True)
        row[2].markdown(
            f'<span style="font-size:11px;color:#5C5C72">{item.get("source", "")}</span>',
            unsafe_allow_html=True,
        )
        title = item.get("title", "")
        if len(title) > 90:
            title = title[:87] + "…"
        row[3].markdown(
            f'<span style="font-size:12px;color:#1A1A2E">{title}</span>',
            unsafe_allow_html=True,
        )
        row[4].markdown(
            f'<span style="font-size:11px;color:#5C5C72">'
            f'{format_date(item.get("published_at"))}</span>',
            unsafe_allow_html=True,
        )
        item_id = item.get("id")
        if item_id and row[5].button("→", key=f"sec_detail_{item_id}"):
            st.session_state["detail_item_id"] = item_id
            st.switch_page("pages/2_Threat_Detail.py")

    if total > 20:
        st.caption(
            f"{total - 20:,} additional items available — use the Sector filter on the Threats page."
        )
