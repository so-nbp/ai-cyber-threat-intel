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
    PLOTLY_TEMPLATE,
    SECTOR_COLORS,
    SECTOR_LABELS,
    SEVERITY_COLORS,
    data_freshness_html,
    format_date,
    get_db,
    inject_global_css,
    section_header_html,
)

# ── Page config ─────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="AI Threat Intelligence Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

inject_global_css()

st.title("AI Threat Intelligence")
st.caption("AI × Cybersecurity Threat Intelligence Platform")

db = get_db()

# ── Fetch data ───────────────────────────────────────────────────────────────
stats = db.get_statistics()
sector_stats = db.get_sector_statistics()
daily_trend = db.get_daily_trend(days=30)

total_items: int = stats.get("total_items", 0)
ai_related: int = stats.get("ai_related_items", 0)
by_severity: dict = stats.get("by_severity", {})
by_category: dict = stats.get("by_category", {})
by_source: dict = stats.get("by_source", {})
recent_runs = stats.get("recent_runs", [])

critical_high = by_severity.get("critical", 0) + by_severity.get("high", 0)
ai_pct = round(ai_related / total_items * 100, 1) if total_items else 0.0

since_24h = datetime.now(timezone.utc) - timedelta(hours=24)
_, new_24h = db.search_items(since=since_24h, limit=1)

# ── Data freshness banner ────────────────────────────────────────────────────
last_run_str = format_date(recent_runs[0].get("started_at")) if recent_runs else "N/A"
st.markdown(data_freshness_html(last_run_str), unsafe_allow_html=True)

# ── KPI Cards ────────────────────────────────────────────────────────────────
st.markdown(section_header_html("SITUATION SUMMARY"), unsafe_allow_html=True)
col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Threats", f"{total_items:,}")
col2.metric("Critical / High", f"{critical_high:,}", help="Sum of Critical + High severity items")
col3.metric("AI-Related", f"{ai_pct}%", help="Percentage of items with is_ai_related = true")
col4.metric("New (24h)", f"{new_24h:,}")

# ── Row 1: Donut (Category) + Bar (Severity) ─────────────────────────────────
st.markdown(section_header_html("THREAT DISTRIBUTION"), unsafe_allow_html=True)
left, right = st.columns(2)

with left:
    st.markdown(
        '<p style="font-size:11px;font-weight:600;color:#5C5C72;letter-spacing:0.5px;'
        'text-transform:uppercase;margin-bottom:8px">By Category</p>',
        unsafe_allow_html=True,
    )
    if by_category:
        labels = [CATEGORY_LABELS.get(k, k) for k in by_category]
        values = list(by_category.values())
        colors = [CATEGORY_COLORS.get(k, "#9E9E9E") for k in by_category]
        fig = go.Figure(go.Pie(
            labels=labels,
            values=values,
            hole=0.45,
            marker_colors=colors,
            textinfo="label+percent",
            hovertemplate="%{label}: %{value:,}<extra></extra>",
        ))
        fig.update_layout(
            template=PLOTLY_TEMPLATE,
            showlegend=True,
            legend=dict(orientation="h", yanchor="bottom", y=-0.35),
            margin=dict(t=10, b=10, l=10, r=10),
            height=320,
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No data available.")

with right:
    st.markdown(
        '<p style="font-size:11px;font-weight:600;color:#5C5C72;letter-spacing:0.5px;'
        'text-transform:uppercase;margin-bottom:8px">By Severity</p>',
        unsafe_allow_html=True,
    )
    if by_severity:
        sev_order = ["critical", "high", "medium", "low", "info", "unknown"]
        sev_labels = [s.upper() for s in sev_order if s in by_severity]
        sev_values = [by_severity[s] for s in sev_order if s in by_severity]
        sev_colors = [SEVERITY_COLORS.get(s, "#9E9E9E") for s in sev_order if s in by_severity]
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
            height=320,
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No data available.")

# ── Row 2: Line (Trend) + Bar (Source) ───────────────────────────────────────
st.markdown(section_header_html("COLLECTION STATUS"), unsafe_allow_html=True)
left2, right2 = st.columns(2)

with left2:
    st.markdown(
        '<p style="font-size:11px;font-weight:600;color:#5C5C72;letter-spacing:0.5px;'
        'text-transform:uppercase;margin-bottom:8px">30-Day Collection Trend</p>',
        unsafe_allow_html=True,
    )
    if daily_trend:
        days_list = [row["day"] for row in daily_trend]
        counts = [row["count"] for row in daily_trend]
        fig = go.Figure(go.Scatter(
            x=days_list,
            y=counts,
            mode="lines+markers",
            line=dict(color="#002F6C", width=2),
            marker=dict(size=5, color="#002F6C"),
            hovertemplate="%{x}: %{y:,}<extra></extra>",
            fill="tozeroy",
            fillcolor="rgba(0,47,108,0.06)",
        ))
        fig.update_layout(
            template=PLOTLY_TEMPLATE,
            xaxis_title=None,
            yaxis_title="Count",
            margin=dict(t=10, b=10, l=10, r=10),
            height=280,
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No trend data available. Run a collection first.")

with right2:
    st.markdown(
        '<p style="font-size:11px;font-weight:600;color:#5C5C72;letter-spacing:0.5px;'
        'text-transform:uppercase;margin-bottom:8px">By Source</p>',
        unsafe_allow_html=True,
    )
    if by_source:
        src_labels = list(by_source.keys())
        src_values = list(by_source.values())
        fig = go.Figure(go.Bar(
            x=src_values,
            y=src_labels,
            orientation="h",
            marker_color="#002F6C",
            hovertemplate="%{y}: %{x:,}<extra></extra>",
        ))
        fig.update_layout(
            template=PLOTLY_TEMPLATE,
            xaxis_title="Count",
            yaxis_title=None,
            margin=dict(t=10, b=10, l=10, r=10),
            height=280,
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No data available.")

# ── Sector Summary (BR-9-1) ───────────────────────────────────────────────────
st.markdown(section_header_html("SECTOR RISK"), unsafe_allow_html=True)

classified_total = sum(v["total"] for k, v in sector_stats.items() if k != "unknown")
unclassified = sector_stats.get("unknown", {}).get("total", 0)

if classified_total == 0 and unclassified > 0:
    st.info(
        f"No sector classification data found ({unclassified:,} unclassified items). "
        "Run `python -m src.main migrate-sectors` from the CLI to auto-assign sectors.",
        icon="ℹ️",
    )
elif sector_stats:
    known_sectors = {k: v for k, v in sector_stats.items() if k != "unknown"}

    sleft, sright = st.columns(2)

    with sleft:
        st.markdown(
            '<p style="font-size:11px;font-weight:600;color:#5C5C72;letter-spacing:0.5px;'
            'text-transform:uppercase;margin-bottom:8px">Threat Volume by Sector</p>',
            unsafe_allow_html=True,
        )
        if known_sectors:
            s_labels = [SECTOR_LABELS.get(k, k) for k in known_sectors]
            s_totals = [v["total"] for v in known_sectors.values()]
            s_criti = [v["critical_high"] for v in known_sectors.values()]

            fig = go.Figure()
            fig.add_trace(go.Bar(
                name="Critical / High",
                y=s_labels,
                x=s_criti,
                orientation="h",
                marker_color="#C41E3A",
                opacity=0.9,
                hovertemplate="%{y}: %{x:,} (Critical / High)<extra></extra>",
            ))
            fig.add_trace(go.Bar(
                name="Other",
                y=s_labels,
                x=[t - c for t, c in zip(s_totals, s_criti)],
                orientation="h",
                marker_color=[SECTOR_COLORS.get(k, "#9E9E9E") for k in known_sectors],
                opacity=0.45,
                hovertemplate="%{y}: %{x:,} (Medium and below)<extra></extra>",
            ))
            fig.update_layout(
                template=PLOTLY_TEMPLATE,
                barmode="stack",
                xaxis_title="Count",
                yaxis_title=None,
                margin=dict(t=10, b=10, l=10, r=10),
                height=360,
                legend=dict(orientation="h", yanchor="bottom", y=-0.2),
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No sector classification data available.")

    with sright:
        st.markdown(
            '<p style="font-size:11px;font-weight:600;color:#5C5C72;letter-spacing:0.5px;'
            'text-transform:uppercase;margin-bottom:8px">Sector Risk Ranking — Top 8</p>',
            unsafe_allow_html=True,
        )
        if known_sectors:
            sorted_sectors = sorted(
                known_sectors.items(),
                key=lambda x: x[1]["critical_high"],
                reverse=True,
            )[:8]
            rank_data = []
            for rank, (sector, vals) in enumerate(sorted_sectors, start=1):
                rank_data.append({
                    "Rank": rank,
                    "Sector": SECTOR_LABELS.get(sector, sector),
                    "Critical / High": vals["critical_high"],
                    "Total": vals["total"],
                })
            st.dataframe(rank_data, use_container_width=True, hide_index=True)
            if unclassified > 0:
                st.caption(f"Note: {unclassified:,} unclassified items excluded from ranking.")
        else:
            st.info("No data available.")

# ── Recent collection runs ────────────────────────────────────────────────────
st.markdown(section_header_html("COLLECTION HISTORY"), unsafe_allow_html=True)
if recent_runs:
    run_data = []
    for r in recent_runs[:10]:
        run_data.append({
            "Source": r.get("source", ""),
            "Started": format_date(r.get("started_at")),
            "Collected": r.get("items_collected", 0),
            "New": r.get("items_new", 0),
            "Status": "Success" if r.get("success") else "Failed",
        })
    st.dataframe(run_data, use_container_width=True, hide_index=True)
else:
    st.info("No collection history found.")
