"""
Shared helpers and design system for the Streamlit dashboard.
"""

from __future__ import annotations

import html
import json
import sys
from pathlib import Path
from typing import Any, Dict, Optional

import plotly.graph_objects as go
import plotly.io as pio
import streamlit as st

# Ensure the project root is on sys.path when running via `streamlit run`
_ROOT = Path(__file__).parent.parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from src.storage.database import ThreatDatabase  # noqa: E402
from src.utils.config import load_config  # noqa: E402

# ────────────────────────────────────────────────────────────────────────────
# McKinsey Light Theme — Color Palette
# ────────────────────────────────────────────────────────────────────────────
COLORS: Dict[str, str] = {
    "bg_page":      "#F4F4F0",  # Warm Gray — page background
    "bg_card":      "#FFFFFF",  # White — card / panel background
    "bg_sidebar":   "#002F6C",  # McKinsey Navy — sidebar
    "text_primary": "#1A1A2E",  # Near Black
    "text_muted":   "#5C5C72",  # Medium Gray
    "text_on_dark": "#FFFFFF",  # Text on dark backgrounds
    "accent_navy":  "#002F6C",  # McKinsey Navy
    "accent_blue":  "#2251FF",  # McKinsey Blue
    "accent_hover": "#E8EEFF",  # Light Blue hover / highlight
    "border":       "#E0E0DA",  # Subtle border
}

# ── Severity ─────────────────────────────────────────────────────────────────
SEVERITY_COLORS: Dict[str, str] = {
    "critical": "#C41E3A",
    "high":     "#D4660A",
    "medium":   "#9A7000",
    "low":      "#2E7D32",
    "info":     "#1565C0",
    "unknown":  "#757575",
}

SEVERITY_LABELS: Dict[str, str] = {
    "critical": "CRITICAL",
    "high":     "HIGH",
    "medium":   "MEDIUM",
    "low":      "LOW",
    "info":     "INFO",
    "unknown":  "UNKNOWN",
}

# ── Category ─────────────────────────────────────────────────────────────────
CATEGORY_LABELS: Dict[str, str] = {
    "ai-as-target":    "AI-as-Target",
    "ai-as-weapon":    "AI-as-Weapon",
    "ai-enabled":      "AI-Enabled",
    "ai-adjacent":     "AI-Adjacent",
    "ai-physical":     "AI-Physical",
    "ai-supply-chain": "AI-Supply-Chain",
    "ai-agentic":      "AI-Agentic",
    "traditional":     "Traditional",
    "unknown":         "Unknown",
}

CATEGORY_COLORS: Dict[str, str] = {
    "ai-as-target":    "#C41E3A",
    "ai-as-weapon":    "#6A1B9A",
    "ai-enabled":      "#1565C0",
    "ai-adjacent":     "#00695C",
    "ai-physical":     "#D4660A",
    "ai-supply-chain": "#2E7D32",
    "ai-agentic":      "#AD1457",
    "traditional":     "#757575",
    "unknown":         "#9E9E9E",
}

# ── Sector ────────────────────────────────────────────────────────────────────
SECTOR_LABELS: Dict[str, str] = {
    "energy":            "Energy",
    "financial":         "Financial",
    "healthcare":        "Healthcare",
    "telecommunications":"Telecom",
    "transportation":    "Transportation",
    "government":        "Government",
    "defense":           "Defense & Space",
    "technology":        "Technology",
    "manufacturing":     "Manufacturing",
    "education":         "Education & Research",
    "general":           "General",
    "unknown":           "Unknown",
}

SECTOR_COLORS: Dict[str, str] = {
    "energy":            "#B45309",
    "financial":         "#1565C0",
    "healthcare":        "#2E7D32",
    "telecommunications":"#6A1B9A",
    "transportation":    "#00695C",
    "government":        "#283593",
    "defense":           "#4E342E",
    "technology":        "#002F6C",
    "manufacturing":     "#558B2F",
    "education":         "#AD1457",
    "general":           "#546E7A",
    "unknown":           "#757575",
}

# ────────────────────────────────────────────────────────────────────────────
# Plotly Template — McKinsey style
# ────────────────────────────────────────────────────────────────────────────
_mckinsey_template = go.layout.Template(
    layout=go.Layout(
        font=dict(family="Inter, system-ui, sans-serif", color="#1A1A2E", size=12),
        paper_bgcolor="white",
        plot_bgcolor="white",
        colorway=["#002F6C", "#2251FF", "#0070C0", "#5B9BD5", "#9DC3E6", "#BDD7EE"],
        xaxis=dict(
            gridcolor="#EBEBEB",
            linecolor="#D0D0C8",
            tickfont=dict(size=11),
            showgrid=True,
        ),
        yaxis=dict(
            gridcolor="#EBEBEB",
            linecolor="#D0D0C8",
            tickfont=dict(size=11),
            showgrid=True,
        ),
        margin=dict(t=30, b=30, l=40, r=20),
        legend=dict(font=dict(size=11)),
    )
)
pio.templates["mckinsey"] = _mckinsey_template
PLOTLY_TEMPLATE = "mckinsey"

# ────────────────────────────────────────────────────────────────────────────
# Database
# ────────────────────────────────────────────────────────────────────────────
@st.cache_resource
def get_db() -> ThreatDatabase:
    """Return a cached ThreatDatabase instance."""
    cfg = load_config(None)
    db = ThreatDatabase(cfg.storage.db_path)
    db.initialize()
    return db


# ────────────────────────────────────────────────────────────────────────────
# Utilities
# ────────────────────────────────────────────────────────────────────────────
def parse_json_field(value: Any) -> list:
    """Safely parse a JSON-encoded list field from the database."""
    if not value:
        return []
    if isinstance(value, list):
        return value
    try:
        result = json.loads(value)
        return result if isinstance(result, list) else []
    except (json.JSONDecodeError, TypeError):
        return []


def format_date(value: Optional[str]) -> str:
    """Return the first 10 characters of an ISO datetime, or '—'."""
    if not value:
        return "—"
    return str(value)[:10]


def go_to_detail(item_id: int) -> None:
    """Navigate to the detail page for the given item ID."""
    st.query_params["page"] = "detail"
    st.query_params["id"] = str(item_id)


# ────────────────────────────────────────────────────────────────────────────
# Design System: CSS Injection
# ────────────────────────────────────────────────────────────────────────────
def inject_global_css() -> None:
    """Inject McKinsey-branded global CSS into the Streamlit app."""
    st.markdown(
        """<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');

/* ── Global typography ───────────────────────────────────────────────── */
html, body, [class*="css"], .stMarkdown, .stText,
.stSelectbox, .stTextInput, .stRadio, .stCheckbox, p, div, span, label {
    font-family: 'Inter', system-ui, sans-serif !important;
}

/* ── Page background ─────────────────────────────────────────────────── */
.stApp { background-color: #F4F4F0 !important; }
.main .block-container { padding-top: 1.5rem !important; }

/* ── Sidebar: McKinsey Navy ──────────────────────────────────────────── */
[data-testid="stSidebar"] {
    background-color: #002F6C !important;
}
[data-testid="stSidebar"] * {
    color: #FFFFFF !important;
}
[data-testid="stSidebar"] .stSelectbox > label,
[data-testid="stSidebar"] .stTextInput > label,
[data-testid="stSidebar"] .stCheckbox > label span,
[data-testid="stSidebar"] .stRadio > label {
    color: #B0C4DE !important;
    font-size: 10px !important;
    font-weight: 700 !important;
    letter-spacing: 0.7px !important;
    text-transform: uppercase !important;
}
[data-testid="stSidebar"] input,
[data-testid="stSidebar"] [data-baseweb="select"] > div {
    background-color: rgba(255,255,255,0.10) !important;
    border-color: rgba(255,255,255,0.25) !important;
    color: #FFFFFF !important;
}
[data-testid="stSidebar"] .stButton > button {
    background-color: rgba(255,255,255,0.12) !important;
    color: #FFFFFF !important;
    border: 1px solid rgba(255,255,255,0.30) !important;
    width: 100% !important;
}
[data-testid="stSidebar"] .stButton > button:hover {
    background-color: rgba(255,255,255,0.22) !important;
}
[data-testid="stSidebar"] h1,
[data-testid="stSidebar"] h2,
[data-testid="stSidebar"] h3 {
    color: #FFFFFF !important;
    font-size: 11px !important;
    font-weight: 700 !important;
    letter-spacing: 0.9px !important;
    text-transform: uppercase !important;
    border-bottom: 1px solid rgba(255,255,255,0.20) !important;
    padding-bottom: 8px !important;
    margin-bottom: 14px !important;
}
[data-testid="stSidebar"] hr {
    border-color: rgba(255,255,255,0.15) !important;
    margin: 8px 0 !important;
}

/* ── Page headings ───────────────────────────────────────────────────── */
h1, h2, h3 {
    color: #1A1A2E !important;
    font-weight: 700 !important;
    letter-spacing: -0.3px !important;
}
h1 {
    font-size: 22px !important;
    border-bottom: 2px solid #002F6C !important;
    padding-bottom: 10px !important;
    margin-bottom: 20px !important;
}
h2 { font-size: 18px !important; }
h3 { font-size: 15px !important; }

/* ── Metric card: McKinsey style ─────────────────────────────────────── */
[data-testid="stMetric"] {
    background-color: #FFFFFF !important;
    border-left: 3px solid #002F6C !important;
    padding: 18px 20px !important;
    border-radius: 2px !important;
    box-shadow: 0 1px 3px rgba(0,0,0,0.06) !important;
}
[data-testid="stMetricValue"] {
    font-size: 28px !important;
    font-weight: 700 !important;
    color: #1A1A2E !important;
    letter-spacing: -0.5px !important;
}
[data-testid="stMetricLabel"] {
    font-size: 10px !important;
    font-weight: 700 !important;
    letter-spacing: 0.8px !important;
    text-transform: uppercase !important;
    color: #5C5C72 !important;
}
[data-testid="stMetricDelta"] {
    font-size: 12px !important;
    font-weight: 500 !important;
}

/* ── Buttons ─────────────────────────────────────────────────────────── */
.stButton > button {
    border-radius: 2px !important;
    font-weight: 600 !important;
    font-size: 11px !important;
    letter-spacing: 0.5px !important;
    text-transform: uppercase !important;
    font-family: 'Inter', system-ui, sans-serif !important;
    transition: all 0.15s ease !important;
}

/* ── DataFrames ──────────────────────────────────────────────────────── */
[data-testid="stDataFrame"] {
    border: 1px solid #E0E0DA !important;
    border-radius: 2px !important;
}

/* ── Alerts / Info boxes ─────────────────────────────────────────────── */
[data-testid="stAlert"] {
    border-radius: 2px !important;
    border-left-width: 3px !important;
}

/* ── Expander ────────────────────────────────────────────────────────── */
[data-testid="stExpander"] {
    border: 1px solid #E0E0DA !important;
    border-radius: 2px !important;
    background: #FFFFFF !important;
}

/* ── Form controls ───────────────────────────────────────────────────── */
[data-baseweb="select"] > div,
[data-baseweb="input"] > div {
    border-radius: 2px !important;
    font-family: 'Inter', system-ui, sans-serif !important;
}

/* ── Divider ─────────────────────────────────────────────────────────── */
hr {
    border-color: #E0E0DA !important;
    margin: 12px 0 !important;
}

/* ── Caption text ────────────────────────────────────────────────────── */
[data-testid="stCaptionContainer"] {
    color: #5C5C72 !important;
    font-size: 12px !important;
}
</style>""",
        unsafe_allow_html=True,
    )


# ────────────────────────────────────────────────────────────────────────────
# Design System: HTML Components
# ────────────────────────────────────────────────────────────────────────────
def section_header_html(title: str, subtitle: str = "") -> str:
    """Return a McKinsey-styled section header as HTML."""
    sub = (
        f'<div style="font-size:12px;color:#5C5C72;margin-top:3px">'
        f'{html.escape(subtitle)}</div>'
        if subtitle
        else ""
    )
    return (
        f'<div style="margin:22px 0 14px 0">'
        f'<div style="font-size:10px;font-weight:700;letter-spacing:1px;'
        f'text-transform:uppercase;color:#5C5C72;border-bottom:1px solid #E0E0DA;'
        f'padding-bottom:7px;font-family:Inter,system-ui,sans-serif">'
        f'{html.escape(title)}</div>'
        f'{sub}</div>'
    )


def severity_badge_html(severity: str) -> str:
    """Return an HTML span styled as a professional severity badge."""
    color = SEVERITY_COLORS.get(severity, "#757575")
    label = SEVERITY_LABELS.get(severity, severity.upper())
    return (
        f'<span style="background:{color};color:#FFFFFF;padding:2px 8px;'
        f'border-radius:2px;font-size:10px;font-weight:700;'
        f'letter-spacing:0.4px;font-family:Inter,system-ui,sans-serif;'
        f'white-space:nowrap">{html.escape(label)}</span>'
    )


def category_badge_html(category: str) -> str:
    """Return an HTML span styled as a category badge."""
    label = CATEGORY_LABELS.get(category, category)
    return (
        f'<span style="background:#E8EEF5;color:#002F6C;padding:2px 8px;'
        f'border-radius:2px;font-size:10px;font-weight:600;'
        f'letter-spacing:0.3px;font-family:Inter,system-ui,sans-serif;'
        f'white-space:nowrap">{html.escape(label)}</span>'
    )


def source_badge_html(source: str) -> str:
    """Return an HTML span styled as a source badge."""
    return (
        f'<span style="background:#F0F0EC;color:#5C5C72;padding:2px 8px;'
        f'border-radius:2px;font-size:10px;font-weight:600;'
        f'letter-spacing:0.3px;font-family:Inter,system-ui,sans-serif;'
        f'white-space:nowrap">{html.escape(source)}</span>'
    )


def data_freshness_html(last_run_date: str) -> str:
    """Return an HTML data freshness indicator banner."""
    return (
        f'<div style="background:#E8EEF5;border-left:3px solid #002F6C;'
        f'padding:8px 14px;border-radius:0 2px 2px 0;'
        f'font-size:11px;color:#5C5C72;margin-bottom:20px;'
        f'font-family:Inter,system-ui,sans-serif">'
        f'<span style="font-weight:700;color:#002F6C;letter-spacing:0.6px">'
        f'DATA AS OF</span>&nbsp;&nbsp;{html.escape(last_run_date)}'
        f'</div>'
    )
