"""
Shared helpers for the Streamlit dashboard.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, Optional

import streamlit as st

# Ensure the project root is on sys.path when running via `streamlit run`
_ROOT = Path(__file__).parent.parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from src.storage.database import ThreatDatabase  # noqa: E402
from src.utils.config import load_config  # noqa: E402

# ── Severity color map ──────────────────────────────────────────────────────
SEVERITY_COLORS: Dict[str, str] = {
    "critical": "#e53935",
    "high": "#fb8c00",
    "medium": "#fdd835",
    "low": "#43a047",
    "info": "#1e88e5",
    "unknown": "#9e9e9e",
}

SEVERITY_BADGE: Dict[str, str] = {
    "critical": "🔴 CRITICAL",
    "high": "🟠 HIGH",
    "medium": "🟡 MEDIUM",
    "low": "🟢 LOW",
    "info": "🔵 INFO",
    "unknown": "⚫ UNKNOWN",
}

# ── Category labels ─────────────────────────────────────────────────────────
CATEGORY_LABELS: Dict[str, str] = {
    "ai-as-target": "AI-as-Target",
    "ai-as-weapon": "AI-as-Weapon",
    "ai-enabled": "AI-Enabled",
    "ai-adjacent": "AI-Adjacent",
    "ai-physical": "AI-Physical",
    "ai-supply-chain": "AI-Supply-Chain",
    "ai-agentic": "AI-Agentic",
    "traditional": "Traditional",
    "unknown": "Unknown",
}

# ── Sector labels & colors ──────────────────────────────────────────────────
SECTOR_LABELS: Dict[str, str] = {
    "energy": "⚡ エネルギー",
    "financial": "🏦 金融",
    "healthcare": "🏥 医療・ヘルスケア",
    "telecommunications": "📡 通信・情報通信",
    "transportation": "✈️ 交通・物流",
    "government": "🏛️ 政府・行政",
    "defense": "🛡️ 防衛・宇宙",
    "technology": "💻 情報技術・IT",
    "manufacturing": "🏭 製造業",
    "education": "🎓 教育・研究",
    "general": "🛒 小売・食品・その他",
    "unknown": "❓ 分類不明",
}

SECTOR_COLORS: Dict[str, str] = {
    "energy": "#ff6f00",
    "financial": "#1565c0",
    "healthcare": "#2e7d32",
    "telecommunications": "#6a1b9a",
    "transportation": "#00695c",
    "government": "#283593",
    "defense": "#4e342e",
    "technology": "#0277bd",
    "manufacturing": "#558b2f",
    "education": "#ad1457",
    "general": "#795548",
    "unknown": "#9e9e9e",
}

CATEGORY_COLORS: Dict[str, str] = {
    "ai-as-target": "#e53935",
    "ai-as-weapon": "#8e24aa",
    "ai-enabled": "#1e88e5",
    "ai-adjacent": "#00acc1",
    "ai-physical": "#fb8c00",
    "ai-supply-chain": "#43a047",
    "ai-agentic": "#f06292",
    "traditional": "#9e9e9e",
    "unknown": "#bdbdbd",
}


@st.cache_resource
def get_db() -> ThreatDatabase:
    """Return a cached ThreatDatabase instance."""
    cfg = load_config(None)
    db = ThreatDatabase(cfg.storage.db_path)
    db.initialize()
    return db


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


def severity_badge_html(severity: str) -> str:
    """Return an HTML span styled as a severity badge."""
    color = SEVERITY_COLORS.get(severity, "#9e9e9e")
    label = SEVERITY_BADGE.get(severity, severity.upper())
    return (
        f'<span style="background:{color};color:white;padding:2px 8px;'
        f'border-radius:4px;font-size:0.8em;font-weight:bold">{label}</span>'
    )


def go_to_detail(item_id: int) -> None:
    """Navigate to the detail page for the given item ID."""
    st.query_params["page"] = "detail"
    st.query_params["id"] = str(item_id)
