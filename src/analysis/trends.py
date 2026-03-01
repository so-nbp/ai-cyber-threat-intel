"""Basic trend analysis for collected threat intelligence."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from ..storage.database import ThreatDatabase
from ..utils.logging import get_logger

logger = get_logger("analysis.trends")


def generate_daily_summary(db: ThreatDatabase, date: Optional[datetime] = None) -> Dict[str, Any]:
    if date is None:
        date = datetime.now(timezone.utc)

    start = date.replace(hour=0, minute=0, second=0, microsecond=0)
    end = start + timedelta(days=1)

    items = db.get_items(since=start, limit=10000)
    day_items = [i for i in items if i.get("collected_at", "") < end.isoformat()]

    if not day_items:
        return {"date": start.strftime("%Y-%m-%d"), "total_items": 0, "message": "No items collected."}

    sources = Counter(i["source"] for i in day_items)
    categories = Counter(i["threat_category"] for i in day_items)
    severities = Counter(i["severity"] for i in day_items)
    ai_related = sum(1 for i in day_items if i.get("is_ai_related"))

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
    sorted_items = sorted(day_items, key=lambda x: severity_order.get(x.get("severity", "unknown"), 5))
    top_items = [
        {"title": i["title"], "severity": i["severity"], "category": i["threat_category"],
         "source": i["source"], "url": i.get("source_url")}
        for i in sorted_items[:10]
    ]

    return {
        "date": start.strftime("%Y-%m-%d"),
        "total_items": len(day_items),
        "ai_related_items": ai_related,
        "by_source": dict(sources),
        "by_category": dict(categories),
        "by_severity": dict(severities),
        "top_items": top_items,
    }
