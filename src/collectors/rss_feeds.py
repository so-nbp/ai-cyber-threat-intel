"""
RSS Feed Collector for security vendor blogs, government advisories, and AI sources.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from time import mktime
from typing import Any, Dict, List, Optional

import feedparser

from ..models.enums import ConfidenceLevel, SourceType, classify_threat_category
from ..models.threat import ThreatIntelItem, ThreatReference
from ..utils.config import load_rss_sources
from .base import BaseCollector

CATEGORY_MAP = {
    "threat-intel": SourceType.THREAT_INTEL_FEED,
    "news": SourceType.NEWS,
    "government": SourceType.GOVERNMENT,
    "advisory": SourceType.ADVISORY,
    "vendor-blog": SourceType.VENDOR_BLOG,
    "research": SourceType.RESEARCH_PAPER,
}

HTML_TAG_RE = re.compile(r"<[^>]+>")


class RSSFeedCollector(BaseCollector):
    SOURCE_NAME = "rss_feeds"
    SOURCE_DESCRIPTION = "Security vendor blogs, advisories, and news via RSS/Atom"

    async def collect(self, since: Optional[datetime] = None) -> List[ThreatIntelItem]:
        if since is None:
            since = datetime.now(timezone.utc) - timedelta(days=3)

        sources = load_rss_sources()
        items: List[ThreatIntelItem] = []

        for group_name, feeds in sources.items():
            if not isinstance(feeds, list):
                continue
            self.logger.info("rss_group", group=group_name, feed_count=len(feeds))
            for feed_cfg in feeds:
                try:
                    feed_items = await self._collect_feed(feed_cfg, since)
                    items.extend(feed_items)
                except Exception as e:
                    self.logger.warning(
                        "rss_feed_error",
                        feed=feed_cfg.get("name", "unknown"),
                        error=str(e),
                    )
                await self.rate_limit_delay(1.0)

        seen: set = set()
        unique = []
        for item in items:
            key = item.source_url or item.source_id
            if key not in seen:
                seen.add(key)
                unique.append(item)

        self.logger.info("rss_done", total=len(unique))
        return unique

    async def _collect_feed(self, feed_cfg: Dict[str, str], since: datetime) -> List[ThreatIntelItem]:
        name = feed_cfg.get("name", "unknown")
        url = feed_cfg.get("url", "")
        category = feed_cfg.get("category", "news")

        if not url:
            return []

        self.logger.debug("rss_fetching", feed=name, url=url)

        try:
            text = await self.fetch_text(url)
            feed = feedparser.parse(text)
        except Exception as e:
            self.logger.warning("rss_fetch_error", feed=name, error=str(e))
            return []

        items = []
        max_entries = self.config.rss.max_entries_per_feed

        for entry in feed.entries[:max_entries]:
            try:
                item = self._parse_entry(entry, name, category, since)
                if item:
                    items.append(item)
            except Exception as e:
                self.logger.debug("rss_entry_error", feed=name, error=str(e))

        self.logger.debug("rss_feed_items", feed=name, count=len(items))
        return items

    def _parse_entry(self, entry: Any, feed_name: str, category: str,
                     since: datetime) -> Optional[ThreatIntelItem]:
        published = None
        if hasattr(entry, "published_parsed") and entry.published_parsed:
            published = datetime.fromtimestamp(mktime(entry.published_parsed), tz=timezone.utc)
        elif hasattr(entry, "updated_parsed") and entry.updated_parsed:
            published = datetime.fromtimestamp(mktime(entry.updated_parsed), tz=timezone.utc)

        if published and published < since:
            return None

        title = getattr(entry, "title", "Untitled")
        link = getattr(entry, "link", "")
        entry_id = getattr(entry, "id", link or title)

        description = ""
        if hasattr(entry, "summary"):
            description = entry.summary
        elif hasattr(entry, "description"):
            description = entry.description

        description = HTML_TAG_RE.sub("", description).strip()

        tags = [feed_name, category]
        if hasattr(entry, "tags"):
            for tag in entry.tags:
                term = tag.get("term", "")
                if term:
                    tags.append(term.lower())

        full_text = f"{title} {description}"
        threat_cat = classify_threat_category(full_text)
        source_type = CATEGORY_MAP.get(category, SourceType.NEWS)

        confidence_map = {
            SourceType.GOVERNMENT: ConfidenceLevel.CONFIRMED,
            SourceType.THREAT_INTEL_FEED: ConfidenceLevel.PROBABLE,
            SourceType.ADVISORY: ConfidenceLevel.CONFIRMED,
            SourceType.VENDOR_BLOG: ConfidenceLevel.PROBABLE,
            SourceType.RESEARCH_PAPER: ConfidenceLevel.POSSIBLE,
            SourceType.NEWS: ConfidenceLevel.POSSIBLE,
        }

        return ThreatIntelItem(
            source=self.SOURCE_NAME,
            source_type=source_type,
            source_id=entry_id,
            source_url=link if link else None,
            title=f"[{feed_name}] {title}",
            description=description[:2000],
            threat_category=threat_cat,
            confidence=confidence_map.get(source_type, ConfidenceLevel.UNVERIFIED),
            tags=tags,
            references=[ThreatReference(ref_type="url", ref_id=link, url=link)] if link else [],
            published_at=published,
        )
