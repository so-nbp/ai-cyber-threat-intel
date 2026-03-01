"""
arXiv Research Paper Collector for AI security topics.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from typing import List, Optional
from urllib.parse import quote

from ..models.enums import ConfidenceLevel, SourceType, classify_threat_category
from ..models.threat import ThreatIntelItem, ThreatReference
from .base import BaseCollector

ATOM_NS = "http://www.w3.org/2005/Atom"
ARXIV_NS = "http://arxiv.org/schemas/atom"


class ArxivCollector(BaseCollector):
    SOURCE_NAME = "arxiv"
    SOURCE_DESCRIPTION = "arXiv preprint server (AI security research)"

    async def collect(self, since: Optional[datetime] = None) -> List[ThreatIntelItem]:
        if since is None:
            since = datetime.now(timezone.utc) - timedelta(days=7)

        cfg = self.config.arxiv
        items: List[ThreatIntelItem] = []

        for query in cfg.search_queries:
            self.logger.info("arxiv_search", query=query)
            try:
                query_items = await self._search(query, cfg.max_results_per_query)
                items.extend(query_items)
            except Exception as e:
                self.logger.warning("arxiv_search_error", query=query, error=str(e))
            await self.rate_limit_delay(3.0)

        seen: set = set()
        unique_items = []
        for item in items:
            if item.source_id not in seen:
                seen.add(item.source_id)
                unique_items.append(item)

        self.logger.info("arxiv_done", total=len(unique_items), raw=len(items))
        return unique_items

    async def _search(self, query: str, max_results: int) -> List[ThreatIntelItem]:
        cfg = self.config.arxiv
        cat_filter = " OR ".join(f"cat:{cat}" for cat in cfg.categories)
        full_query = f"all:{quote(query)} AND ({cat_filter})"

        params = {
            "search_query": full_query,
            "start": 0,
            "max_results": max_results,
            "sortBy": "submittedDate",
            "sortOrder": "descending",
        }

        text = await self.fetch_text(cfg.base_url, params=params)
        return self._parse_atom_feed(text, query)

    def _parse_atom_feed(self, xml_text: str, search_query: str) -> List[ThreatIntelItem]:
        items = []
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError as e:
            self.logger.error("arxiv_xml_parse_error", error=str(e))
            return items

        for entry in root.findall(f"{{{ATOM_NS}}}entry"):
            try:
                item = self._parse_entry(entry, search_query)
                if item:
                    items.append(item)
            except Exception as e:
                self.logger.warning("arxiv_entry_error", error=str(e))

        return items

    def _parse_entry(self, entry: ET.Element, search_query: str) -> Optional[ThreatIntelItem]:
        id_elem = entry.find(f"{{{ATOM_NS}}}id")
        if id_elem is None or id_elem.text is None:
            return None
        arxiv_url = id_elem.text.strip()
        arxiv_id = arxiv_url.split("/abs/")[-1]

        title_elem = entry.find(f"{{{ATOM_NS}}}title")
        title = title_elem.text.strip().replace("\n", " ") if title_elem is not None and title_elem.text else ""

        summary_elem = entry.find(f"{{{ATOM_NS}}}summary")
        summary = summary_elem.text.strip().replace("\n", " ") if summary_elem is not None and summary_elem.text else ""

        authors = []
        for author_elem in entry.findall(f"{{{ATOM_NS}}}author"):
            name_elem = author_elem.find(f"{{{ATOM_NS}}}name")
            if name_elem is not None and name_elem.text:
                authors.append(name_elem.text.strip())

        categories = []
        for cat_elem in entry.findall(f"{{{ARXIV_NS}}}primary_category"):
            term = cat_elem.get("term", "")
            if term:
                categories.append(term)
        for cat_elem in entry.findall(f"{{{ATOM_NS}}}category"):
            term = cat_elem.get("term", "")
            if term and term not in categories:
                categories.append(term)

        published_elem = entry.find(f"{{{ATOM_NS}}}published")
        published = None
        if published_elem is not None and published_elem.text:
            published = datetime.fromisoformat(published_elem.text.replace("Z", "+00:00"))

        updated_elem = entry.find(f"{{{ATOM_NS}}}updated")
        updated = None
        if updated_elem is not None and updated_elem.text:
            updated = datetime.fromisoformat(updated_elem.text.replace("Z", "+00:00"))

        pdf_url = None
        for link_elem in entry.findall(f"{{{ATOM_NS}}}link"):
            if link_elem.get("title") == "pdf":
                pdf_url = link_elem.get("href")

        full_text = f"{title} {summary}"
        threat_cat = classify_threat_category(full_text)
        tags = ["research", "preprint"] + categories
        tags.append(f"search:{search_query}")

        author_str = ", ".join(authors[:5])
        if len(authors) > 5:
            author_str += "..."

        references = [ThreatReference(ref_type="arxiv", ref_id=arxiv_id, url=arxiv_url)]
        if pdf_url:
            references.append(ThreatReference(ref_type="pdf", ref_id=arxiv_id, url=pdf_url))

        return ThreatIntelItem(
            source=self.SOURCE_NAME,
            source_type=SourceType.RESEARCH_PAPER,
            source_id=arxiv_id,
            source_url=arxiv_url,
            title=f"[arXiv] {title}",
            description=f"{summary}\n\nAuthors: {author_str}",
            threat_category=threat_cat,
            confidence=ConfidenceLevel.POSSIBLE,
            tags=tags,
            keywords=authors[:5],
            references=references,
            published_at=published,
            modified_at=updated,
        )
