"""
AlienVault OTX (Open Threat Exchange) Collector.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from ..models.enums import (
    ConfidenceLevel,
    Severity,
    SourceType,
    classify_threat_category,
)
from ..models.threat import ThreatIntelItem, ThreatReference
from .base import BaseCollector


class OTXCollector(BaseCollector):
    SOURCE_NAME = "otx"
    SOURCE_DESCRIPTION = "AlienVault Open Threat Exchange (OTX)"

    AI_SEARCH_TERMS = [
        "artificial intelligence", "machine learning", "LLM",
        "GPT", "neural network", "deep learning", "tensorflow",
        "pytorch", "AI attack", "prompt injection",
    ]

    async def collect(self, since: Optional[datetime] = None) -> List[ThreatIntelItem]:
        cfg = self.config.otx
        if not cfg.api_key:
            self.logger.warning("otx_no_api_key", msg="Skipping OTX (no API key configured)")
            return []

        if since is None:
            since = datetime.now(timezone.utc) - timedelta(days=cfg.pulse_days)

        items: List[ThreatIntelItem] = []

        for term in self.AI_SEARCH_TERMS:
            try:
                pulses = await self._search_pulses(term, cfg.api_key)
                for pulse in pulses:
                    item = self._parse_pulse(pulse, since)
                    if item:
                        items.append(item)
            except Exception as e:
                self.logger.warning("otx_search_error", term=term, error=str(e))
            await self.rate_limit_delay(1.0)

        seen: set = set()
        unique = []
        for i in items:
            if i.source_id not in seen:
                seen.add(i.source_id)
                unique.append(i)

        self.logger.info("otx_done", count=len(unique))
        return unique

    async def _search_pulses(self, query: str, api_key: str) -> List[Dict[str, Any]]:
        url = f"{self.config.otx.base_url}/search/pulses"
        params = {"q": query, "page": 1, "limit": 20}
        headers = {"X-OTX-API-KEY": api_key}

        data = await self.fetch_json(url, params=params, extra_headers=headers)
        return data.get("results", [])

    def _parse_pulse(self, pulse: Dict[str, Any], since: datetime) -> Optional[ThreatIntelItem]:
        created = pulse.get("created")
        if created:
            created_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
            if created_dt < since:
                return None

        pulse_id = pulse.get("id", "")
        name = pulse.get("name", "")
        description = pulse.get("description", "")
        tags = pulse.get("tags", [])
        tlp = pulse.get("tlp", "")
        indicator_count = len(pulse.get("indicators", []))

        refs = []
        for ref_url in pulse.get("references", []):
            refs.append(ThreatReference(ref_type="url", ref_id=ref_url, url=ref_url))

        cve_ids = []
        for indicator in pulse.get("indicators", []):
            if indicator.get("type") == "CVE":
                cve_ids.append(indicator.get("indicator", ""))

        full_text = f"{name} {description} {' '.join(tags)}"

        modified = pulse.get("modified")

        return ThreatIntelItem(
            source=self.SOURCE_NAME,
            source_type=SourceType.THREAT_INTEL_FEED,
            source_id=pulse_id,
            source_url=f"https://otx.alienvault.com/pulse/{pulse_id}",
            title=f"[OTX] {name}",
            description=f"{description}\n\nIndicators: {indicator_count}, TLP: {tlp}",
            raw_content=pulse,
            threat_category=classify_threat_category(full_text),
            severity=Severity.MEDIUM,
            confidence=ConfidenceLevel.PROBABLE,
            tags=["otx", tlp] + tags[:10],
            cve_ids=cve_ids,
            references=refs,
            published_at=datetime.fromisoformat(created.replace("Z", "+00:00")) if created else None,
            modified_at=datetime.fromisoformat(modified.replace("Z", "+00:00")) if modified else None,
        )
