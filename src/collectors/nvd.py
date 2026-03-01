"""
NVD (National Vulnerability Database) Collector.

Fetches CVE vulnerability data via NVD API 2.0, filtered for AI/ML keywords.
Rate Limits: Without API key: 5 req/30s; With key: 50 req/30s
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from ..models.enums import (
    ConfidenceLevel,
    SourceType,
    classify_threat_category,
    severity_from_cvss,
)
from ..models.threat import AffectedProduct, ThreatIntelItem, ThreatReference
from .base import BaseCollector


class NVDCollector(BaseCollector):
    SOURCE_NAME = "nvd"
    SOURCE_DESCRIPTION = "NIST National Vulnerability Database (CVE)"

    async def collect(self, since: Optional[datetime] = None) -> List[ThreatIntelItem]:
        if since is None:
            since = datetime.now(timezone.utc) - timedelta(days=7)

        items: List[ThreatIntelItem] = []
        cfg = self.config.nvd

        for keyword in cfg.ai_keywords:
            self.logger.info("nvd_keyword_search", keyword=keyword)
            try:
                keyword_items = await self._search_keyword(keyword, since)
                items.extend(keyword_items)
            except Exception as e:
                self.logger.warning("nvd_keyword_error", keyword=keyword, error=str(e))

            delay = 0.6 if cfg.api_key else cfg.rate_limit_delay
            await self.rate_limit_delay(delay)

        # Deduplicate by CVE ID
        seen: set = set()
        unique_items = []
        for item in items:
            if item.source_id not in seen:
                seen.add(item.source_id)
                unique_items.append(item)

        self.logger.info("nvd_collection_done", total=len(unique_items), raw=len(items))
        return unique_items

    async def _search_keyword(self, keyword: str, since: datetime) -> List[ThreatIntelItem]:
        cfg = self.config.nvd
        params: Dict[str, Any] = {
            "keywordSearch": keyword,
            "keywordExactMatch": "",
            "pubStartDate": since.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": cfg.results_per_page,
            "startIndex": 0,
        }

        headers: Dict[str, str] = {}
        if cfg.api_key:
            headers["apiKey"] = cfg.api_key

        data = await self.fetch_json(cfg.base_url, params=params, extra_headers=headers)
        return self._parse_response(data)

    def _parse_response(self, data: Dict[str, Any]) -> List[ThreatIntelItem]:
        items = []
        for vuln_wrapper in data.get("vulnerabilities", []):
            cve = vuln_wrapper.get("cve", {})
            try:
                item = self._parse_cve(cve)
                if item:
                    items.append(item)
            except Exception as e:
                cve_id = cve.get("id", "unknown")
                self.logger.warning("nvd_parse_error", cve_id=cve_id, error=str(e))
        return items

    def _parse_cve(self, cve: Dict[str, Any]) -> Optional[ThreatIntelItem]:
        cve_id = cve.get("id", "")
        if not cve_id:
            return None

        descriptions = cve.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break
        if not description and descriptions:
            description = descriptions[0].get("value", "")

        cvss_score = None
        metrics = cve.get("metrics", {})
        for version_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            metric_list = metrics.get(version_key, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                break

        refs = []
        for ref in cve.get("references", []):
            refs.append(ThreatReference(
                ref_type="url",
                ref_id=ref.get("url", ""),
                url=ref.get("url"),
                description=", ".join(ref.get("tags", [])),
            ))

        affected = self._extract_affected_products(cve)

        published = cve.get("published")
        modified = cve.get("lastModified")
        full_text = f"{cve_id} {description}"

        return ThreatIntelItem(
            source=self.SOURCE_NAME,
            source_type=SourceType.VULNERABILITY_DB,
            source_id=cve_id,
            source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            title=cve_id,
            description=description,
            raw_content=cve,
            threat_category=classify_threat_category(full_text),
            severity=severity_from_cvss(cvss_score),
            cvss_score=cvss_score,
            confidence=ConfidenceLevel.CONFIRMED,
            cve_ids=[cve_id],
            references=refs,
            affected_products=affected,
            published_at=datetime.fromisoformat(published.replace("Z", "+00:00")) if published else None,
            modified_at=datetime.fromisoformat(modified.replace("Z", "+00:00")) if modified else None,
        )

    def _extract_affected_products(self, cve: Dict[str, Any]) -> List[AffectedProduct]:
        products = []
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    if cpe_match.get("vulnerable", False):
                        cpe = cpe_match.get("criteria", "")
                        parts = cpe.split(":")
                        if len(parts) >= 5:
                            products.append(AffectedProduct(
                                vendor=parts[3] if parts[3] != "*" else None,
                                product=parts[4] if parts[4] != "*" else "unknown",
                                cpe=cpe,
                                version_start=cpe_match.get("versionStartIncluding"),
                                version_end=cpe_match.get("versionEndExcluding"),
                            ))
        return products
