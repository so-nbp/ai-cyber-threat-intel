"""
CISA KEV (Known Exploited Vulnerabilities) Collector.
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
from ..models.threat import AffectedProduct, ThreatIntelItem, ThreatReference
from .base import BaseCollector


class CISAKEVCollector(BaseCollector):
    SOURCE_NAME = "cisa_kev"
    SOURCE_DESCRIPTION = "CISA Known Exploited Vulnerabilities Catalog"

    async def collect(self, since: Optional[datetime] = None) -> List[ThreatIntelItem]:
        if since is None:
            since = datetime.now(timezone.utc) - timedelta(days=30)

        self.logger.info("cisa_kev_fetching")
        data = await self.fetch_json(self.config.cisa.kev_url)

        vulnerabilities = data.get("vulnerabilities", [])
        self.logger.info("cisa_kev_total", count=len(vulnerabilities))

        items = []
        for vuln in vulnerabilities:
            try:
                item = self._parse_vulnerability(vuln, since)
                if item:
                    items.append(item)
            except Exception as e:
                cve_id = vuln.get("cveID", "unknown")
                self.logger.warning("cisa_kev_parse_error", cve_id=cve_id, error=str(e))

        self.logger.info("cisa_kev_filtered", count=len(items))
        return items

    def _parse_vulnerability(self, vuln: Dict[str, Any], since: datetime) -> Optional[ThreatIntelItem]:
        date_added_str = vuln.get("dateAdded", "")
        if date_added_str:
            date_added = datetime.strptime(date_added_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            if date_added < since:
                return None

        cve_id = vuln.get("cveID", "")
        vendor = vuln.get("vendorProject", "")
        product = vuln.get("product", "")
        name = vuln.get("vulnerabilityName", "")
        description = vuln.get("shortDescription", "")
        action = vuln.get("requiredAction", "")
        due_date = vuln.get("dueDate", "")

        full_text = f"{vendor} {product} {name} {description}"

        return ThreatIntelItem(
            source=self.SOURCE_NAME,
            source_type=SourceType.GOVERNMENT,
            source_id=cve_id,
            source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            title=f"[CISA KEV] {cve_id}: {name}",
            description=f"{description}\n\nRequired Action: {action}\nDue Date: {due_date}",
            raw_content=vuln,
            threat_category=classify_threat_category(full_text),
            severity=Severity.HIGH,
            confidence=ConfidenceLevel.CONFIRMED,
            tags=["actively-exploited", "cisa-kev"],
            cve_ids=[cve_id] if cve_id else [],
            affected_products=[AffectedProduct(vendor=vendor, product=product)] if product else [],
            references=[ThreatReference(
                ref_type="cve", ref_id=cve_id,
                url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            )],
            published_at=datetime.strptime(date_added_str, "%Y-%m-%d").replace(tzinfo=timezone.utc) if date_added_str else None,
        )
