"""
GitHub Security Advisory Collector.

Fetches security advisories related to AI/ML packages via GitHub REST API.
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


class GitHubAdvisoryCollector(BaseCollector):
    SOURCE_NAME = "github_advisory"
    SOURCE_DESCRIPTION = "GitHub Security Advisory Database (AI/ML packages)"

    API_URL = "https://api.github.com/advisories"

    async def collect(self, since: Optional[datetime] = None) -> List[ThreatIntelItem]:
        if since is None:
            since = datetime.now(timezone.utc) - timedelta(days=7)

        cfg = self.config.github
        items: List[ThreatIntelItem] = []

        headers: Dict[str, str] = {"Accept": "application/vnd.github+json"}
        if cfg.token:
            headers["Authorization"] = f"Bearer {cfg.token}"

        try:
            advisories = await self._fetch_advisories(since, headers)
            for adv in advisories:
                item = self._parse_advisory(adv, cfg.ai_package_keywords)
                if item:
                    items.append(item)
        except Exception as e:
            self.logger.error("github_advisory_error", error=str(e))
            raise

        self.logger.info("github_advisory_done", count=len(items))
        return items

    async def _fetch_advisories(self, since: datetime, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        all_advisories: List[Dict[str, Any]] = []
        params: Dict[str, Any] = {
            "type": "reviewed",
            "updated": f">={since.strftime('%Y-%m-%d')}",
            "per_page": 100,
        }

        page = 1
        while page <= 5:
            params["page"] = page
            session = await self._get_session()
            async with session.get(self.API_URL, params=params, headers=headers) as resp:
                resp.raise_for_status()
                data = await resp.json()

            if not data:
                break

            all_advisories.extend(data)
            page += 1
            await self.rate_limit_delay(1.0)

        return all_advisories

    def _parse_advisory(self, adv: Dict[str, Any], ai_keywords: List[str]) -> Optional[ThreatIntelItem]:
        ghsa_id = adv.get("ghsa_id", "")
        summary = adv.get("summary", "")
        description = adv.get("description", "")

        cvss_score = None
        if adv.get("cvss"):
            cvss_score = adv["cvss"].get("score")

        vulnerabilities = adv.get("vulnerabilities", [])
        is_ai_related = False
        affected_products = []

        for vuln in vulnerabilities:
            pkg = vuln.get("package", {})
            pkg_name = pkg.get("name", "").lower()
            pkg_ecosystem = pkg.get("ecosystem", "").lower()

            for keyword in ai_keywords:
                if keyword.lower() in pkg_name:
                    is_ai_related = True
                    break

            affected_products.append(AffectedProduct(
                vendor=pkg_ecosystem,
                product=pkg.get("name", "unknown"),
                version_start=vuln.get("vulnerable_version_range", ""),
                version_end=vuln.get("patched_versions"),
            ))

        full_text = f"{summary} {description}"
        threat_cat = classify_threat_category(full_text)
        if threat_cat.value != "unknown":
            is_ai_related = True

        if not is_ai_related:
            return None

        cve_ids = [
            ident.get("value", "")
            for ident in adv.get("identifiers", [])
            if ident.get("type") == "CVE"
        ]

        references = [ThreatReference(ref_type="ghsa", ref_id=ghsa_id, url=adv.get("html_url"))]
        for cve_id in cve_ids:
            references.append(ThreatReference(
                ref_type="cve", ref_id=cve_id,
                url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            ))

        published = adv.get("published_at")
        updated = adv.get("updated_at")
        severity_str = adv.get("severity", "")

        return ThreatIntelItem(
            source=self.SOURCE_NAME,
            source_type=SourceType.ADVISORY,
            source_id=ghsa_id,
            source_url=adv.get("html_url"),
            title=f"[GHSA] {summary}",
            description=description or summary,
            raw_content=adv,
            threat_category=threat_cat,
            severity=severity_from_cvss(cvss_score),
            cvss_score=cvss_score,
            confidence=ConfidenceLevel.CONFIRMED,
            tags=["github-advisory", severity_str] if severity_str else ["github-advisory"],
            cve_ids=cve_ids,
            references=references,
            affected_products=affected_products,
            published_at=datetime.fromisoformat(published.replace("Z", "+00:00")) if published else None,
            modified_at=datetime.fromisoformat(updated.replace("Z", "+00:00")) if updated else None,
        )
