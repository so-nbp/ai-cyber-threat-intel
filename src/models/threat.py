"""
Unified Threat Intelligence data model.

All collected data is normalized to this schema regardless of source.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from .enums import (
    AffectedSector,
    ConfidenceLevel,
    Severity,
    SourceType,
    ThreatCategory,
)


class ThreatReference(BaseModel):
    """External reference (CVE, ATLAS technique, ATT&CK technique, URL, etc.)."""

    ref_type: str = ""
    ref_id: str = ""
    url: Optional[str] = None
    description: Optional[str] = None


class AffectedProduct(BaseModel):
    """Affected software/product information."""

    vendor: Optional[str] = None
    product: str = "unknown"
    version_start: Optional[str] = None
    version_end: Optional[str] = None
    cpe: Optional[str] = None


def _make_item_hash(source: str, source_id: str) -> str:
    """Deterministic hash for deduplication."""
    key = f"{source}:{source_id}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


class ThreatIntelItem(BaseModel):
    """
    Unified threat intelligence item.

    This is the core data model that all collectors normalize their data into.
    """

    # ── Identity ──
    source: str = ""
    source_type: SourceType = SourceType.NEWS
    source_id: str = ""
    source_url: Optional[str] = None

    # ── Content ──
    title: str = ""
    description: str = ""
    raw_content: Optional[Dict[str, Any]] = Field(default=None, exclude=True)

    # ── Classification ──
    threat_category: ThreatCategory = ThreatCategory.UNKNOWN
    severity: Severity = Severity.UNKNOWN
    cvss_score: Optional[float] = None
    confidence: ConfidenceLevel = ConfidenceLevel.UNVERIFIED
    tags: List[str] = Field(default_factory=list)
    keywords: List[str] = Field(default_factory=list)

    # ── Mapping ──
    atlas_techniques: List[str] = Field(default_factory=list)
    attck_techniques: List[str] = Field(default_factory=list)
    affected_sectors: List[AffectedSector] = Field(default_factory=list)
    affected_products: List[AffectedProduct] = Field(default_factory=list)

    # ── References ──
    references: List[ThreatReference] = Field(default_factory=list)
    cve_ids: List[str] = Field(default_factory=list)

    # ── Temporal ──
    published_at: Optional[datetime] = None
    modified_at: Optional[datetime] = None
    collected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # ── Computed (set automatically after creation) ──
    item_hash: str = ""
    is_ai_related: bool = False

    def __init__(self, **data: Any) -> None:
        super().__init__(**data)
        # Compute derived fields after init
        self.item_hash = _make_item_hash(self.source, self.source_id)
        self.is_ai_related = (
            self.threat_category != ThreatCategory.TRADITIONAL
            and self.threat_category != ThreatCategory.UNKNOWN
        )


class CollectionResult(BaseModel):
    """Result of a single collection run."""

    source: str = ""
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    items_collected: int = 0
    items_new: int = 0
    items_updated: int = 0
    errors: List[str] = Field(default_factory=list)
    success: bool = True

    @property
    def duration_seconds(self) -> float:
        return (self.completed_at - self.started_at).total_seconds()


class CollectionSummary(BaseModel):
    """Summary of a full collection cycle across all sources."""

    cycle_id: str = ""
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    results: List[CollectionResult] = Field(default_factory=list)

    @property
    def total_collected(self) -> int:
        return sum(r.items_collected for r in self.results)

    @property
    def total_new(self) -> int:
        return sum(r.items_new for r in self.results)

    @property
    def all_success(self) -> bool:
        return all(r.success for r in self.results)
