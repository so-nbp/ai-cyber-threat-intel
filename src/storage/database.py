"""
SQLite storage layer for threat intelligence data.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..models.threat import CollectionResult, ThreatIntelItem
from ..utils.logging import get_logger

logger = get_logger("storage.database")

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS threat_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    item_hash TEXT UNIQUE NOT NULL,
    source TEXT NOT NULL,
    source_type TEXT NOT NULL,
    source_id TEXT NOT NULL,
    source_url TEXT,
    title TEXT NOT NULL,
    description TEXT,
    threat_category TEXT DEFAULT 'unknown',
    severity TEXT DEFAULT 'unknown',
    cvss_score REAL,
    confidence TEXT DEFAULT 'unverified',
    is_ai_related BOOLEAN DEFAULT 0,
    tags TEXT,
    keywords TEXT,
    atlas_techniques TEXT,
    attck_techniques TEXT,
    affected_sectors TEXT,
    affected_products TEXT,
    references_json TEXT,
    cve_ids TEXT,
    published_at TEXT,
    modified_at TEXT,
    collected_at TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_threat_source ON threat_items(source);
CREATE INDEX IF NOT EXISTS idx_threat_category ON threat_items(threat_category);
CREATE INDEX IF NOT EXISTS idx_threat_severity ON threat_items(severity);
CREATE INDEX IF NOT EXISTS idx_threat_published ON threat_items(published_at);
CREATE INDEX IF NOT EXISTS idx_threat_collected ON threat_items(collected_at);
CREATE INDEX IF NOT EXISTS idx_threat_ai_related ON threat_items(is_ai_related);
CREATE INDEX IF NOT EXISTS idx_threat_source_id ON threat_items(source, source_id);

CREATE TABLE IF NOT EXISTS collection_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cycle_id TEXT,
    source TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT NOT NULL,
    items_collected INTEGER DEFAULT 0,
    items_new INTEGER DEFAULT 0,
    items_updated INTEGER DEFAULT 0,
    errors TEXT,
    success BOOLEAN DEFAULT 1,
    duration_seconds REAL,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_runs_source ON collection_runs(source);
CREATE INDEX IF NOT EXISTS idx_runs_started ON collection_runs(started_at);
"""


class ThreatDatabase:
    """SQLite-based threat intelligence database."""

    def __init__(self, db_path: str) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: Optional[sqlite3.Connection] = None

    def _get_connection(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(str(self.db_path))
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
        return self._conn

    def initialize(self) -> None:
        conn = self._get_connection()
        conn.executescript(SCHEMA_SQL)
        conn.commit()
        logger.info("database_initialized", path=str(self.db_path))

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    def store_items(self, items: List[ThreatIntelItem]) -> Tuple[int, int]:
        """Store items with upsert. Returns (new_count, updated_count)."""
        conn = self._get_connection()
        new_count = 0
        updated_count = 0

        for item in items:
            try:
                row = self._item_to_row(item)
                try:
                    conn.execute("""
                        INSERT INTO threat_items (
                            item_hash, source, source_type, source_id, source_url,
                            title, description, threat_category, severity, cvss_score,
                            confidence, is_ai_related, tags, keywords,
                            atlas_techniques, attck_techniques, affected_sectors,
                            affected_products, references_json, cve_ids,
                            published_at, modified_at, collected_at
                        ) VALUES (
                            :item_hash, :source, :source_type, :source_id, :source_url,
                            :title, :description, :threat_category, :severity, :cvss_score,
                            :confidence, :is_ai_related, :tags, :keywords,
                            :atlas_techniques, :attck_techniques, :affected_sectors,
                            :affected_products, :references_json, :cve_ids,
                            :published_at, :modified_at, :collected_at
                        )
                    """, row)
                    new_count += 1
                except sqlite3.IntegrityError:
                    conn.execute("""
                        UPDATE threat_items SET
                            title = :title,
                            description = :description,
                            threat_category = :threat_category,
                            severity = :severity,
                            cvss_score = :cvss_score,
                            confidence = :confidence,
                            is_ai_related = :is_ai_related,
                            tags = :tags,
                            modified_at = :modified_at,
                            updated_at = datetime('now')
                        WHERE item_hash = :item_hash
                    """, row)
                    updated_count += 1
            except Exception as e:
                logger.warning("store_item_error", item_hash=item.item_hash, error=str(e))

        conn.commit()
        logger.info("items_stored", new=new_count, updated=updated_count)
        return new_count, updated_count

    def store_collection_run(self, result: CollectionResult, cycle_id: str = "") -> None:
        conn = self._get_connection()
        conn.execute("""
            INSERT INTO collection_runs (
                cycle_id, source, started_at, completed_at,
                items_collected, items_new, items_updated,
                errors, success, duration_seconds
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            cycle_id,
            result.source,
            result.started_at.isoformat(),
            result.completed_at.isoformat(),
            result.items_collected,
            result.items_new,
            result.items_updated,
            json.dumps(result.errors),
            result.success,
            result.duration_seconds,
        ))
        conn.commit()

    def get_items(
        self,
        source: Optional[str] = None,
        threat_category: Optional[str] = None,
        severity: Optional[str] = None,
        ai_only: bool = False,
        since: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        conn = self._get_connection()
        conditions = []
        params: List[Any] = []

        if source:
            conditions.append("source = ?")
            params.append(source)
        if threat_category:
            conditions.append("threat_category = ?")
            params.append(threat_category)
        if severity:
            conditions.append("severity = ?")
            params.append(severity)
        if ai_only:
            conditions.append("is_ai_related = 1")
        if since:
            conditions.append("collected_at >= ?")
            params.append(since.isoformat())

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        query = f"SELECT * FROM threat_items {where} ORDER BY collected_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cursor = conn.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]

    def get_statistics(self) -> Dict[str, Any]:
        conn = self._get_connection()
        stats: Dict[str, Any] = {}

        cursor = conn.execute("SELECT COUNT(*) as total FROM threat_items")
        stats["total_items"] = cursor.fetchone()["total"]

        cursor = conn.execute("SELECT COUNT(*) as total FROM threat_items WHERE is_ai_related = 1")
        stats["ai_related_items"] = cursor.fetchone()["total"]

        cursor = conn.execute("SELECT source, COUNT(*) as count FROM threat_items GROUP BY source ORDER BY count DESC")
        stats["by_source"] = {row["source"]: row["count"] for row in cursor.fetchall()}

        cursor = conn.execute("SELECT threat_category, COUNT(*) as count FROM threat_items GROUP BY threat_category ORDER BY count DESC")
        stats["by_category"] = {row["threat_category"]: row["count"] for row in cursor.fetchall()}

        cursor = conn.execute("SELECT severity, COUNT(*) as count FROM threat_items GROUP BY severity ORDER BY count DESC")
        stats["by_severity"] = {row["severity"]: row["count"] for row in cursor.fetchall()}

        cursor = conn.execute("SELECT source, started_at, items_collected, items_new, success FROM collection_runs ORDER BY started_at DESC LIMIT 20")
        stats["recent_runs"] = [dict(row) for row in cursor.fetchall()]

        return stats

    def _item_to_row(self, item: ThreatIntelItem) -> Dict[str, Any]:
        return {
            "item_hash": item.item_hash,
            "source": item.source,
            "source_type": item.source_type.value,
            "source_id": item.source_id,
            "source_url": item.source_url,
            "title": item.title,
            "description": item.description,
            "threat_category": item.threat_category.value,
            "severity": item.severity.value,
            "cvss_score": item.cvss_score,
            "confidence": item.confidence.value,
            "is_ai_related": item.is_ai_related,
            "tags": json.dumps(item.tags),
            "keywords": json.dumps(item.keywords),
            "atlas_techniques": json.dumps(item.atlas_techniques),
            "attck_techniques": json.dumps(item.attck_techniques),
            "affected_sectors": json.dumps([s.value for s in item.affected_sectors]),
            "affected_products": json.dumps([p.model_dump() for p in item.affected_products]),
            "references_json": json.dumps([r.model_dump() for r in item.references]),
            "cve_ids": json.dumps(item.cve_ids),
            "published_at": item.published_at.isoformat() if item.published_at else None,
            "modified_at": item.modified_at.isoformat() if item.modified_at else None,
            "collected_at": item.collected_at.isoformat(),
        }
