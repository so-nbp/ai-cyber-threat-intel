"""File-based storage for raw collected data."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from ..models.threat import ThreatIntelItem
from ..utils.logging import get_logger

logger = get_logger("storage.file_store")


class FileStore:
    def __init__(self, base_path: str) -> None:
        self.base_path = Path(base_path)
        self.base_path.mkdir(parents=True, exist_ok=True)

    def store_raw(self, items: List[ThreatIntelItem], source: str) -> Path:
        now = datetime.now(timezone.utc)
        date_dir = self.base_path / source / now.strftime("%Y-%m-%d")
        date_dir.mkdir(parents=True, exist_ok=True)

        filename = f"{now.strftime('%H-%M-%S')}.json"
        filepath = date_dir / filename

        data = {
            "source": source,
            "collected_at": now.isoformat(),
            "item_count": len(items),
            "items": [
                {
                    **item.model_dump(exclude={"raw_content"}),
                    "raw_content": item.raw_content,
                }
                for item in items
            ],
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2, default=str)

        logger.info("raw_data_stored", path=str(filepath), count=len(items))
        return filepath
