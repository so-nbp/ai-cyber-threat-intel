"""
Abstract base collector.

All source-specific collectors inherit from this base class.
"""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import aiohttp

from ..models.threat import CollectionResult, ThreatIntelItem
from ..utils.config import AppConfig
from ..utils.logging import get_logger


class BaseCollector(ABC):
    """Base class for all threat intelligence collectors."""

    SOURCE_NAME: str = ""
    SOURCE_DESCRIPTION: str = ""

    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self.logger = get_logger(f"collector.{self.SOURCE_NAME}")
        self._session: Optional[aiohttp.ClientSession] = None

    @property
    def headers(self) -> Dict[str, str]:
        return {
            "User-Agent": self.config.user_agent,
            "Accept": "application/json",
        }

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=60, connect=15)
            self._session = aiohttp.ClientSession(
                headers=self.headers,
                timeout=timeout,
            )
        return self._session

    async def _close_session(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()

    async def fetch_json(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Fetch JSON from a URL with error handling."""
        session = await self._get_session()
        hdrs = {**self.headers, **(extra_headers or {})}
        try:
            async with session.get(url, params=params, headers=hdrs) as resp:
                resp.raise_for_status()
                return await resp.json()
        except aiohttp.ClientError as e:
            self.logger.error("fetch_failed", url=url, error=str(e))
            raise

    async def fetch_text(self, url: str, params: Optional[Dict[str, Any]] = None) -> str:
        """Fetch text content from a URL."""
        session = await self._get_session()
        try:
            async with session.get(url, params=params) as resp:
                resp.raise_for_status()
                return await resp.text()
        except aiohttp.ClientError as e:
            self.logger.error("fetch_failed", url=url, error=str(e))
            raise

    @abstractmethod
    async def collect(self, since: Optional[datetime] = None) -> List[ThreatIntelItem]:
        """
        Collect threat intelligence items from the source.

        Args:
            since: Only collect items published/modified after this datetime.

        Returns:
            List of normalized ThreatIntelItem instances.
        """
        ...

    async def run(self, since: Optional[datetime] = None) -> Tuple[CollectionResult, List[ThreatIntelItem]]:
        """
        Execute collection with timing and error handling.

        Returns:
            Tuple of (CollectionResult metadata, list of collected items)
        """
        started_at = datetime.now(timezone.utc)
        errors: List[str] = []
        items: List[ThreatIntelItem] = []

        self.logger.info("collection_started", source=self.SOURCE_NAME)

        try:
            items = await self.collect(since=since)
            self.logger.info(
                "collection_completed",
                source=self.SOURCE_NAME,
                items_count=len(items),
            )
        except Exception as e:
            errors.append(f"{type(e).__name__}: {str(e)}")
            self.logger.error(
                "collection_failed",
                source=self.SOURCE_NAME,
                error=str(e),
            )
        finally:
            await self._close_session()

        completed_at = datetime.now(timezone.utc)

        result = CollectionResult(
            source=self.SOURCE_NAME,
            started_at=started_at,
            completed_at=completed_at,
            items_collected=len(items),
            items_new=len(items),
            items_updated=0,
            errors=errors,
            success=len(errors) == 0,
        )

        return result, items

    async def rate_limit_delay(self, seconds: float) -> None:
        await asyncio.sleep(seconds)
