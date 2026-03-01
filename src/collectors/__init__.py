"""Threat intelligence collectors registry."""

from __future__ import annotations

from typing import TYPE_CHECKING, Dict, List, Type

from .arxiv import ArxivCollector
from .base import BaseCollector
from .cisa_kev import CISAKEVCollector
from .github_advisory import GitHubAdvisoryCollector
from .nvd import NVDCollector
from .otx import OTXCollector
from .rss_feeds import RSSFeedCollector

if TYPE_CHECKING:
    from ..utils.config import AppConfig

COLLECTOR_REGISTRY: Dict[str, Type[BaseCollector]] = {
    "nvd": NVDCollector,
    "cisa_kev": CISAKEVCollector,
    "github_advisory": GitHubAdvisoryCollector,
    "arxiv": ArxivCollector,
    "rss_feeds": RSSFeedCollector,
    "otx": OTXCollector,
}


def get_collector(name: str, config: "AppConfig") -> BaseCollector:
    cls = COLLECTOR_REGISTRY.get(name)
    if cls is None:
        raise ValueError(f"Unknown collector: {name}. Available: {list(COLLECTOR_REGISTRY.keys())}")
    return cls(config)


def get_all_collectors(config: "AppConfig") -> List[BaseCollector]:
    return [cls(config) for cls in COLLECTOR_REGISTRY.values()]
