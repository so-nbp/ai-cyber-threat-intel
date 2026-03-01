"""
Configuration management.

Loads settings from YAML config file with environment variable overrides.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from pydantic import BaseModel, Field


class NVDConfig(BaseModel):
    api_key: Optional[str] = None
    base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    results_per_page: int = 100
    rate_limit_delay: float = 6.0
    ai_keywords: List[str] = Field(default_factory=lambda: [
        "artificial intelligence", "machine learning", "deep learning",
        "neural network", "tensorflow", "pytorch", "hugging face",
        "langchain", "openai", "llm", "large language model",
        "transformer", "generative ai", "chatgpt", "gpt",
        "prompt injection", "model", "training data",
    ])


class CISAConfig(BaseModel):
    kev_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class GitHubConfig(BaseModel):
    token: Optional[str] = None
    advisory_api_url: str = "https://api.github.com/graphql"
    ai_ecosystems: List[str] = Field(default_factory=lambda: [
        "pip", "npm", "go", "rust",
    ])
    ai_package_keywords: List[str] = Field(default_factory=lambda: [
        "tensorflow", "torch", "pytorch", "transformers", "huggingface",
        "langchain", "llamaindex", "openai", "anthropic", "scikit-learn",
        "keras", "jax", "onnx", "mlflow", "ray", "vllm", "ollama",
        "chromadb", "pinecone", "weaviate", "milvus", "faiss",
        "gradio", "streamlit",
    ])


class ArxivConfig(BaseModel):
    base_url: str = "http://export.arxiv.org/api/query"
    categories: List[str] = Field(default_factory=lambda: [
        "cs.CR", "cs.AI", "cs.LG",
    ])
    search_queries: List[str] = Field(default_factory=lambda: [
        "adversarial machine learning",
        "AI security",
        "LLM security",
        "prompt injection",
        "model poisoning",
        "federated learning attack",
        "AI safety cybersecurity",
    ])
    max_results_per_query: int = 50


class OTXConfig(BaseModel):
    api_key: Optional[str] = None
    base_url: str = "https://otx.alienvault.com/api/v1"
    pulse_days: int = 7


class RSSConfig(BaseModel):
    fetch_timeout: int = 30
    max_entries_per_feed: int = 50


class StorageConfig(BaseModel):
    db_path: str = "data/db/threat_intel.db"
    raw_data_path: str = "data/raw"
    processed_data_path: str = "data/processed"


class SchedulerConfig(BaseModel):
    daily_collection_hour: int = 6
    daily_collection_minute: int = 0
    enable_scheduler: bool = True


class AppConfig(BaseModel):
    """Root application configuration."""

    project_root: str = "."
    log_level: str = "INFO"
    log_file: Optional[str] = "logs/acti.log"
    user_agent: str = "AI-CyberThreatIntel/0.1.0 (Research)"

    nvd: NVDConfig = Field(default_factory=NVDConfig)
    cisa: CISAConfig = Field(default_factory=CISAConfig)
    github: GitHubConfig = Field(default_factory=GitHubConfig)
    arxiv: ArxivConfig = Field(default_factory=ArxivConfig)
    otx: OTXConfig = Field(default_factory=OTXConfig)
    rss: RSSConfig = Field(default_factory=RSSConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)
    scheduler: SchedulerConfig = Field(default_factory=SchedulerConfig)


def _env_override(config_dict: Dict[str, Any], prefix: str = "ACTI") -> Dict[str, Any]:
    """Override config values with environment variables."""
    overrides = {
        f"{prefix}_NVD_API_KEY": ("nvd", "api_key"),
        f"{prefix}_GITHUB_TOKEN": ("github", "token"),
        f"{prefix}_OTX_API_KEY": ("otx", "api_key"),
        f"{prefix}_LOG_LEVEL": ("log_level",),
    }
    for env_var, keys in overrides.items():
        value = os.environ.get(env_var)
        if value is not None:
            if len(keys) == 1:
                config_dict[keys[0]] = value
            elif len(keys) == 2:
                if keys[0] not in config_dict:
                    config_dict[keys[0]] = {}
                config_dict[keys[0]][keys[1]] = value
    return config_dict


def load_config(config_path: Optional[str] = None) -> AppConfig:
    """Load application configuration."""
    config_dict: Dict[str, Any] = {}

    if config_path is None:
        candidates = [
            Path("config/settings.yaml"),
            Path("config/settings.yml"),
        ]
        for candidate in candidates:
            if candidate.exists():
                config_path = str(candidate)
                break

    if config_path is not None:
        path = Path(config_path)
        if path.exists():
            with open(path) as f:
                config_dict = yaml.safe_load(f) or {}

    config_dict = _env_override(config_dict)
    return AppConfig(**config_dict)


def load_rss_sources(config_path: Optional[str] = None) -> Dict[str, Any]:
    """Load RSS feed source definitions."""
    if config_path is None:
        config_path = "config/rss_sources.yaml"

    path = Path(config_path)
    if path.exists():
        with open(path) as f:
            return yaml.safe_load(f) or {}
    return {}
