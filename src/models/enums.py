"""
Enumerations and taxonomy definitions for AI Cyber Threat Intelligence.

Based on MITRE ATLAS, MITRE ATT&CK, and custom AI threat taxonomy.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional


class ThreatCategory(str, Enum):
    """Top-level AI threat classification."""

    AI_AS_TARGET = "ai-as-target"
    AI_AS_WEAPON = "ai-as-weapon"
    AI_ENABLED = "ai-enabled"
    AI_ADJACENT = "ai-adjacent"
    TRADITIONAL = "traditional"
    UNKNOWN = "unknown"


class Severity(str, Enum):
    """Severity levels aligned with CVSS qualitative ratings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


class ConfidenceLevel(str, Enum):
    """Intelligence confidence level."""

    CONFIRMED = "confirmed"
    PROBABLE = "probable"
    POSSIBLE = "possible"
    UNVERIFIED = "unverified"


class SourceType(str, Enum):
    """Data source type classification."""

    VULNERABILITY_DB = "vulnerability-db"
    THREAT_INTEL_FEED = "threat-intel-feed"
    RESEARCH_PAPER = "research-paper"
    VENDOR_BLOG = "vendor-blog"
    ADVISORY = "advisory"
    NEWS = "news"
    GOVERNMENT = "government"
    FRAMEWORK = "framework"


class AffectedSector(str, Enum):
    """Critical infrastructure / industry sectors."""

    ENERGY = "energy"
    FINANCIAL = "financial"
    HEALTHCARE = "healthcare"
    TELECOMMUNICATIONS = "telecommunications"
    TRANSPORTATION = "transportation"
    GOVERNMENT = "government"
    DEFENSE = "defense"
    TECHNOLOGY = "technology"
    MANUFACTURING = "manufacturing"
    EDUCATION = "education"
    GENERAL = "general"
    UNKNOWN = "unknown"


# ──────────────────────────────────────────────
# AI-specific keyword sets for auto-classification
# ──────────────────────────────────────────────

AI_TARGET_KEYWORDS = [
    "adversarial", "model evasion", "data poisoning", "model theft",
    "model extraction", "model inversion", "membership inference",
    "prompt injection", "jailbreak", "llm attack", "backdoor attack",
    "trojan model", "neural trojan", "federated learning attack",
    "training data extraction", "model stealing",
]

AI_WEAPON_KEYWORDS = [
    "ai-generated malware", "deepfake", "ai phishing",
    "automated exploit", "ai social engineering", "voice cloning",
    "synthetic identity", "ai-powered attack", "llm-generated",
    "gpt malware", "ai vulnerability discovery",
]

AI_ENABLED_KEYWORDS = [
    "tensorflow", "pytorch", "hugging face", "transformers",
    "langchain", "llamaindex", "openai api", "anthropic api",
    "ml pipeline", "model serving", "mlops", "kubeflow",
    "mlflow", "model registry", "onnx", "triton",
    "vllm", "ollama", "localai",
]

AI_ADJACENT_KEYWORDS = [
    "gpu cluster", "cuda vulnerability", "nvidia driver",
    "cloud ml", "sagemaker", "vertex ai", "azure ml",
    "data lake", "feature store", "vector database",
    "embedding", "rag pipeline", "ai governance",
]


def classify_threat_category(text: str) -> ThreatCategory:
    """Classify threat category based on keyword matching."""
    text_lower = text.lower()

    scores = {
        ThreatCategory.AI_AS_TARGET: sum(1 for kw in AI_TARGET_KEYWORDS if kw in text_lower),
        ThreatCategory.AI_AS_WEAPON: sum(1 for kw in AI_WEAPON_KEYWORDS if kw in text_lower),
        ThreatCategory.AI_ENABLED: sum(1 for kw in AI_ENABLED_KEYWORDS if kw in text_lower),
        ThreatCategory.AI_ADJACENT: sum(1 for kw in AI_ADJACENT_KEYWORDS if kw in text_lower),
    }

    max_score = max(scores.values())
    if max_score == 0:
        return ThreatCategory.UNKNOWN

    for category, score in scores.items():
        if score == max_score:
            return category

    return ThreatCategory.UNKNOWN


def severity_from_cvss(cvss_score: Optional[float]) -> Severity:
    """Convert CVSS score to severity enum."""
    if cvss_score is None:
        return Severity.UNKNOWN
    if cvss_score >= 9.0:
        return Severity.CRITICAL
    if cvss_score >= 7.0:
        return Severity.HIGH
    if cvss_score >= 4.0:
        return Severity.MEDIUM
    if cvss_score >= 0.1:
        return Severity.LOW
    return Severity.INFO
