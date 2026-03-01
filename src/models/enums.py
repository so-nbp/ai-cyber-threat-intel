"""
Enumerations and taxonomy definitions for AI Cyber Threat Intelligence.

Based on MITRE ATLAS, MITRE ATT&CK, and custom AI threat taxonomy.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional


class ThreatCategory(str, Enum):
    """Top-level AI threat classification (7-axis taxonomy)."""

    AI_AS_TARGET = "ai-as-target"
    AI_AS_WEAPON = "ai-as-weapon"
    AI_ENABLED = "ai-enabled"
    AI_ADJACENT = "ai-adjacent"
    AI_PHYSICAL = "ai-physical"
    AI_SUPPLY_CHAIN = "ai-supply-chain"
    AI_AGENTIC = "ai-agentic"
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

AI_PHYSICAL_KEYWORDS = [
    "autonomous vehicle", "self-driving", "autonomous driving",
    "industrial robot", "robotic system", "surgical robot", "medical robot",
    "drone attack", "uav", "unmanned aerial",
    "cyber-physical", "autonomous weapon", "lethal autonomous",
    "ai-controlled physical", "physical ai attack", "embedded ai attack",
    "smart grid attack", "ot security ai",
]

AI_SUPPLY_CHAIN_KEYWORDS = [
    "poisoned model", "model supply chain", "malicious weights",
    "compromised model", "model repository attack",
    "dataset poisoning", "training dataset manipulation",
    "model hub attack", "pre-trained model attack",
    "weight poisoning", "fine-tuning attack",
    "lora poisoning", "adapter attack", "artifact poisoning",
    "dependency confusion ai", "malicious package ml",
]

AI_AGENTIC_KEYWORDS = [
    "ai agent attack", "llm agent", "agentic ai",
    "autonomous agent attack", "agentic attack",
    "tool injection", "indirect prompt injection",
    "agent hijacking", "agent manipulation", "multi-agent attack",
    "function calling attack", "tool use attack",
    "computer use attack", "code interpreter attack",
    "agent orchestration attack", "mcp attack", "mcp vulnerability",
]


# ──────────────────────────────────────────────
# Sector keyword sets for auto-classification
# Based on CISA/NISC/NIS2 sector definitions (ADR-006)
# ──────────────────────────────────────────────

SECTOR_KEYWORDS: dict[AffectedSector, list[str]] = {
    AffectedSector.FINANCIAL: [
        "bank", "banking", "financial", "finance", "payment", "crypto",
        "cryptocurrency", "fintech", "insurance", "swift", "trading",
        "stock", "broker", "wallet", "exchange", "ledger", "credit",
        "securities", "investment", "atm", "forex", "brokerage",
    ],
    AffectedSector.HEALTHCARE: [
        "hospital", "medical", "health", "patient", "clinical", "pharma",
        "pharmaceutical", "ehr", "hipaa", "fda", "drug", "vaccine",
        "diagnostic", "radiology", "telehealth", "healthcare", "biomed",
        "genomics", "dental", "nursing",
    ],
    AffectedSector.ENERGY: [
        "power grid", "electricity", "energy", "utility", "oil", "gas",
        "nuclear", "smart grid", "scada", "renewable", "solar", "wind turbine",
        "substation", "pipeline", "refinery", "lng", "fuel", "grid",
    ],
    AffectedSector.GOVERNMENT: [
        "government", "federal", "ministry", "municipal", "public sector",
        "election", "parliament", "legislature", "department of",
        "agency", "administration", "state department", "whitehouse",
        "census", "passport", "tax authority", "regulation",
    ],
    AffectedSector.DEFENSE: [
        "military", "defense", "army", "navy", "air force", "weapon",
        "missile", "combat", "classified", "pentagon", "armed forces",
        "nato", "satellite", "aerospace", "intelligence agency",
        "surveillance", "warfare", "dod", "defence",
    ],
    AffectedSector.TECHNOLOGY: [
        "cloud", "saas", "api", "developer", "software platform",
        "github", "npm", "pypi", "docker", "kubernetes",
        "data center", "hosting", "it service",
        "managed service", "msp", "mssp", "devops", "ci/cd",
    ],
    AffectedSector.MANUFACTURING: [
        "factory", "industrial", "manufacturing", "automotive", "supply chain",
        "ics", "plc", "oem", "production", "assembly", "robotics",
        "semiconductor", "electronics", "chemical plant", "steel",
        "aerospace manufacturing",
    ],
    AffectedSector.TELECOMMUNICATIONS: [
        "telecom", "telecommunications", "carrier", "isp", "5g", "4g",
        "router", "switch", "internet exchange", "bgp", "fiber",
        "mobile network", "wireless", "broadband", "voip", "sms",
        "network provider",
    ],
    AffectedSector.TRANSPORTATION: [
        "aviation", "airline", "airport", "railway", "railroad", "shipping",
        "port", "harbor", "road", "fleet", "logistics", "freight",
        "autonomous vehicle", "self-driving", "maritime", "cargo",
        "transit", "traffic", "navigation",
    ],
    AffectedSector.EDUCATION: [
        "university", "school", "college", "education", "academic",
        "student", "research institution", "campus", "faculty",
        "k-12", "edtech", "e-learning", "curriculum",
    ],
    AffectedSector.GENERAL: [
        "retail", "ecommerce", "food", "agriculture", "grocery",
        "restaurant", "supermarket", "consumer", "hospitality",
        "hotel", "real estate", "water utility", "wastewater",
    ],
}


def classify_affected_sectors(text: str) -> list[AffectedSector]:
    """Classify all matching target sectors based on keyword matching.

    Returns a list of all sectors that have at least one keyword match.
    Returns an empty list when no sector keyword is found.
    """
    text_lower = text.lower()
    return [
        sector
        for sector, keywords in SECTOR_KEYWORDS.items()
        if any(kw in text_lower for kw in keywords)
    ]


def classify_affected_sector(text: str) -> AffectedSector:
    """Classify the most likely (highest-score) target sector.

    Kept for backward compatibility. Prefer classify_affected_sectors()
    for new code where multiple sectors can apply.
    """
    text_lower = text.lower()

    scores = {
        sector: sum(1 for kw in keywords if kw in text_lower)
        for sector, keywords in SECTOR_KEYWORDS.items()
    }

    max_score = max(scores.values())
    if max_score == 0:
        return AffectedSector.UNKNOWN

    for sector, score in scores.items():
        if score == max_score:
            return sector

    return AffectedSector.UNKNOWN


def classify_threat_category(text: str) -> ThreatCategory:
    """Classify threat category based on keyword matching."""
    text_lower = text.lower()

    scores = {
        ThreatCategory.AI_AS_TARGET: sum(1 for kw in AI_TARGET_KEYWORDS if kw in text_lower),
        ThreatCategory.AI_AS_WEAPON: sum(1 for kw in AI_WEAPON_KEYWORDS if kw in text_lower),
        ThreatCategory.AI_ENABLED: sum(1 for kw in AI_ENABLED_KEYWORDS if kw in text_lower),
        ThreatCategory.AI_ADJACENT: sum(1 for kw in AI_ADJACENT_KEYWORDS if kw in text_lower),
        ThreatCategory.AI_PHYSICAL: sum(1 for kw in AI_PHYSICAL_KEYWORDS if kw in text_lower),
        ThreatCategory.AI_SUPPLY_CHAIN: sum(1 for kw in AI_SUPPLY_CHAIN_KEYWORDS if kw in text_lower),
        ThreatCategory.AI_AGENTIC: sum(1 for kw in AI_AGENTIC_KEYWORDS if kw in text_lower),
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
