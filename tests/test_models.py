"""Tests for threat models and classification."""

from src.models.enums import (
    ThreatCategory,
    Severity,
    classify_threat_category,
    severity_from_cvss,
)
from src.models.threat import ThreatIntelItem
from src.models.enums import SourceType


class TestClassifyThreatCategory:
    def test_ai_as_target(self):
        text = "New prompt injection attack allows jailbreak of LLM systems"
        assert classify_threat_category(text) == ThreatCategory.AI_AS_TARGET

    def test_ai_as_weapon(self):
        text = "AI-generated malware uses deepfake social engineering"
        assert classify_threat_category(text) == ThreatCategory.AI_AS_WEAPON

    def test_ai_enabled(self):
        text = "Critical vulnerability found in tensorflow model serving pipeline"
        assert classify_threat_category(text) == ThreatCategory.AI_ENABLED

    def test_ai_adjacent(self):
        text = "NVIDIA driver vulnerability in GPU cluster computing environment"
        assert classify_threat_category(text) == ThreatCategory.AI_ADJACENT

    def test_unknown(self):
        text = "Generic SQL injection in web application"
        assert classify_threat_category(text) == ThreatCategory.UNKNOWN


class TestSeverityFromCVSS:
    def test_critical(self):
        assert severity_from_cvss(9.8) == Severity.CRITICAL

    def test_high(self):
        assert severity_from_cvss(7.5) == Severity.HIGH

    def test_medium(self):
        assert severity_from_cvss(5.0) == Severity.MEDIUM

    def test_low(self):
        assert severity_from_cvss(2.0) == Severity.LOW

    def test_info(self):
        assert severity_from_cvss(0.0) == Severity.INFO

    def test_none(self):
        assert severity_from_cvss(None) == Severity.UNKNOWN


class TestThreatIntelItem:
    def test_item_hash_deterministic(self):
        item1 = ThreatIntelItem(
            source="nvd", source_type=SourceType.VULNERABILITY_DB,
            source_id="CVE-2024-1234", title="Test", description="A",
        )
        item2 = ThreatIntelItem(
            source="nvd", source_type=SourceType.VULNERABILITY_DB,
            source_id="CVE-2024-1234", title="Updated", description="B",
        )
        assert item1.item_hash == item2.item_hash

    def test_different_items_different_hash(self):
        item1 = ThreatIntelItem(
            source="nvd", source_type=SourceType.VULNERABILITY_DB,
            source_id="CVE-2024-1234", title="T", description="D",
        )
        item2 = ThreatIntelItem(
            source="nvd", source_type=SourceType.VULNERABILITY_DB,
            source_id="CVE-2024-5678", title="T", description="D",
        )
        assert item1.item_hash != item2.item_hash

    def test_is_ai_related_true(self):
        item = ThreatIntelItem(
            source="nvd", source_type=SourceType.VULNERABILITY_DB,
            source_id="CVE-2024-1234", title="T", description="D",
            threat_category=ThreatCategory.AI_AS_TARGET,
        )
        assert item.is_ai_related is True

    def test_is_ai_related_false(self):
        item = ThreatIntelItem(
            source="nvd", source_type=SourceType.VULNERABILITY_DB,
            source_id="CVE-2024-1234", title="T", description="D",
            threat_category=ThreatCategory.TRADITIONAL,
        )
        assert item.is_ai_related is False
