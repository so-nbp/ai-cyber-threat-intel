"""Tests for threat models and classification."""

from src.models.enums import (
    AffectedSector,
    ThreatCategory,
    Severity,
    classify_affected_sector,
    classify_affected_sectors,
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

    def test_ai_physical(self):
        text = "Researchers demonstrate cyber-physical attack hijacking autonomous vehicle via self-driving system"
        assert classify_threat_category(text) == ThreatCategory.AI_PHYSICAL

    def test_ai_supply_chain(self):
        text = "Poisoned model distributed via model hub attack found with malicious weights through dataset poisoning campaign"
        assert classify_threat_category(text) == ThreatCategory.AI_SUPPLY_CHAIN

    def test_ai_agentic(self):
        text = "Indirect prompt injection enables agent hijacking through tool injection in LLM agent deployment"
        assert classify_threat_category(text) == ThreatCategory.AI_AGENTIC

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

class TestClassifyAffectedSector:
    def test_financial(self):
        text = "Critical vulnerability in banking payment system allows unauthorized SWIFT transactions"
        assert classify_affected_sector(text) == AffectedSector.FINANCIAL

    def test_healthcare(self):
        text = "Ransomware targets hospital patient EHR system with clinical data exfiltration"
        assert classify_affected_sector(text) == AffectedSector.HEALTHCARE

    def test_energy(self):
        text = "SCADA attack on power grid electricity substation control system"
        assert classify_affected_sector(text) == AffectedSector.ENERGY

    def test_government(self):
        text = "Federal government ministry election system compromised by nation-state actor"
        assert classify_affected_sector(text) == AffectedSector.GOVERNMENT

    def test_defense(self):
        text = "Military drone weapon system vulnerability found in combat navigation software"
        assert classify_affected_sector(text) == AffectedSector.DEFENSE

    def test_technology(self):
        text = "Supply chain attack on npm package targeting cloud SaaS developer platform"
        assert classify_affected_sector(text) == AffectedSector.TECHNOLOGY

    def test_manufacturing(self):
        text = "ICS PLC vulnerability in automotive manufacturing factory control system"
        assert classify_affected_sector(text) == AffectedSector.MANUFACTURING

    def test_telecommunications(self):
        text = "5G carrier network router BGP hijack targeting telecom ISP infrastructure"
        assert classify_affected_sector(text) == AffectedSector.TELECOMMUNICATIONS

    def test_transportation(self):
        text = "Ransomware hits airport aviation system disrupting airline flight operations"
        assert classify_affected_sector(text) == AffectedSector.TRANSPORTATION

    def test_education(self):
        text = "University student data breach exposes academic research campus credentials"
        assert classify_affected_sector(text) == AffectedSector.EDUCATION

    def test_unknown(self):
        text = "Generic buffer overflow vulnerability in open source library"
        assert classify_affected_sector(text) == AffectedSector.UNKNOWN


    def test_is_ai_related_new_categories(self):
        for category in (
            ThreatCategory.AI_PHYSICAL,
            ThreatCategory.AI_SUPPLY_CHAIN,
            ThreatCategory.AI_AGENTIC,
        ):
            item = ThreatIntelItem(
                source="test", source_type=SourceType.NEWS,
                source_id=f"test-{category.value}", title="T", description="D",
                threat_category=category,
            )
            assert item.is_ai_related is True, f"{category} should be ai_related"


class TestClassifyAffectedSectors:
    """Tests for the multi-sector classify_affected_sectors() function."""

    def test_single_sector_match(self):
        text = "Ransomware targets hospital patient EHR system"
        result = classify_affected_sectors(text)
        assert AffectedSector.HEALTHCARE in result

    def test_multi_sector_match(self):
        # Contains both financial and government keywords
        text = "Federal government bank payment system breach"
        result = classify_affected_sectors(text)
        assert AffectedSector.FINANCIAL in result
        assert AffectedSector.GOVERNMENT in result

    def test_no_match_returns_empty_list(self):
        text = "Generic buffer overflow in open source library"
        assert classify_affected_sectors(text) == []

    def test_returns_list_type(self):
        text = "Cloud SaaS developer API security issue"
        result = classify_affected_sectors(text)
        assert isinstance(result, list)


class TestThreatIntelItemSectorAutoAssign:
    """Tests for automatic sector assignment in ThreatIntelItem.__init__."""

    def test_sector_auto_assigned_from_title_description(self):
        item = ThreatIntelItem(
            source="test", source_type=SourceType.NEWS,
            source_id="auto-sector-1",
            title="Ransomware hits hospital EHR system",
            description="Patient clinical data exfiltrated.",
        )
        assert AffectedSector.HEALTHCARE in item.affected_sectors

    def test_no_sector_keyword_leaves_empty_list(self):
        item = ThreatIntelItem(
            source="test", source_type=SourceType.NEWS,
            source_id="auto-sector-2",
            title="Buffer overflow in generic library",
            description="No sector keywords here.",
        )
        assert item.affected_sectors == []

    def test_explicit_sectors_not_overwritten(self):
        explicit = [AffectedSector.DEFENSE]
        item = ThreatIntelItem(
            source="test", source_type=SourceType.NEWS,
            source_id="auto-sector-3",
            title="Military drone weapon system issue",
            description="Affects armed forces navigation.",
            affected_sectors=explicit,
        )
        # Should keep the explicitly provided value, not re-classify
        assert item.affected_sectors == explicit

    def test_multi_sector_auto_assigned(self):
        item = ThreatIntelItem(
            source="test", source_type=SourceType.NEWS,
            source_id="auto-sector-4",
            title="Federal government bank payment breach",
            description="Attack spans financial and public sector systems.",
        )
        assert AffectedSector.FINANCIAL in item.affected_sectors
        assert AffectedSector.GOVERNMENT in item.affected_sectors
