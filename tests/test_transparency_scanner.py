"""Tests for Article 13 transparency scanner (v1.11+)."""

import os
import pytest
from air_blackbox.compliance.transparency_scanner import (
    scan_transparency,
    TransparencyFinding,
)


def _write(tmp_path, name: str, content: str) -> str:
    p = tmp_path / name
    p.write_text(content)
    return str(p)


def _by_name(findings, name):
    return [f for f in findings if f.name == name]


class TestScanTransparencySmoke:
    def test_empty_directory_returns_findings(self, tmp_path):
        findings = scan_transparency(str(tmp_path))
        assert len(findings) == 6  # 6 Article 13 checks
        assert all(isinstance(f, TransparencyFinding) for f in findings)
        assert all(f.article == 13 for f in findings)

    def test_every_finding_has_name_and_status(self, tmp_path):
        findings = scan_transparency(str(tmp_path))
        for f in findings:
            assert f.name
            assert f.status in ("pass", "warn", "fail")


class TestAIDisclosure:
    def test_disclosure_in_system_prompt_passes(self, tmp_path):
        _write(tmp_path, "agent.py", '''
def run():
    system = "I am an AI assistant designed to help with customer service."
    return system
''')
        findings = scan_transparency(str(tmp_path))
        disclosure = _by_name(findings, "AI disclosure to users")[0]
        assert disclosure.status == "pass"

    def test_no_disclosure_warns(self, tmp_path):
        _write(tmp_path, "agent.py", 'def run(): return "hello"')
        findings = scan_transparency(str(tmp_path))
        disclosure = _by_name(findings, "AI disclosure to users")[0]
        assert disclosure.status == "warn"


class TestCapabilityDocs:
    def test_model_card_passes(self, tmp_path):
        _write(tmp_path, "MODEL_CARD.md", "# Model Card\nCapabilities: classification")
        findings = scan_transparency(str(tmp_path))
        cap = _by_name(findings, "Capability and limitation documentation")[0]
        assert cap.status == "pass"

    def test_no_capability_docs_fails(self, tmp_path):
        findings = scan_transparency(str(tmp_path))
        cap = _by_name(findings, "Capability and limitation documentation")[0]
        assert cap.status == "fail"


class TestInstructionsForUse:
    def test_operator_guide_passes(self, tmp_path):
        _write(tmp_path, "OPERATOR_GUIDE.md", "# Operator Guide\nHow to run this.")
        findings = scan_transparency(str(tmp_path))
        instr = _by_name(findings, "Instructions for use")[0]
        assert instr.status == "pass"

    def test_readme_only_warns(self, tmp_path):
        _write(tmp_path, "README.md", "# Project")
        findings = scan_transparency(str(tmp_path))
        instr = _by_name(findings, "Instructions for use")[0]
        assert instr.status == "warn"

    def test_no_docs_fails(self, tmp_path):
        findings = scan_transparency(str(tmp_path))
        instr = _by_name(findings, "Instructions for use")[0]
        assert instr.status == "fail"


class TestProviderIdentity:
    def test_authors_file_passes(self, tmp_path):
        _write(tmp_path, "AUTHORS", "Jason Shotwell <jason@airblackbox.ai>")
        findings = scan_transparency(str(tmp_path))
        prov = _by_name(findings, "Provider identity disclosure")[0]
        assert prov.status == "pass"

    def test_no_provider_info_fails(self, tmp_path):
        findings = scan_transparency(str(tmp_path))
        prov = _by_name(findings, "Provider identity disclosure")[0]
        assert prov.status == "fail"


class TestOutputInterpretation:
    def test_confidence_score_passes(self, tmp_path):
        _write(tmp_path, "agent.py", 'def predict(): return {"confidence_score": 0.87}')
        findings = scan_transparency(str(tmp_path))
        out = _by_name(findings, "Output interpretation support")[0]
        assert out.status == "pass"

    def test_no_interpretation_warns(self, tmp_path):
        _write(tmp_path, "agent.py", 'def predict(): return "answer"')
        findings = scan_transparency(str(tmp_path))
        out = _by_name(findings, "Output interpretation support")[0]
        assert out.status == "warn"


class TestChangeLogging:
    def test_changelog_passes(self, tmp_path):
        _write(tmp_path, "CHANGELOG.md", "# v1.0\n- initial release")
        findings = scan_transparency(str(tmp_path))
        chg = _by_name(findings, "Change logging and versioning")[0]
        assert chg.status == "pass"

    def test_no_changelog_fails(self, tmp_path):
        findings = scan_transparency(str(tmp_path))
        chg = _by_name(findings, "Change logging and versioning")[0]
        assert chg.status == "fail"
