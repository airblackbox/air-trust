"""Tests for the agent-identity-binding compliance check in code_scanner."""

from air_blackbox.compliance.code_scanner import _check_agent_identity_binding


def _write(tmp_path, name: str, content: str) -> None:
    p = tmp_path / name
    p.write_text(content)


def _contents(tmp_path) -> dict:
    d = {}
    for f in tmp_path.rglob("*.py"):
        d[str(f)] = f.read_text()
    return d


class TestAgentIdentityBinding:
    def test_no_autonomous_agent_passes(self, tmp_path):
        _write(tmp_path, "utils.py", "def helper(x):\n    return x + 1\n")
        findings = _check_agent_identity_binding(_contents(tmp_path), str(tmp_path))
        assert len(findings) == 1
        assert findings[0].status == "pass"
        assert "not applicable" in findings[0].evidence.lower()

    def test_tick_loop_without_identity_fails(self, tmp_path):
        _write(tmp_path, "agent.py", """
def tick():
    while True:
        decision = make_decision()
        execute(decision)
""")
        findings = _check_agent_identity_binding(_contents(tmp_path), str(tmp_path))
        assert findings[0].status == "fail"
        assert "stable cryptographic identity" in findings[0].evidence

    def test_tick_loop_with_air_trust_and_persistence_passes(self, tmp_path):
        _write(tmp_path, "agent.py", """
import air_trust
from pathlib import Path

def load_identity():
    key_path = Path.home() / ".air-trust" / "keys" / "botbotfromuk-ed25519.key"
    return air_trust.AgentIdentity(agent_name="botbotfromuk")

def tick():
    while True:
        identity = load_identity()
        run_decision_loop()
""")
        findings = _check_agent_identity_binding(_contents(tmp_path), str(tmp_path))
        assert findings[0].status == "pass"

    def test_tick_loop_with_identity_but_no_persistence_warns(self, tmp_path):
        _write(tmp_path, "agent.py", """
import air_trust

def run_tick():
    identity = air_trust.AgentIdentity(agent_name="ephemeral")
    while True:
        do_stuff()
""")
        findings = _check_agent_identity_binding(_contents(tmp_path), str(tmp_path))
        assert findings[0].status == "warn"
        assert "persistence path unclear" in findings[0].evidence


class TestSCCAARDetection:
    """v1.11.1+: detect botindex-aar (AAR) and Session Continuity Certificate (SCC)."""

    def test_aar_with_persistence_passes(self, tmp_path):
        _write(tmp_path, "agent.py", """
from botindex_aar import AgentActionReceipt, createAndSignAAR
from pathlib import Path

def tick():
    key_path = Path.home() / ".aar" / "keys" / "botbotfromuk.key"
    while True:
        receipt = createAndSignAAR(action="decide", previousReceiptHash="abc")
""")
        findings = _check_agent_identity_binding(_contents(tmp_path), str(tmp_path))
        assert findings[0].status == "pass"
        assert "AAR" in findings[0].evidence

    def test_scc_with_persistence_passes(self, tmp_path):
        _write(tmp_path, "agent.py", """
from botindex_aar import createAndSignSCC, validateSCCChain, detectCapabilityDrift
from pathlib import Path

def run_tick():
    scc_path = Path.home() / ".scc" / "session.key"
    while True:
        scc = createAndSignSCC(
            prior_session_hash="beef",
            memory_root="cafe",
            capability_hash="dead",
        )
""")
        findings = _check_agent_identity_binding(_contents(tmp_path), str(tmp_path))
        assert findings[0].status == "pass"
        assert "SCC" in findings[0].evidence

    def test_both_schemes_listed_in_evidence(self, tmp_path):
        _write(tmp_path, "agent.py", """
import air_trust
from botindex_aar import AgentActionReceipt, createAndSignSCC
from pathlib import Path

def tick():
    key = Path.home() / ".air-trust" / "keys" / "agent.key"
    while True:
        pass
""")
        findings = _check_agent_identity_binding(_contents(tmp_path), str(tmp_path))
        evidence = findings[0].evidence
        assert findings[0].status == "pass"
        assert "air-trust" in evidence
        assert "AAR" in evidence
        assert "SCC" in evidence

    def test_fail_message_references_all_three_schemes(self, tmp_path):
        _write(tmp_path, "agent.py", """
def tick():
    while True:
        do_stuff()
""")
        findings = _check_agent_identity_binding(_contents(tmp_path), str(tmp_path))
        assert findings[0].status == "fail"
        fix_hint = findings[0].fix_hint
        assert "air-trust" in fix_hint
        assert "AAR" in fix_hint
        assert "SCC" in fix_hint

    def test_scc_schema_fields_alone_trigger_detection(self, tmp_path):
        # Even without imports — field names like memory_root are a strong signal
        _write(tmp_path, "agent.py", """
def tick():
    while True:
        cert = {
            "prior_session_hash": "abc",
            "memory_root": "def",
            "capability_hash": "ghi",
        }
""")
        # No persistence patterns -> should warn (not fail)
        findings = _check_agent_identity_binding(_contents(tmp_path), str(tmp_path))
        assert findings[0].status == "warn"
        assert "SCC" in findings[0].evidence
