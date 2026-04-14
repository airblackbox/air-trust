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
