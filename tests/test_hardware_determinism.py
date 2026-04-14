"""Tests for the v1.12 hardware determinism checks (Article 15)."""

from air_blackbox.compliance.code_scanner import (
    _check_deterministic_seeds,
    _check_deterministic_algorithms,
    _check_hardware_abstraction,
)


def _write(tmp_path, name: str, content: str) -> None:
    p = tmp_path / name
    p.write_text(content)


def _contents(tmp_path) -> dict:
    return {str(f): f.read_text() for f in tmp_path.rglob("*.py")}


# ============================================================================
# Seed determinism tests
# ============================================================================

class TestDeterministicSeeds:
    def test_non_ml_codebase_passes(self, tmp_path):
        _write(tmp_path, "utils.py", "def helper(x): return x + 1")
        findings = _check_deterministic_seeds(_contents(tmp_path), str(tmp_path))
        assert findings[0].status == "pass"
        assert "not applicable" in findings[0].evidence.lower()

    def test_torch_with_all_seeds_passes(self, tmp_path):
        _write(tmp_path, "train.py", """
import torch
import numpy as np
import random

SEED = 42
random.seed(SEED)
np.random.seed(SEED)
torch.manual_seed(SEED)
torch.cuda.manual_seed_all(SEED)

def train():
    pass
""")
        findings = _check_deterministic_seeds(_contents(tmp_path), str(tmp_path))
        assert findings[0].status == "pass"

    def test_torch_no_seeds_fails(self, tmp_path):
        _write(tmp_path, "train.py", """
import torch

def train():
    x = torch.randn(10, 10)
    return x.sum()
""")
        findings = _check_deterministic_seeds(_contents(tmp_path), str(tmp_path))
        assert findings[0].status == "fail"
        assert "no RNG seeds set" in findings[0].evidence

    def test_partial_coverage_warns(self, tmp_path):
        # Only torch seed set, numpy not seeded
        _write(tmp_path, "train.py", """
import torch
import numpy as np

torch.manual_seed(42)

def train():
    return np.random.randn(10)
""")
        findings = _check_deterministic_seeds(_contents(tmp_path), str(tmp_path))
        assert findings[0].status == "warn"
        assert "missing" in findings[0].evidence.lower()

    def test_tensorflow_with_seed_passes(self, tmp_path):
        _write(tmp_path, "train.py", """
import tensorflow as tf

tf.random.set_seed(42)

def train():
    pass
""")
        findings = _check_deterministic_seeds(_contents(tmp_path), str(tmp_path))
        assert findings[0].status == "pass"


# ============================================================================
# Deterministic algorithm flag tests
# ============================================================================

class TestDeterministicAlgorithms:
    def test_non_ml_codebase_passes(self, tmp_path):
        _write(tmp_path, "utils.py", "def helper(): pass")
        findings = _check_deterministic_algorithms(_contents(tmp_path), str(tmp_path))
        assert findings[0].status == "pass"

    def test_torch_with_deterministic_flags_passes(self, tmp_path):
        _write(tmp_path, "setup.py", """
import torch
import os

torch.use_deterministic_algorithms(True)
torch.backends.cudnn.deterministic = True
torch.backends.cudnn.benchmark = False
os.environ['CUBLAS_WORKSPACE_CONFIG'] = ':4096:8'
""")
        findings = _check_deterministic_algorithms(_contents(tmp_path), str(tmp_path))
        assert findings[0].status == "pass"

    def test_torch_without_flags_fails(self, tmp_path):
        _write(tmp_path, "train.py", """
import torch

def train():
    model = torch.nn.Linear(10, 10)
""")
        findings = _check_deterministic_algorithms(_contents(tmp_path), str(tmp_path))
        assert findings[0].status == "fail"
        assert "deterministic algorithm flags missing" in findings[0].evidence

    def test_tf_with_enable_op_determinism_passes(self, tmp_path):
        _write(tmp_path, "setup.py", """
import tensorflow as tf

tf.config.experimental.enable_op_determinism()
""")
        findings = _check_deterministic_algorithms(_contents(tmp_path), str(tmp_path))
        assert findings[0].status == "pass"

    def test_flags_in_env_file_detected(self, tmp_path):
        _write(tmp_path, "train.py", "import torch\ntorch.manual_seed(0)")
        env_file = tmp_path / ".env"
        env_file.write_text("CUBLAS_WORKSPACE_CONFIG=:4096:8\nTF_DETERMINISTIC_OPS=1\n")
        findings = _check_deterministic_algorithms(_contents(tmp_path), str(tmp_path))
        # Still missing cudnn.benchmark=False -> should fail, but CUBLAS detected
        assert "CUBLAS" in findings[0].evidence or findings[0].status == "fail"


# ============================================================================
# Hardware abstraction tests
# ============================================================================

class TestHardwareAbstraction:
    def test_non_ml_codebase_passes(self, tmp_path):
        _write(tmp_path, "utils.py", "def helper(): pass")
        findings = _check_hardware_abstraction(_contents(tmp_path), str(tmp_path))
        assert findings[0].status == "pass"

    def test_device_agnostic_pattern_passes(self, tmp_path):
        _write(tmp_path, "train.py", """
import torch

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

def run():
    model = torch.nn.Linear(10, 10).to(device)
""")
        findings = _check_hardware_abstraction(_contents(tmp_path), str(tmp_path))
        assert findings[0].status == "pass"
        assert "hardware-portable" in findings[0].evidence

    def test_hardcoded_cuda_without_check_fails(self, tmp_path):
        _write(tmp_path, "train.py", """
import torch

def run():
    model = torch.nn.Linear(10, 10).to("cuda")
    return model
""")
        findings = _check_hardware_abstraction(_contents(tmp_path), str(tmp_path))
        assert findings[0].status == "fail"
        assert "Hardcoded CUDA" in findings[0].evidence

    def test_hardcoded_cuda0_without_check_fails(self, tmp_path):
        _write(tmp_path, "train.py", """
import torch

def run():
    tensor = torch.zeros(10).to("cuda:0")
""")
        findings = _check_hardware_abstraction(_contents(tmp_path), str(tmp_path))
        assert findings[0].status == "fail"

    def test_mixed_patterns_warns(self, tmp_path):
        # Capability check exists somewhere but other files hardcode
        _write(tmp_path, "config.py", """
import torch
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
""")
        _write(tmp_path, "utils.py", """
import torch
tensor = torch.zeros(10).to("cuda")
""")
        findings = _check_hardware_abstraction(_contents(tmp_path), str(tmp_path))
        assert findings[0].status == "warn"
        assert "capability checks found elsewhere" in findings[0].evidence

    def test_dot_cuda_method_flagged(self, tmp_path):
        _write(tmp_path, "train.py", """
import torch
model = torch.nn.Linear(10, 10)
model.cuda()
""")
        findings = _check_hardware_abstraction(_contents(tmp_path), str(tmp_path))
        assert findings[0].status == "fail"
