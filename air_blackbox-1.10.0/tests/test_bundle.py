"""
Tests for the self-verifying evidence bundle (.air-evidence) creator.

Covers bundle creation, contents verification, manifest integrity,
signature validation, verify.py script, and tamper detection.
"""

import json
import subprocess
import sys
import zipfile
import pytest
from pathlib import Path

from air_blackbox.evidence.keys import KeyManager
from air_blackbox.evidence.signer import EvidenceSigner
from air_blackbox.evidence.bundle import EvidenceBundleBuilder


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def key_manager(tmp_path):
    """KeyManager with generated keys."""
    km = KeyManager(key_dir=tmp_path / "keys")
    km.generate()
    return km


@pytest.fixture
def builder(key_manager):
    """EvidenceBundleBuilder ready to build."""
    return EvidenceBundleBuilder(key_manager=key_manager)


@pytest.fixture
def sample_scan():
    """Minimal scan results dict."""
    return {
        "framework": "EU AI Act",
        "articles_checked": [9, 10, 11, 12, 14, 15],
        "results": [
            {
                "article": 9,
                "checks": [
                    {"name": "Risk management policy", "status": "pass", "evidence": "Found risk assessment doc"},
                ]
            },
            {
                "article": 12,
                "checks": [
                    {"name": "Record-keeping", "status": "warn", "evidence": "Partial audit logging"},
                ]
            },
        ],
        "summary": {
            "total_checks": 2,
            "passing": 1,
            "warnings": 1,
            "failing": 0,
        }
    }


@pytest.fixture
def sample_crosswalk():
    """Minimal crosswalk report dict."""
    return {
        "frameworks": ["eu", "iso42001"],
        "by_category": {
            "risk_management": {
                "eu": "Article 9",
                "iso42001": "6.1.1",
                "status": "pass",
            }
        }
    }


@pytest.fixture
def bundle_path(builder, sample_scan, sample_crosswalk, tmp_path):
    """Build a bundle and return its path."""
    return builder.build(
        scan_results=sample_scan,
        crosswalk_report=sample_crosswalk,
        frameworks=["eu", "iso42001", "nist", "colorado"],
        output_dir=tmp_path / "output",
    )


# ---------------------------------------------------------------------------
# Bundle Creation Tests
# ---------------------------------------------------------------------------

class TestBundleCreation:
    """Tests for evidence bundle file creation."""

    def test_bundle_is_created(self, bundle_path):
        """Build produces a .air-evidence file."""
        assert bundle_path.exists()
        assert bundle_path.suffix == ".air-evidence"

    def test_bundle_is_valid_zip(self, bundle_path):
        """The .air-evidence file is a valid ZIP archive."""
        assert zipfile.is_zipfile(bundle_path)

    def test_bundle_contains_required_files(self, bundle_path):
        """Bundle contains all required files."""
        with zipfile.ZipFile(bundle_path) as zf:
            names = [Path(n).name for n in zf.namelist()]
            # Also check by relative path within the bundle dir
            rel_paths = set()
            for n in zf.namelist():
                parts = Path(n).parts
                if len(parts) > 1:
                    rel_paths.add("/".join(parts[1:]))

        required = [
            "manifest.json",
            "manifest.sig",
            "scan/results.json",
            "scan/results.sig",
            "scan/summary.json",
            "verify.py",
            "README.md",
            "keys/public_key.bin",
            "metadata/scanner.json",
            "metadata/timestamp.json",
            "metadata/frameworks.json",
        ]
        for req in required:
            assert req in rel_paths, f"Missing required file: {req}"

    def test_bundle_includes_crosswalk(self, bundle_path):
        """Crosswalk report is included when provided."""
        with zipfile.ZipFile(bundle_path) as zf:
            rel_paths = set()
            for n in zf.namelist():
                parts = Path(n).parts
                if len(parts) > 1:
                    rel_paths.add("/".join(parts[1:]))
        assert "scan/crosswalk.json" in rel_paths

    def test_bundle_without_crosswalk(self, builder, sample_scan, tmp_path):
        """Bundle works without crosswalk report."""
        path = builder.build(
            scan_results=sample_scan,
            output_dir=tmp_path / "no_crosswalk",
        )
        assert path.exists()
        with zipfile.ZipFile(path) as zf:
            rel_paths = set()
            for n in zf.namelist():
                parts = Path(n).parts
                if len(parts) > 1:
                    rel_paths.add("/".join(parts[1:]))
        assert "scan/crosswalk.json" not in rel_paths

    def test_bundle_size_is_reasonable(self, bundle_path):
        """Bundle is under 1MB for a simple scan (sanity check)."""
        assert bundle_path.stat().st_size < 1_000_000


# ---------------------------------------------------------------------------
# Manifest Tests
# ---------------------------------------------------------------------------

class TestManifest:
    """Tests for manifest.json integrity."""

    def _read_bundle_file(self, bundle_path, rel_path):
        """Read a file from inside the bundle ZIP."""
        with zipfile.ZipFile(bundle_path) as zf:
            for name in zf.namelist():
                if name.endswith(rel_path):
                    return zf.read(name)
        return None

    def test_manifest_is_valid_json(self, bundle_path):
        """manifest.json is valid JSON."""
        data = self._read_bundle_file(bundle_path, "manifest.json")
        manifest = json.loads(data)
        assert "files" in manifest
        assert "bundle_name" in manifest

    def test_manifest_has_all_file_hashes(self, bundle_path):
        """Every file in the bundle (except manifest.sig) is in the manifest."""
        manifest_data = self._read_bundle_file(bundle_path, "manifest.json")
        manifest = json.loads(manifest_data)
        manifest_files = set(manifest["files"].keys())

        with zipfile.ZipFile(bundle_path) as zf:
            for name in zf.namelist():
                parts = Path(name).parts
                if len(parts) > 1:
                    rel = "/".join(parts[1:])
                    # manifest.sig is created after manifest.json, so it's not in the manifest
                    if rel not in ("manifest.json", "manifest.sig"):
                        assert rel in manifest_files, f"File not in manifest: {rel}"

    def test_manifest_hashes_are_correct(self, bundle_path):
        """SHA-256 hashes in manifest match actual file contents."""
        import hashlib

        manifest_data = self._read_bundle_file(bundle_path, "manifest.json")
        manifest = json.loads(manifest_data)

        with zipfile.ZipFile(bundle_path) as zf:
            for rel_path, info in manifest["files"].items():
                # Find the file in the ZIP
                for name in zf.namelist():
                    if name.endswith(rel_path):
                        content = zf.read(name)
                        actual_hash = hashlib.sha256(content).hexdigest()
                        assert actual_hash == info["sha256"], (
                            f"Hash mismatch for {rel_path}: "
                            f"expected {info['sha256']}, got {actual_hash}"
                        )
                        break

    def test_manifest_has_monotonic_counter(self, bundle_path):
        """Manifest includes a monotonic counter for ordering."""
        data = self._read_bundle_file(bundle_path, "manifest.json")
        manifest = json.loads(data)
        assert "monotonic_counter" in manifest
        assert manifest["monotonic_counter"] >= 1

    def test_monotonic_counter_increments(self, builder, sample_scan, tmp_path):
        """Counter increments across bundle builds."""
        p1 = builder.build(scan_results=sample_scan, output_dir=tmp_path / "b1")
        p2 = builder.build(scan_results=sample_scan, output_dir=tmp_path / "b2")

        with zipfile.ZipFile(p1) as zf:
            for name in zf.namelist():
                if name.endswith("manifest.json"):
                    m1 = json.loads(zf.read(name))
        with zipfile.ZipFile(p2) as zf:
            for name in zf.namelist():
                if name.endswith("manifest.json"):
                    m2 = json.loads(zf.read(name))

        assert m2["monotonic_counter"] == m1["monotonic_counter"] + 1


# ---------------------------------------------------------------------------
# Signature Tests
# ---------------------------------------------------------------------------

class TestSignatures:
    """Tests for ML-DSA-65 signatures in the bundle."""

    def _read_bundle_file(self, bundle_path, rel_path):
        with zipfile.ZipFile(bundle_path) as zf:
            for name in zf.namelist():
                if name.endswith(rel_path):
                    return zf.read(name)
        return None

    def test_manifest_sig_exists(self, bundle_path):
        """manifest.sig is present in the bundle."""
        data = self._read_bundle_file(bundle_path, "manifest.sig")
        assert data is not None
        sig = json.loads(data)
        assert sig["algorithm"] == "ML-DSA-65"

    def test_results_sig_exists(self, bundle_path):
        """scan/results.sig is present in the bundle."""
        data = self._read_bundle_file(bundle_path, "results.sig")
        assert data is not None
        sig = json.loads(data)
        assert sig["algorithm"] == "ML-DSA-65"

    def test_manifest_signature_verifies(self, bundle_path, key_manager):
        """Manifest signature is cryptographically valid."""
        manifest_bytes = self._read_bundle_file(bundle_path, "manifest.json")
        sig_data = self._read_bundle_file(bundle_path, "manifest.sig")
        sig = json.loads(sig_data)

        signer = EvidenceSigner(key_manager=key_manager)
        assert signer.verify_bytes(
            manifest_bytes, sig["signature_hex"]
        ) is True

    def test_results_signature_verifies(self, bundle_path, key_manager):
        """Scan results signature is cryptographically valid."""
        results_bytes = self._read_bundle_file(bundle_path, "scan/results.json")
        sig_data = self._read_bundle_file(bundle_path, "scan/results.sig")
        sig = json.loads(sig_data)

        signer = EvidenceSigner(key_manager=key_manager)
        assert signer.verify_bytes(
            results_bytes, sig["signature_hex"]
        ) is True

    def test_public_key_in_bundle_matches(self, bundle_path, key_manager):
        """Public key in the bundle matches the signing key."""
        pk_in_bundle = self._read_bundle_file(bundle_path, "public_key.bin")
        pk_on_disk = key_manager.load_public_key()
        assert pk_in_bundle == pk_on_disk


# ---------------------------------------------------------------------------
# Verify Script Tests
# ---------------------------------------------------------------------------

class TestVerifyScript:
    """Tests for the standalone verify.py script."""

    def test_verify_script_is_included(self, bundle_path):
        """verify.py is present in the bundle."""
        with zipfile.ZipFile(bundle_path) as zf:
            names = [Path(n).name for n in zf.namelist()]
        assert "verify.py" in names

    def test_verify_script_is_valid_python(self, bundle_path, tmp_path):
        """verify.py compiles without syntax errors."""
        # Extract the bundle
        with zipfile.ZipFile(bundle_path) as zf:
            zf.extractall(tmp_path / "extracted")

        # Find verify.py
        verify_files = list((tmp_path / "extracted").rglob("verify.py"))
        assert len(verify_files) >= 1

        # Compile check (no syntax errors)
        result = subprocess.run(
            [sys.executable, "-m", "py_compile", str(verify_files[0])],
            capture_output=True, text=True
        )
        assert result.returncode == 0, f"verify.py has syntax errors: {result.stderr}"

    def test_verify_script_passes_on_valid_bundle(self, bundle_path, tmp_path):
        """verify.py exits 0 on an untampered bundle."""
        extract_dir = tmp_path / "valid_bundle"
        with zipfile.ZipFile(bundle_path) as zf:
            zf.extractall(extract_dir)

        # Find the bundle directory (contains manifest.json)
        bundle_dirs = list(extract_dir.rglob("manifest.json"))
        assert len(bundle_dirs) >= 1
        bundle_dir = bundle_dirs[0].parent

        result = subprocess.run(
            [sys.executable, str(bundle_dir / "verify.py")],
            capture_output=True, text=True, cwd=str(bundle_dir)
        )
        assert result.returncode == 0, f"verify.py failed:\n{result.stdout}\n{result.stderr}"
        assert "PASS" in result.stdout

    def test_verify_script_fails_on_tampered_file(self, bundle_path, tmp_path):
        """verify.py exits 1 when a file has been modified."""
        extract_dir = tmp_path / "tampered_bundle"
        with zipfile.ZipFile(bundle_path) as zf:
            zf.extractall(extract_dir)

        # Find and tamper with results.json
        results_files = list(extract_dir.rglob("results.json"))
        assert len(results_files) >= 1
        results_file = results_files[0]

        # Modify the scan results
        data = json.loads(results_file.read_text(encoding="utf-8"))
        data["tampered"] = True
        results_file.write_text(json.dumps(data), encoding="utf-8")

        bundle_dir = results_file.parent.parent  # go up from scan/ to bundle root

        result = subprocess.run(
            [sys.executable, str(bundle_dir / "verify.py")],
            capture_output=True, text=True, cwd=str(bundle_dir)
        )
        assert result.returncode == 1, f"verify.py should fail on tampered bundle:\n{result.stdout}"
        assert "FAIL" in result.stdout


# ---------------------------------------------------------------------------
# Metadata Tests
# ---------------------------------------------------------------------------

class TestMetadata:
    """Tests for bundle metadata files."""

    def _read_bundle_json(self, bundle_path, rel_path):
        with zipfile.ZipFile(bundle_path) as zf:
            for name in zf.namelist():
                if name.endswith(rel_path):
                    return json.loads(zf.read(name))
        return None

    def test_scanner_metadata(self, bundle_path):
        """Scanner metadata includes version and platform info."""
        meta = self._read_bundle_json(bundle_path, "scanner.json")
        assert meta is not None
        assert meta["tool"] == "air-blackbox"
        assert "version" in meta
        assert "python_version" in meta
        assert "os" in meta

    def test_timestamp_metadata(self, bundle_path):
        """Timestamp metadata includes ISO 8601 and monotonic counter."""
        meta = self._read_bundle_json(bundle_path, "timestamp.json")
        assert meta is not None
        assert "generated_at" in meta
        assert "monotonic_counter" in meta
        assert meta["timezone"] == "UTC"

    def test_frameworks_metadata(self, bundle_path):
        """Frameworks metadata lists the evaluated frameworks."""
        meta = self._read_bundle_json(bundle_path, "frameworks.json")
        assert meta is not None
        assert "eu" in meta["frameworks_evaluated"]

    def test_readme_exists_and_has_content(self, bundle_path):
        """README.md exists and contains verification instructions."""
        with zipfile.ZipFile(bundle_path) as zf:
            for name in zf.namelist():
                if name.endswith("README.md"):
                    content = zf.read(name).decode("utf-8")
                    assert "python verify.py" in content
                    assert "ML-DSA-65" in content
                    return
        pytest.fail("README.md not found in bundle")


# ---------------------------------------------------------------------------
# Edge Cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    """Edge case and boundary tests."""

    def test_bundle_with_empty_scan(self, builder, tmp_path):
        """Bundle works with empty scan results."""
        path = builder.build(
            scan_results={},
            output_dir=tmp_path / "empty",
        )
        assert path.exists()
        assert zipfile.is_zipfile(path)

    def test_bundle_with_scanned_file_hashes(self, builder, sample_scan, tmp_path):
        """Bundle includes scanned file hashes when provided."""
        hashes = {
            "main.py": "abc123" * 10 + "abcd",
            "utils.py": "def456" * 10 + "defg",
        }
        path = builder.build(
            scan_results=sample_scan,
            output_dir=tmp_path / "with_hashes",
            scanned_files_hashes=hashes,
        )
        with zipfile.ZipFile(path) as zf:
            for name in zf.namelist():
                if name.endswith("scanned_files.json"):
                    data = json.loads(zf.read(name))
                    assert "main.py" in data
                    return
        pytest.fail("scanned_files.json not found in bundle")
