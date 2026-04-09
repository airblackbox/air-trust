"""Tests for the badge command."""

import json
import subprocess
import sys
from pathlib import Path


class TestBadgeURLGeneration:
    """Test badge URL generation logic."""

    def test_score_to_color_brightgreen(self):
        """Score >= 90 should be brightgreen."""
        from air_trust.__main__ import _score_to_color

        assert _score_to_color(90) == "brightgreen"
        assert _score_to_color(95) == "brightgreen"
        assert _score_to_color(100) == "brightgreen"

    def test_score_to_color_yellow(self):
        """Score 70-89 should be yellow."""
        from air_trust.__main__ import _score_to_color

        assert _score_to_color(70) == "yellow"
        assert _score_to_color(75) == "yellow"
        assert _score_to_color(89) == "yellow"

    def test_score_to_color_orange(self):
        """Score 50-69 should be orange."""
        from air_trust.__main__ import _score_to_color

        assert _score_to_color(50) == "orange"
        assert _score_to_color(60) == "orange"
        assert _score_to_color(69) == "orange"

    def test_score_to_color_red(self):
        """Score < 50 should be red."""
        from air_trust.__main__ import _score_to_color

        assert _score_to_color(0) == "red"
        assert _score_to_color(25) == "red"
        assert _score_to_color(49) == "red"

    def test_badge_url_generation(self):
        """Test basic badge URL generation."""
        from air_trust.__main__ import _generate_badge_url

        url = _generate_badge_url("Test", "passed", "green", "flat")
        assert "img.shields.io/badge" in url
        assert "Test" in url
        assert "passed" in url
        assert "green" in url
        assert "flat" in url

    def test_badge_url_encoding(self):
        """Test URL encoding in badge URLs."""
        from air_trust.__main__ import _generate_badge_url

        url = _generate_badge_url("EU AI Act", "91% compliant", "brightgreen", "for-the-badge")
        assert "EU_AI_Act" in url
        assert "%25" in url or "%" not in url.split("badge/")[1].split("?")[0]  # % should be encoded
        assert "for-the-badge" in url

    def test_badge_url_styles(self):
        """Test different badge styles."""
        from air_trust.__main__ import _generate_badge_url

        for style in ["flat", "flat-square", "plastic", "for-the-badge"]:
            url = _generate_badge_url("Test", "data", "blue", style)
            assert f"style={style}" in url


class TestBadgeCommand:
    """Test the badge CLI command."""

    def test_badge_command_exists(self):
        """Badge command should be in help output."""
        result = subprocess.run(
            [sys.executable, "-m", "air_trust", "--help"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "badge" in result.stdout.lower()

    def test_badge_markdown_output(self):
        """Badge command should output markdown format."""
        result = subprocess.run(
            [sys.executable, "-m", "air_trust", "badge", "--format", "markdown"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        # Should output at least the audit chain badge (always present)
        assert "![" in result.stdout  # Markdown image syntax
        assert "Audit_Chain" in result.stdout

    def test_badge_html_output(self):
        """Badge command should output HTML format."""
        result = subprocess.run(
            [sys.executable, "-m", "air_trust", "badge", "--format", "html"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        # Should output at least the audit chain badge
        assert "<img" in result.stdout  # HTML img tag
        assert "Audit_Chain" in result.stdout

    def test_badge_style_flat(self):
        """Badge command should support flat style."""
        result = subprocess.run(
            [sys.executable, "-m", "air_trust", "badge", "--style", "flat"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "style=flat" in result.stdout or "flat" in result.stdout

    def test_badge_style_flat_square(self):
        """Badge command should support flat-square style."""
        result = subprocess.run(
            [sys.executable, "-m", "air_trust", "badge", "--style", "flat-square"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "flat-square" in result.stdout

    def test_badge_style_plastic(self):
        """Badge command should support plastic style."""
        result = subprocess.run(
            [sys.executable, "-m", "air_trust", "badge", "--style", "plastic"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "plastic" in result.stdout

    def test_badge_style_for_the_badge(self):
        """Badge command should support for-the-badge style (default)."""
        result = subprocess.run(
            [sys.executable, "-m", "air_trust", "badge"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "for-the-badge" in result.stdout

    def test_badge_contains_audit_chain(self):
        """Badge output should always include audit chain badge."""
        result = subprocess.run(
            [sys.executable, "-m", "air_trust", "badge"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "Audit_Chain" in result.stdout
        assert ("verified" in result.stdout or "not_verified" in result.stdout)

    def test_badge_contains_valid_url(self):
        """Badge output should contain valid shield.io URLs."""
        result = subprocess.run(
            [sys.executable, "-m", "air_trust", "badge"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "https://img.shields.io/badge/" in result.stdout

    def test_badge_default_format_is_markdown(self):
        """Default format should be markdown."""
        result = subprocess.run(
            [sys.executable, "-m", "air_trust", "badge"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "![" in result.stdout  # Markdown syntax

    def test_badge_default_style_is_for_the_badge(self):
        """Default style should be for-the-badge."""
        result = subprocess.run(
            [sys.executable, "-m", "air_trust", "badge"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "for-the-badge" in result.stdout
