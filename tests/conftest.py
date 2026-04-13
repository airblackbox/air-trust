"""Shared fixtures for AIR Blackbox test suite."""

import os

import pytest


@pytest.fixture(autouse=True)
def _preserve_cwd():
    """Ensure tests don't change the working directory for subsequent tests."""
    original = os.getcwd()
    yield
    os.chdir(original)
