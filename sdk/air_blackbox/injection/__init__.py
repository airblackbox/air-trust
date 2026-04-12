"""Prompt injection detection and prevention.

Provides tools for detecting and mitigating prompt injection attacks
in AI system inputs and interactions.
"""

from .detector import InjectionDetector, InjectionResult

__all__ = ["InjectionDetector", "InjectionResult"]
