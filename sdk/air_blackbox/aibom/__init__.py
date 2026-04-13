"""AI Bill of Materials (AIBOM) components.

Provides tools for generating and managing AI Bills of Materials
with compliance documentation and shadow AI detection.
"""

from .generator import AIBOMEntry, AIBOMGenerator
from .shadow import RiskClassification, ShadowAIDetector, ShadowAIFinding

__all__ = [
    "AIBOMGenerator",
    "AIBOMEntry",
    "ShadowAIDetector",
    "ShadowAIFinding",
    "RiskClassification",
]
