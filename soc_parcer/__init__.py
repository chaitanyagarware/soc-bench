"""
soc-parser: Fuzzy field extractor for SLM-based SOC log classifiers.

Addresses parsing-induced recall suppression in LLM security output evaluation.
Reference: Garware, C.V. (2026) - Failure Modes of Fine-Tuned SLMs for
Security Log Classification.

Usage:
    from soc_parser import SOCParser
    parser = SOCParser()
    result = parser.parse("Threat Type: SQL Injection\\nSeverity: High")
    # {'THREAT_TYPE': 'SQL INJECTION', 'SEVERITY': 'HIGH', 'MITRE_TECHNIQUE': None}
"""

from .parser import SOCParser
from .normalizer import ThreatNormalizer
from .scorer import SOCBenchScorer

__version__ = "0.1.0"
__author__ = "Chaitanya Vilas Garware"
__all__ = ["SOCParser", "ThreatNormalizer", "SOCBenchScorer"]
