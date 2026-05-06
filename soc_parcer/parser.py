"""
SOCParser: Robust field extractor for SLM security classification output.

Handles the full spectrum of format drift observed in instruction-tuned
models at the 1B-7B scale:
  - Field name case variation (THREAT_TYPE vs Threat Type vs threat_type)
  - Separator variation (colon, dash, equals)
  - Missing underscores (THREAT TYPE vs THREAT_TYPE)
  - Prompt repetition loop artifacts
"""

import re
from typing import Optional


# All regex patterns that match known field name variations
_FIELD_PATTERNS = {
    "THREAT_TYPE": re.compile(
        r"Threat[\s_\-]*Type[\s]*[:\-=]+\s*([^\n]+)",
        re.IGNORECASE
    ),
    "SEVERITY": re.compile(
        r"Severity[\s]*[:\-=]+\s*([^\n]+)",
        re.IGNORECASE
    ),
    "MITRE_TECHNIQUE": re.compile(
        r"MITRE[\s_\-]*Technique[\s_\-]*(?:ID)?[\s]*[:\-=]+\s*([^\n]+)",
        re.IGNORECASE
    ),
    "MITRE_TACTIC": re.compile(
        r"MITRE[\s_\-]*Tactic[\s]*[:\-=]+\s*([^\n]+)",
        re.IGNORECASE
    ),
    "RISK_SCORE": re.compile(
        r"Risk[\s_\-]*Score[\s]*[:\-=]+\s*([^\n]+)",
        re.IGNORECASE
    ),
}

# Markers that indicate the model has started looping into the next prompt
_LOOP_MARKERS = [
    "### Input:",
    "### Instruction:",
    "### Response:",
    "### Human:",
    "### Assistant:",
]

SEVERITY_CANONICAL = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"}


class SOCParser:
    """
    Fuzzy field parser for SLM security classification output.

    Replaces rigid regex-based extraction with format-tolerant matching
    that handles the full range of field name drift observed in
    instruction-tuned models at the 1B-7B scale.

    Args:
        truncate_loops (bool): If True, truncate output at prompt-repetition
            markers before parsing. Default: True.
        normalize_severity (bool): If True, map severity values to canonical
            set (CRITICAL/HIGH/MEDIUM/LOW/INFORMATIONAL). Default: True.
    """

    def __init__(
        self,
        truncate_loops: bool = True,
        normalize_severity: bool = True,
    ):
        self.truncate_loops = truncate_loops
        self.normalize_severity = normalize_severity

    def _truncate(self, text: str) -> str:
        """Remove prompt-repetition loop artifacts."""
        for marker in _LOOP_MARKERS:
            idx = text.find(marker)
            if idx > 0:
                text = text[:idx]
        return text.strip()

    def _normalize_severity(self, raw: str) -> str:
        """Map severity value to canonical form."""
        token = raw.strip().upper().split()[0] if raw.strip() else ""
        # Direct match
        if token in SEVERITY_CANONICAL:
            return token
        # Partial match
        for canonical in SEVERITY_CANONICAL:
            if canonical in token or token in canonical:
                return canonical
        return token

    def parse(self, text: str) -> dict:
        """
        Parse structured fields from SLM output text.

        Args:
            text: Raw model output string.

        Returns:
            dict with keys: THREAT_TYPE, SEVERITY, MITRE_TECHNIQUE,
            MITRE_TACTIC, RISK_SCORE. Values are None if field not found.
        """
        if self.truncate_loops:
            text = self._truncate(text)

        result = {field: None for field in _FIELD_PATTERNS}

        for field, pattern in _FIELD_PATTERNS.items():
            match = pattern.search(text)
            if match:
                value = match.group(1).strip()
                # Remove trailing punctuation artifacts
                value = re.sub(r"[,;]+$", "", value).strip()
                if not value:
                    continue
                if field == "SEVERITY" and self.normalize_severity:
                    value = self._normalize_severity(value)
                result[field] = value

        return result

    def parse_batch(self, texts: list) -> list:
        """Parse a list of model outputs. Returns list of dicts."""
        return [self.parse(t) for t in texts]
