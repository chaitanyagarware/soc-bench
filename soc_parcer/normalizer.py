"""
ThreatNormalizer: Maps fine-grained model output labels to SOC-Bench
canonical broad categories.

This is necessary because models trained on broad labels (e.g. "SQL Injection")
produce outputs that don't exactly match subcategory evaluation labels
(e.g. "SQL Injection -- OS Command via SQLi"). Normalization to canonical
categories enables fair comparison across models and training taxonomies.
"""

# SOC-Bench canonical category set (13 categories, aligned to MITRE ATT&CK v14)
CANONICAL_CATEGORIES = {
    "SB-01": "SQL INJECTION",
    "SB-02": "XSS",
    "SB-03": "COMMAND INJECTION",
    "SB-04": "PATH TRAVERSAL",
    "SB-05": "LFI",
    "SB-06": "BRUTE FORCE",
    "SB-07": "CREDENTIAL STUFFING",
    "SB-08": "RECONNAISSANCE",
    "SB-09": "DDOS",
    "SB-10": "DATA EXFILTRATION",
    "SB-11": "LATERAL MOVEMENT",
    "SB-12": "MALWARE C2",
    "SB-13": "NO THREAT",
}

# Keyword rules: if any keyword found in label → canonical category
_NORMALIZATION_RULES = [
    (["sql", "sqli", "sql injection"],                          "SQL INJECTION"),
    (["xss", "cross-site scripting", "cross site scripting",
      "scripting"],                                             "XSS"),
    (["command injection", "os command", "cmd injection"],      "COMMAND INJECTION"),
    (["path traversal", "directory traversal"],                 "PATH TRAVERSAL"),
    (["local file inclusion", " lfi", "lfi "],                  "LFI"),
    (["ssh brute", "ssh brute force"],                          "SSH BRUTE FORCE"),
    (["brute force"],                                           "BRUTE FORCE"),
    (["credential stuffing"],                                   "CREDENTIAL STUFFING"),
    (["reconnaissance", "vulnerability scanning", "port scan",
      "scanning"],                                              "RECONNAISSANCE"),
    (["denial of service", "ddos", "dos attack"],               "DDOS"),
    (["exfiltration", "data exfil"],                            "DATA EXFILTRATION"),
    (["lateral movement", "privilege escalation"],              "LATERAL MOVEMENT"),
    (["malware", "command and control", "c2", "c&c",
      "backdoor"],                                              "MALWARE C2"),
    (["no threat", "normal traffic", "benign", "legitimate"],   "NO THREAT"),
    (["windows threat", "windows event"],                       "WINDOWS THREAT"),
]


class ThreatNormalizer:
    """
    Maps raw threat label strings to SOC-Bench canonical categories.

    Handles both model output labels and ground truth subcategory labels,
    enabling fair comparison across different labeling granularities.

    Usage:
        normalizer = ThreatNormalizer()
        normalizer.normalize("SQL Injection -- OS Command via SQLi")
        # "SQL INJECTION"
        normalizer.normalize("Threat Type: Cross-Site Scripting (XSS)")
        # "XSS"
    """

    def normalize(self, raw: str) -> str:
        """
        Normalize a raw threat label to a SOC-Bench canonical category.

        Args:
            raw: Raw threat label string from model output or ground truth.

        Returns:
            Canonical category string, or the uppercased input if no match.
        """
        if not raw:
            return ""
        text = raw.lower().strip()

        for keywords, canonical in _NORMALIZATION_RULES:
            if any(kw in text for kw in keywords):
                return canonical

        return raw.upper().strip()

    def normalize_batch(self, labels: list) -> list:
        """Normalize a list of raw labels."""
        return [self.normalize(l) for l in labels]

    @staticmethod
    def list_canonical() -> dict:
        """Return the full SOC-Bench canonical category mapping."""
        return CANONICAL_CATEGORIES.copy()
