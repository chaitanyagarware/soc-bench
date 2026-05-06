"""
SOCBenchScorer: Standardized evaluation scorer for SOC-Bench.

Implements the SOC-Bench evaluation protocol:
- Fuzzy field extraction (via SOCParser)
- Broad-category normalization (via ThreatNormalizer)
- Macro-averaged broad-category accuracy as primary metric
- Per-class accuracy with Wilson confidence intervals
- Strict vs fuzzy comparison reporting
"""

import math
from typing import Optional
from .parser import SOCParser
from .normalizer import ThreatNormalizer


def _wilson_ci(correct: int, total: int, confidence: float = 0.95) -> tuple:
    """
    Wilson score confidence interval for a proportion.
    Returns (lower, upper) bounds.
    """
    if total == 0:
        return (0.0, 1.0)
    # z for 95% confidence
    z = 1.96 if confidence == 0.95 else 2.576
    p = correct / total
    denom = 1 + z**2 / total
    center = (p + z**2 / (2 * total)) / denom
    spread = (z * math.sqrt(p * (1 - p) / total + z**2 / (4 * total**2))) / denom
    return (max(0.0, center - spread), min(1.0, center + spread))


class SOCBenchScorer:
    """
    SOC-Bench compliant evaluation scorer.

    Args:
        parser: SOCParser instance. Uses default if None.
        normalizer: ThreatNormalizer instance. Uses default if None.
    """

    def __init__(
        self,
        parser: Optional[SOCParser] = None,
        normalizer: Optional[ThreatNormalizer] = None,
    ):
        self.parser = parser or SOCParser()
        self.normalizer = normalizer or ThreatNormalizer()

    def score(
        self,
        predictions: list,
        ground_truths: list,
    ) -> dict:
        """
        Score model predictions against ground truth labels.

        Args:
            predictions: List of raw model output strings.
            ground_truths: List of ground truth output strings (same format).

        Returns:
            dict with keys:
                - threat_accuracy: Overall threat classification accuracy
                - severity_accuracy: Overall severity accuracy
                - macro_accuracy: Macro-averaged per-class accuracy
                - per_class: Dict of {category: {correct, total, accuracy, ci}}
                - per_example: List of per-example result dicts
        """
        assert len(predictions) == len(ground_truths), \
            "predictions and ground_truths must have the same length"

        per_example = []
        class_stats = {}

        threat_correct = 0
        severity_correct = 0

        for i, (pred_text, gt_text) in enumerate(zip(predictions, ground_truths)):
            pred = self.parser.parse(pred_text)
            gt   = self.parser.parse(
                gt_text
                .replace("THREAT_TYPE", "Threat Type")
                .replace("SEVERITY", "Severity")
                .replace("MITRE_TECHNIQUE", "MITRE Technique ID")
            )

            pred_threat = self.normalizer.normalize(pred.get("THREAT_TYPE") or "")
            gt_threat   = self.normalizer.normalize(gt.get("THREAT_TYPE") or "")
            pred_sev    = (pred.get("SEVERITY") or "").split()[0]
            gt_sev      = (gt.get("SEVERITY") or "").split()[0]

            threat_match   = bool(pred_threat) and (pred_threat == gt_threat)
            severity_match = bool(pred_sev) and (pred_sev == gt_sev)

            threat_correct   += int(threat_match)
            severity_correct += int(severity_match)

            # Per-class tracking
            if gt_threat:
                if gt_threat not in class_stats:
                    class_stats[gt_threat] = {"correct": 0, "total": 0}
                class_stats[gt_threat]["total"] += 1
                class_stats[gt_threat]["correct"] += int(threat_match)

            per_example.append({
                "index":         i,
                "pred_threat":   pred_threat,
                "gt_threat":     gt_threat,
                "threat_match":  threat_match,
                "pred_severity": pred_sev,
                "gt_severity":   gt_sev,
                "sev_match":     severity_match,
            })

        n = len(predictions)

        # Per-class accuracy + confidence intervals
        per_class = {}
        class_accuracies = []
        for cat, stats in class_stats.items():
            acc = stats["correct"] / stats["total"] if stats["total"] > 0 else 0.0
            ci  = _wilson_ci(stats["correct"], stats["total"])
            per_class[cat] = {
                "correct":  stats["correct"],
                "total":    stats["total"],
                "accuracy": round(acc, 4),
                "ci_95":    (round(ci[0], 3), round(ci[1], 3)),
            }
            class_accuracies.append(acc)

        macro_acc = sum(class_accuracies) / len(class_accuracies) if class_accuracies else 0.0

        return {
            "threat_accuracy":   round(threat_correct / n, 4),
            "severity_accuracy": round(severity_correct / n, 4),
            "macro_accuracy":    round(macro_acc, 4),
            "n_examples":        n,
            "per_class":         per_class,
            "per_example":       per_example,
        }

    def compare_parsers(
        self,
        predictions: list,
        ground_truths: list,
    ) -> dict:
        """
        Compare strict regex parser vs fuzzy parser on the same predictions.
        Quantifies parsing-induced recall suppression.

        Returns dict with strict_results, fuzzy_results, and delta.
        """
        import re

        # Strict parser (original approach)
        def strict_extract(text):
            fields = {}
            for key in ["THREAT_TYPE", "SEVERITY", "MITRE_ID"]:
                m = re.search(rf"{key}[:\s]+([^\n,]+)", text, re.IGNORECASE)
                if m:
                    fields[key] = m.group(1).strip().upper()
            return fields

        strict_threat = 0
        strict_sev    = 0

        for pred_text, gt_text in zip(predictions, ground_truths):
            s   = strict_extract(pred_text)
            gt  = self.parser.parse(
                gt_text
                .replace("THREAT_TYPE", "Threat Type")
                .replace("SEVERITY", "Severity")
            )
            gt_threat = self.normalizer.normalize(gt.get("THREAT_TYPE") or "")
            gt_sev    = (gt.get("SEVERITY") or "").split()[0]

            pred_t = self.normalizer.normalize(s.get("THREAT_TYPE", ""))
            pred_s = s.get("SEVERITY", "").split()[0] if s.get("SEVERITY") else ""

            strict_threat += int(bool(pred_t) and pred_t == gt_threat)
            strict_sev    += int(bool(pred_s) and pred_s == gt_sev)

        n = len(predictions)
        fuzzy = self.score(predictions, ground_truths)

        strict_threat_acc = strict_threat / n
        strict_sev_acc    = strict_sev / n

        return {
            "strict": {
                "threat_accuracy":   round(strict_threat_acc, 4),
                "severity_accuracy": round(strict_sev_acc, 4),
            },
            "fuzzy": {
                "threat_accuracy":   fuzzy["threat_accuracy"],
                "severity_accuracy": fuzzy["severity_accuracy"],
            },
            "delta": {
                "threat_accuracy":   round(fuzzy["threat_accuracy"] - strict_threat_acc, 4),
                "severity_accuracy": round(fuzzy["severity_accuracy"] - strict_sev_acc, 4),
            },
            "parsing_suppression_pp": round(
                (fuzzy["threat_accuracy"] - strict_threat_acc) * 100, 1
            ),
        }
