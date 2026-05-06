"""
SOC-Bench v0: Standardized evaluation script for SLM-based SOC log classifiers.

Usage:
    python evaluate.py --predictions preds.json --ground_truth soc_eval.json

Input format (both files): list of dicts with 'output' field containing
model-formatted structured output.

Reference:
    Garware, C.V. (2026). Failure Modes of Fine-Tuned Small Language Models
    for Security Log Classification. arXiv preprint.
"""

import json
import argparse
import re
import math
from pathlib import Path


# ── SOC-Bench canonical categories ────────────────────────────────────────────
CANONICAL = {
    "SQL INJECTION", "XSS", "COMMAND INJECTION", "PATH TRAVERSAL",
    "LFI", "BRUTE FORCE", "SSH BRUTE FORCE", "CREDENTIAL STUFFING",
    "RECONNAISSANCE", "DDOS", "DATA EXFILTRATION", "LATERAL MOVEMENT",
    "MALWARE C2", "NO THREAT", "WINDOWS THREAT",
}

NORMALIZATION_RULES = [
    (["sql", "sqli"],                                   "SQL INJECTION"),
    (["xss", "cross-site scripting", "cross site"],     "XSS"),
    (["command injection", "os command"],               "COMMAND INJECTION"),
    (["path traversal", "directory traversal"],         "PATH TRAVERSAL"),
    (["local file inclusion", "lfi"],                   "LFI"),
    (["ssh brute"],                                     "SSH BRUTE FORCE"),
    (["brute force"],                                   "BRUTE FORCE"),
    (["credential stuffing"],                           "CREDENTIAL STUFFING"),
    (["reconnaissance", "scanning", "scan"],            "RECONNAISSANCE"),
    (["denial of service", "ddos"],                     "DDOS"),
    (["exfiltration"],                                  "DATA EXFILTRATION"),
    (["lateral movement", "privilege escalation"],      "LATERAL MOVEMENT"),
    (["malware", "c2", "command and control"],          "MALWARE C2"),
    (["no threat", "normal traffic", "benign"],         "NO THREAT"),
    (["windows threat", "windows event"],               "WINDOWS THREAT"),
]

LOOP_MARKERS = ["### Input:", "### Instruction:", "### Response:"]


def truncate_loops(text: str) -> str:
    for marker in LOOP_MARKERS:
        idx = text.find(marker)
        if idx > 0:
            text = text[:idx]
    return text.strip()


def extract_fuzzy(text: str) -> dict:
    """Fuzzy field extractor — handles all common field name format variations."""
    text = truncate_loops(text)
    fields = {}
    patterns = {
        "THREAT_TYPE":     r"Threat[\s_\-]*Type[\s]*[:\-=]+\s*([^\n]+)",
        "SEVERITY":        r"Severity[\s]*[:\-=]+\s*([^\n]+)",
        "MITRE_TECHNIQUE": r"MITRE[\s_\-]*Technique[\s_\-]*(?:ID)?[\s]*[:\-=]+\s*([^\n]+)",
    }
    for field, pattern in patterns.items():
        m = re.search(pattern, text, re.IGNORECASE)
        if m:
            fields[field] = re.sub(r"[,;]+$", "", m.group(1).strip())
    return fields


def normalize(raw: str) -> str:
    if not raw:
        return ""
    text = raw.lower()
    for keywords, canonical in NORMALIZATION_RULES:
        if any(kw in text for kw in keywords):
            return canonical
    return raw.upper().strip()


def wilson_ci(correct: int, total: int) -> tuple:
    if total == 0:
        return (0.0, 1.0)
    z = 1.96
    p = correct / total
    d = 1 + z**2 / total
    c = (p + z**2 / (2 * total)) / d
    s = (z * math.sqrt(p * (1 - p) / total + z**2 / (4 * total**2))) / d
    return (round(max(0.0, c - s), 3), round(min(1.0, c + s), 3))


def evaluate(predictions: list, ground_truths: list) -> dict:
    assert len(predictions) == len(ground_truths)

    threat_correct = sev_correct = 0
    class_stats = {}
    per_example = []

    for i, (pred, gt) in enumerate(zip(predictions, ground_truths)):
        pred_text = pred.get("output", pred) if isinstance(pred, dict) else str(pred)
        gt_text   = gt.get("output", gt)   if isinstance(gt, dict)   else str(gt)

        pred_fields = extract_fuzzy(pred_text)
        gt_fields   = extract_fuzzy(
            gt_text
            .replace("THREAT_TYPE", "Threat Type")
            .replace("SEVERITY", "Severity")
            .replace("MITRE_TECHNIQUE", "MITRE Technique ID")
        )

        pred_threat = normalize(pred_fields.get("THREAT_TYPE", ""))
        gt_threat   = normalize(gt_fields.get("THREAT_TYPE", ""))
        pred_sev    = (pred_fields.get("SEVERITY", "") or "").split()[0].upper()
        gt_sev      = (gt_fields.get("SEVERITY", "")  or "").split()[0].upper()

        tm = bool(pred_threat) and pred_threat == gt_threat
        sm = bool(pred_sev) and pred_sev == gt_sev

        threat_correct += int(tm)
        sev_correct    += int(sm)

        if gt_threat:
            if gt_threat not in class_stats:
                class_stats[gt_threat] = {"correct": 0, "total": 0}
            class_stats[gt_threat]["total"]   += 1
            class_stats[gt_threat]["correct"] += int(tm)

        per_example.append({
            "index": i, "pred_threat": pred_threat, "gt_threat": gt_threat,
            "threat_match": tm, "pred_sev": pred_sev, "gt_sev": gt_sev, "sev_match": sm,
        })

    n = len(predictions)
    per_class = {}
    accs = []
    for cat, s in sorted(class_stats.items()):
        acc = s["correct"] / s["total"]
        per_class[cat] = {
            "correct": s["correct"], "total": s["total"],
            "accuracy": round(acc, 4), "ci_95": wilson_ci(s["correct"], s["total"]),
        }
        accs.append(acc)

    return {
        "threat_accuracy":   round(threat_correct / n, 4),
        "severity_accuracy": round(sev_correct / n, 4),
        "macro_accuracy":    round(sum(accs) / len(accs), 4) if accs else 0.0,
        "n_examples":        n,
        "per_class":         per_class,
        "per_example":       per_example,
    }


def print_results(results: dict) -> None:
    print("\n" + "=" * 60)
    print("   SOC-BENCH v0 EVALUATION RESULTS")
    print("=" * 60)
    print(f"  Examples evaluated:      {results['n_examples']}")
    print(f"  Threat accuracy:         {results['threat_accuracy']:.1%}")
    print(f"  Severity accuracy:       {results['severity_accuracy']:.1%}")
    print(f"  Macro-avg accuracy:      {results['macro_accuracy']:.1%}")
    print()
    print(f"  {'Category':<30} {'Acc':>6}  {'CI 95%':>15}  {'n':>4}")
    print("  " + "-" * 58)
    for cat, s in results["per_class"].items():
        ci = f"[{s['ci_95'][0]:.2f}, {s['ci_95'][1]:.2f}]"
        flag = " ⚠" if s["total"] < 20 else ""
        print(f"  {cat:<30} {s['accuracy']:>6.1%}  {ci:>15}  {s['total']:>4}{flag}")
    print()
    print("  ⚠ = below SOC-Bench minimum (20 examples per class)")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(description="SOC-Bench v0 evaluator")
    parser.add_argument("--predictions",   required=True, help="JSON file of model predictions")
    parser.add_argument("--ground_truth",  required=True, help="JSON file of ground truth examples")
    parser.add_argument("--output",        default=None,  help="Save results to JSON file")
    args = parser.parse_args()

    with open(args.predictions)  as f: preds = json.load(f)
    with open(args.ground_truth) as f: gts   = json.load(f)

    results = evaluate(preds, gts)
    print_results(results)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\n  Results saved to: {args.output}")


if __name__ == "__main__":
    main()
