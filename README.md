# soc-parser

**Fuzzy field extractor for SLM-based SOC log classifier evaluation.**

[![PyPI version](https://badge.fury.io/py/soc-parser.svg)](https://badge.fury.io/py/soc-parser)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Addresses **parsing-induced recall suppression** in LLM security output evaluation — a failure mode where a rigid regular-expression extractor causes 100% apparent failure on a model that is semantically correct.

> **Reference:** Garware, C.V. (2026). *Failure Modes of Fine-Tuned Small Language Models for Security Log Classification: A Systematic Study with Experimental Validation.* arXiv preprint.

---

## The Problem

When evaluating SLM-based SOC classifiers, a common pattern is:

```python
# Original strict extractor
match = re.search(r"THREAT_TYPE[:\s]+([^\n,]+)", model_output)
```

This fails silently when the model outputs `Threat Type: SQL Injection` instead of `THREAT_TYPE: SQL Injection` — a formatting variation that is common in instruction-tuned models at the 1B–7B scale. In our experiments, this single mismatch caused a **76 percentage-point gap** between reported accuracy (0%) and actual accuracy (76%).

---

## Installation

```bash
pip install soc-parser
```

---

## Quick Start

```python
from soc_parser import SOCParser, ThreatNormalizer, SOCBenchScorer

# Parse model output — handles all field name format variations
parser = SOCParser()
result = parser.parse("""
Threat Type: SQL Injection
Severity: High
MITRE Technique ID: T1190
""")
# {'THREAT_TYPE': 'SQL Injection', 'SEVERITY': 'HIGH', 'MITRE_TECHNIQUE': 'T1190', ...}

# Normalize threat labels to SOC-Bench canonical categories
normalizer = ThreatNormalizer()
normalizer.normalize("SQL Injection — OS Command via SQLi")
# "SQL INJECTION"

# Full SOC-Bench compliant evaluation
scorer = SOCBenchScorer()
results = scorer.score(predictions=model_outputs, ground_truths=gt_outputs)
print(f"Threat accuracy: {results['threat_accuracy']:.1%}")
print(f"Macro accuracy:  {results['macro_accuracy']:.1%}")

# Compare strict vs fuzzy parser — quantify parsing suppression
comparison = scorer.compare_parsers(model_outputs, gt_outputs)
print(f"Parsing suppression: {comparison['parsing_suppression_pp']}pp")
```

---

## Field Name Variants Handled

| Model outputs | Extracted as |
|---|---|
| `THREAT_TYPE: SQL Injection` | ✅ THREAT_TYPE |
| `Threat Type: SQL Injection` | ✅ THREAT_TYPE |
| `threat type: SQL Injection` | ✅ THREAT_TYPE |
| `Threat-Type: SQL Injection` | ✅ THREAT_TYPE |
| `Threat_Type: SQL Injection` | ✅ THREAT_TYPE |
| `MITRE Technique ID: T1190` | ✅ MITRE_TECHNIQUE |
| `MITRE_TECHNIQUE: T1190` | ✅ MITRE_TECHNIQUE |

---

## SOC-Bench Evaluation Protocol

`soc-parser` implements the SOC-Bench evaluation standard:

1. **Fuzzy field extraction** — handles format drift across all common variants
2. **Broad-category normalization** — maps subcategory labels to canonical set
3. **Macro-averaged accuracy** — unweighted mean across all 13 categories
4. **Wilson confidence intervals** — per-class statistical power reporting
5. **Loop truncation** — removes prompt-repetition artifacts before parsing

---

## Supported Categories (SOC-Bench v0)

| ID | Category |
|---|---|
| SB-01 | SQL Injection |
| SB-02 | XSS |
| SB-03 | Command Injection |
| SB-04 | Path / Directory Traversal |
| SB-05 | Local File Inclusion (LFI) |
| SB-06 | Brute Force |
| SB-07 | Credential Stuffing |
| SB-08 | Reconnaissance / Scanning |
| SB-09 | Denial of Service / DDoS |
| SB-10 | Data Exfiltration |
| SB-11 | Lateral Movement |
| SB-12 | Malware / C2 |
| SB-13 | No Threat / Normal Traffic |

---

## Citation

```bibtex
@article{garware2026failure,
  title={Failure Modes of Fine-Tuned Small Language Models for Security Log
         Classification: A Systematic Study with Experimental Validation},
  author={Garware, Chaitanya Vilas},
  journal={arXiv preprint},
  year={2026}
}
```

---

## License

MIT
