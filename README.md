# SOC-Bench v0

SOC-Bench v0 is a lightweight benchmark and scoring protocol for evaluating LLM-based Security Operations Center (SOC) log classification systems.

It is designed to reduce evaluation errors caused by brittle parsing, inconsistent label normalization, and non-standard scoring pipelines.

This repository accompanies the paper:

**When the Ruler Is Broken: Parsing-Induced Suppression in LLM-Based Security Log Evaluation**

## Why SOC-Bench exists

LLM-based SOC classifiers often generate free-form text such as:

```text
Threat Type: SQL Injection
Severity: Critical
MITRE Technique ID: T1190
```

Many evaluation scripts use strict regular expressions to extract fields from this output. If the model writes `Threat Type` instead of `THREAT_TYPE`, a strict parser may fail even when the prediction is semantically correct.

SOC-Bench provides a simple evaluation structure to make SOC LLM results more reproducible and comparable.

## Features

- 13-category SOC threat taxonomy
- Threat-label normalization
- Severity scoring
- Parser-agnostic evaluation format
- Simple JSON input/output structure
- Reproducible scoring script

## Repository structure

```text
soc-bench/
├── README.md
├── requirements.txt
├── evaluate.py
├── taxonomy.json
├── soc_eval_v0.json
└── example_predictions.json
```

## Installation

```bash
git clone https://github.com/chaitanyagarware/soc-bench.git
cd soc-bench
pip install -r requirements.txt
```

## Run evaluation

```bash
python evaluate.py --predictions example_predictions.json
```

## Citation

```bibtex
@article{garware2026opensocai,
  title={OpenSOC-AI: Democratizing Security Operations with Parameter Efficient LLM Log Analysis},
  author={Garware, Chaitanya Vilas and Zisad, Sharif Noor},
  journal={arXiv preprint arXiv:2604.26217},
  year={2026}
}
```

## License

MIT License
