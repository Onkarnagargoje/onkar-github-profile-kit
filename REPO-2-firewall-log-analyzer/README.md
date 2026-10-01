# Firewall Log Analyzer

<div align="center">

<img src="https://img.shields.io/badge/SOC-Log_Triage-0f172a?style=for-the-badge&logo=shield&logoColor=38bdf8" alt="SOC" />
<img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python" />
<img src="https://img.shields.io/badge/MITRE-ATT%26CK-E52228?style=for-the-badge&logo=mitre&logoColor=white" alt="MITRE" />

**Practice Tier-1 firewall log analysis — built for SOC portfolios**

[Report bug](https://github.com/Onkarnagargoje/firewall-log-analyzer/issues) · [Author](https://www.linkedin.com/in/Onkarnagargoje-836797291)

</div>

---

A **Python CLI** for security students and **junior SOC analysts** to practice **log triage**: parse common firewall log lines, summarize blocked traffic, flag suspicious patterns, and map activity to **MITRE ATT&CK** technique IDs (educational heuristics).

Part of **[Onkar Nagargoje](https://github.com/Onkarnagargoje)**'s blue-team GitHub portfolio (B.Voc Cyber Security & Digital Forensics).

## Why recruiters care

| Skill demonstrated | In this repo |
|--------------------|--------------|
| Structured triage | Top blocked sources, action counts, filters |
| Detection mindset | Port-scan & repeat-block heuristics |
| Framework literacy | MITRE technique IDs (T1046, T1110) |
| Engineering hygiene | Tests, sample data, CLI + JSON output |

## Features

- Parse **CSV**, **pipe-delimited**, or **TSV** firewall-style logs
- Report **top blocked source IPs**, ports, and actions
- Heuristic **severity hints** (port scan patterns, repeated blocks)
- **MITRE ATT&CK** technique labels for common scenarios
- Synthetic sample log (RFC 5737 documentation IPs only)

## Requirements

- Python 3.10+

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
pip install -e .
```

## Usage

```bash
# Summary report
firewall-analyzer analyze sample_logs/firewall.log --top 10

# JSON output for pipelines / jq
firewall-analyzer analyze sample_logs/firewall.log --format json

# Filter by action (e.g. DENY, DROP)
firewall-analyzer analyze sample_logs/firewall.log --action DENY
```

### Example output (text)

```
Firewall Log Analysis
=====================
Events parsed:     24
Unique src IPs:    4
Top blocked sources:
  203.0.113.77         12  (T1110 Brute Force — ...)
  203.0.113.50          9  (T1046 Network Service Discovery — ...)
```

## Log format

Flexible column names (case-insensitive), for example:

`timestamp`, `src_ip`, `dst_ip`, `dst_port`, `action`, `protocol`

See [`sample_logs/firewall.log`](sample_logs/firewall.log).

## Run tests

```bash
pip install -e ".[dev]"
pytest -q
```

## Ethics & scope

Use only on **logs you are authorized to analyze** (lab samples, synthetic data, or employer data under policy). Do not use this tool to probe networks without permission.

## License

MIT — see [LICENSE](LICENSE).

## Author

**Onkar Nagargoje** — Nanded, India · SOC / blue-team track  
📧 onkarnagargoje25@gmail.com · 💼 [LinkedIn](https://www.linkedin.com/in/Onkarnagargoje-836797291) · 🌐 [Portfolio](https://nagargojeonkar.netlify.app/)
