# threat-intel-analyzer-alan-vo

> AI-powered threat intelligence platform that ingests CVEs, IOC feeds, and news to produce prioritized, actionable security briefings with LLM-generated context and risk scoring.

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![AI](https://img.shields.io/badge/AI-Powered-purple)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

</div>

## Why threat-intel-analyzer-alan-vo?

AI-powered threat intelligence platform that ingests CVEs, IOC feeds, and news to produce prioritized, actionable security briefings with LLM-generated context and risk scoring. Built by [Alan Vo](https://github.com/ALANDVO) — AI/ML & cybersecurity engineer.

## Features

- **Ingest CVE feeds, YARA rules, and STIX/TAXII threat intelligence**
- **LLM-powered risk scoring and impact analysis per vulnerability**
- **Auto-generated security briefings with executive summaries**
- **Attack surface mapping — correlates CVEs to your tech stack**
- **Natural language queries: 'What critical RCEs affect our Python stack?'**
- **Export to PDF, JSON, or Slack-ready format**
- **Multi-source: NVD, MITRE ATT&CK, CISA KEV, custom feeds**

## Quick Start

```bash
git clone https://github.com/ALANDVO/threat-intel-analyzer-alan-vo.git
cd threat-intel-analyzer-alan-vo
pip install -r requirements.txt
python -m venv .venv && source .venv/bin/activate
```

## Usage

```
python main.py scan --stack python,nodejs --severity critical
python main.py brief --date today --output brief.md
python main.py query "What RCEs affect our Flask apps?"
```

## API Keys

Set your provider key:
```bash
export LLM_API_KEY="your-key-here"
```

Works with: OpenAI, Anthropic (Claude), Google Gemini, Ollama (local), or any OpenAI-compatible endpoint.

## Tech Stack

`Python` `OpenAI/Anthropic/Gemini` `CVE/NVD` `STIX/TAXII` `MITRE ATT&CK`

## License

MIT — see [LICENSE](LICENSE)

---

**Built by [Alan Vo](https://github.com/ALANDVO)** | [GitHub](https://github.com/ALANDVO) | AI, ML & Cybersecurity


