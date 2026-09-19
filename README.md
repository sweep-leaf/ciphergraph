# 🔐 CipherGraph

**LLM-Powered Cybersecurity Knowledge Graph Platform for Autonomous Vulnerability Discovery and Red/Blue Team Evaluation**

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## 🌟 Overview

CipherGraph is an innovative cybersecurity platform that combines **Large Language Models (LLM)**, **Knowledge Graphs**, and **Multi-Agent Systems** to revolutionize vulnerability discovery and security evaluation.

### Key Features

- **🕸️ Knowledge Graph Architecture** - Maps CVE, ATT&CK tactics, and vulnerability relationships into an intelligent graph network
- **🤖 LLM-Powered Analysis** - Multi-modal support for security logs, network traffic, and source code analysis
- **🔍 Autonomous Penetration Testing** - Graph-guided intelligent vulnerability discovery agents
- **⚔️ Red/Blue Arena** - Quantifiable evaluation framework for offensive and defensive security capabilities
- **📊 Measurable Metrics** - Data-driven assessment with CVSS scoring and attack path analysis

## 🎯 Why CipherGraph?

| Capability | Traditional Tools | CipherGraph |
|------------|-------------------|-------------|
| Vulnerability Discovery | Rule-based, limited context | LLM reasoning with graph knowledge |
| Attack Path Analysis | Manual correlation | Automated graph traversal |
| Red Team Evaluation | Qualitative assessment | Quantitative metrics |
| Knowledge Reuse | Siloed data | Graph-powered relationship mining |

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    CipherGraph Platform                      │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐│
│  │  Knowledge  │  │     LLM     │  │   Multi-Agent      ││
│  │    Graph    │  │   Analysis  │  │      System        ││
│  │  (Neo4j)    │  │   Engine    │  │  (Orchestration)   ││
│  └──────┬──────┘  └──────┬──────┘  └──────────┬──────────┘│
│         │                │                     │           │
│  ┌──────┴────────────────┴─────────────────────┴──────────┐│
│  │              Evaluation Framework                      ││
│  │  • CVSS Scoring  • ATT&CK Mapping  • Attack Paths    ││
│  └────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
```

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/gip-hado/CipherGraph.git
cd CipherGraph

# Install dependencies
pip install -r requirements.txt

# Initialize knowledge graph
python -m ciphergraph init
```

### Basic Usage

```python
from ciphergraph import CipherGraph

# Initialize the platform
cg = CipherGraph()

# Add vulnerability data
cg.load_cve_data("cve_data.json")

# Query attack paths
paths = cg.find_attack_paths(target="web_server", goal="data_exfiltration")

# Run autonomous penetration test
result = cg.autonomous_pentest(target="192.168.1.100", scope="web_application")

# Evaluate red team performance
report = cg.redblue_evaluate(red_team=agent, blue_team=defense_system)
```

## 📁 Project Structure

```
ciphergraph/
├── ciphergraph/                 # Main package
│   ├── __init__.py
│   ├── core/                    # Core functionality
│   │   ├── knowledge_graph.py   # Graph database operations
│   │   ├── llm_engine.py        # LLM analysis engine
│   │   └── config.py            # Configuration
│   ├── agents/                  # Multi-agent system
│   │   ├── recon_agent.py       # Reconnaissance agent
│   │   ├── exploit_agent.py     # Exploitation agent
│   │   └── defense_agent.py     # Defense agent
│   ├── evaluation/              # Evaluation framework
│   │   ├── metrics.py           # CVSS and metrics
│   │   └── redblue_arena.py     # Red/Blue team evaluation
│   └── utils/                   # Utilities
│       ├── cve_parser.py        # CVE data parser
│       └── attack_mapping.py    # ATT&CK mapping
├── tests/                       # Unit tests
├── examples/                    # Usage examples
├── docs/                        # Documentation
└── README.md
```

## 📊 Evaluation Metrics

CipherGraph provides quantifiable security metrics:

| Metric | Description | Range |
|--------|-------------|-------|
| **Vulnerability Coverage** | % of known vulnerabilities discovered | 0-100% |
| **Attack Path Efficiency** | Average steps from entry to target | 1-10 |
| **Red Team Score** | Offensive capability assessment | 0-100 |
| **Blue Team Score** | Defensive capability assessment | 0-100 |
| **CVSS Accuracy** | Prediction vs actual severity correlation | 0-1 |

## 🔬 Use Cases

1. **Autonomous Vulnerability Discovery** - AI agents discover未知 vulnerabilities
2. **Security Research** - Graph-based vulnerability relationship analysis
3. **Red Team Training** - Quantitative evaluation of offensive capabilities
4. **Blue Team Assessment** - Defensive readiness measurement
5. **CTF Preparation** - Attack path optimization training

## 📖 Documentation

- [Detailed Explanation](docs/detailed-explanation.md) - In-depth technical documentation
- [API Reference](docs/api.md) - Complete API documentation
- [Examples](examples/) - Usage examples and tutorials

## 🤝 Contributing

Contributions are welcome! Please read our contributing guidelines first.

## 📄 License

MIT License - See [LICENSE](LICENSE) for details.

## 👨‍💻 Author

**gip-hado** - Security Researcher specializing in AI-powered cybersecurity

---

⭐ Star us on GitHub if this project helped you!
