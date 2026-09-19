# 🔐 CipherGraph

**LLM驱动的网络安全知识图谱平台 - 自主漏洞发现与红蓝对抗评估**

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## 🌟 概述

CipherGraph 是一个创新的网络安全平台，将**大语言模型 (LLM)**、**知识图谱**和**多智能体系统**相结合，彻底改变漏洞发现和安全评估的方式。

### 核心特性

- **🕸️ 知识图谱架构** - 将CVE、ATT&CK战术、漏洞关系映射为智能图网络
- **🤖 LLM驱动的分析** - 支持安全日志、网络流量和源代码多模态分析
- **🔍 自主渗透测试** - 基于知识图谱引导的智能漏洞发现智能体
- **⚔️ 红蓝对抗竞技场** - 可量化的攻守能力评估框架
- **📊 可测量指标** - 基于CVSS评分和攻击路径的数据驱动评估

## 🎯 为什么选择 CipherGraph？

| 能力 | 传统工具 | CipherGraph |
|------|----------|-------------|
| 漏洞发现 | 基于规则，上下文有限 | LLM推理结合图知识 |
| 攻击路径分析 | 手动关联 | 自动图遍历 |
| 红队评估 | 定性评估 | 定量指标 |
| 知识复用 | 数据孤岛 | 图驱动的关系统挖掘 |

## 🏗️ 系统架构

```
┌─────────────────────────────────────────────────────────────┐
│                    CipherGraph 平台                          │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐│
│  │  知识图谱   │  │    LLM      │  │    多智能体系统    ││
│  │ Knowledge   │  │   分析引擎  │  │  (编排协调)        ││
│  │    Graph   │  │   Engine    │  │     System         ││
│  └──────┬──────┘  └──────┬──────┘  └──────────┬──────────┘│
│         │                │                     │           │
│  ┌──────┴────────────────┴─────────────────────┴──────────┐│
│  │              评估框架                                  ││
│  │  • CVSS评分  • ATT&CK映射  • 攻击路径分析            ││
│  └────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
```

## 🚀 快速开始

### 安装

```bash
# 克隆仓库
git clone https://github.com/gip-hado/CipherGraph.git
cd CipherGraph

# 安装依赖
pip install -r requirements.txt

# 初始化知识图谱
python -m ciphergraph init
```

### 基本使用

```python
from ciphergraph import CipherGraph

# 初始化平台
cg = CipherGraph()

# 添加漏洞数据
cg.load_cve_data("cve_data.json")

# 查询攻击路径
paths = cg.find_attack_paths(target="web_server", goal="data_exfiltration")

# 运行自主渗透测试
result = cg.autonomous_pentest(target="192.168.1.100", scope="web_application")

# 评估红队表现
report = cg.redblue_evaluate(red_team=agent, blue_team=defense_system)
```

## 📁 项目结构

```
ciphergraph/
├── ciphergraph/                 # 主包
│   ├── __init__.py
│   ├── core/                    # 核心功能
│   │   ├── knowledge_graph.py   # 图数据库操作
│   │   ├── llm_engine.py        # LLM分析引擎
│   │   └── config.py            # 配置管理
│   ├── agents/                  # 多智能体系统
│   │   ├── recon_agent.py       # 侦察智能体
│   │   ├── exploit_agent.py     # 漏洞利用智能体
│   │   └── defense_agent.py     # 防御智能体
│   ├── evaluation/              # 评估框架
│   │   ├── metrics.py           # CVSS和指标
│   │   └── redblue_arena.py     # 红蓝对抗评估
│   └── utils/                   # 工具函数
│       ├── cve_parser.py        # CVE数据解析
│       └── attack_mapping.py    # ATT&CK映射
├── tests/                       # 单元测试
├── examples/                    # 使用示例
├── docs/                        # 文档
└── README.md
```

## 📊 评估指标

CipherGraph 提供可量化的安全指标：

| 指标 | 描述 | 范围 |
|------|------|------|
| **漏洞覆盖率** | 发现的已知漏洞百分比 | 0-100% |
| **攻击路径效率** | 从入口到目标的平均步数 | 1-10 |
| **红队得分** | 攻击能力评估 | 0-100 |
| **蓝队得分** | 防御能力评估 | 0-100 |
| **CVSS准确度** | 预测与实际严重性相关性 | 0-1 |

## 🔬 应用场景

1. **自主漏洞发现** - AI智能体发现未知漏洞
2. **安全研究** - 基于图的漏洞关系分析
3. **红队训练** - 攻击能力定量评估
4. **蓝队评估** - 防御准备度测量
5. **CTF备战** - 攻击路径优化训练

## 📖 文档

- [详细技术说明](docs/detailed-explanation.md) - 深入技术文档
- [API参考](docs/api.md) - 完整API文档
- [示例](examples/) - 使用示例和教程

## 🤝 贡献

欢迎贡献！请先阅读我们的贡献指南。

## 📄 许可证

MIT 许可证 - 详见 [LICENSE](LICENSE)。

## 👨‍💻 作者

**gip-hado** - 专注于AI驱动网络安全的 安全研究员

---

如果这个项目对您有帮助，请在GitHub上给我们一个⭐！
