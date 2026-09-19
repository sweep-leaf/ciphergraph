"""
CipherGraph - LLM-Powered Cybersecurity Knowledge Graph Platform
"""

__version__ = "1.0.0"
__author__ = "gip-hado"

from ciphergraph.core.knowledge_graph import KnowledgeGraph
from ciphergraph.core.llm_engine import LLMEngine
from ciphergraph.evaluation.redblue_arena import RedBlueArena

__all__ = [
    "CipherGraph",
    "KnowledgeGraph",
    "LLMEngine",
    "RedBlueArena",
]


class CipherGraph:
    """
    Main CipherGraph platform class.

    Provides an integrated interface for:
    - Knowledge graph management
    - LLM-powered analysis
    - Autonomous penetration testing
    - Red/Blue team evaluation
    """

    def __init__(self, config: dict = None):
        self.config = config or {}
        self.knowledge_graph = KnowledgeGraph(self.config.get("graph_config", {}))
        self.llm_engine = LLMEngine(self.config.get("llm_config", {}))
        self.redblue_arena = RedBlueArena(self.knowledge_graph, self.llm_engine)

    def load_cve_data(self, cve_data_path: str) -> int:
        """Load CVE data into the knowledge graph."""
        from ciphergraph.utils.cve_parser import CVEParser

        parser = CVEParser()
        cves = parser.parse_file(cve_data_path)
        for cve in cves:
            self.knowledge_graph.add_vulnerability(cve)
        return len(cves)

    def find_attack_paths(self, target: str, goal: str, max_depth: int = 10) -> list:
        """Find attack paths from target to goal."""
        return self.knowledge_graph.find_attack_paths(target, goal, max_depth)

    def autonomous_pentest(self, target: str, scope: str = "full") -> dict:
        """Run autonomous penetration testing."""
        from ciphergraph.agents.recon_agent import ReconnaissanceAgent
        from ciphergraph.agents.exploit_agent import ExploitAgent

        recon_agent = ReconnaissanceAgent(self.knowledge_graph, self.llm_engine)
        exploit_agent = ExploitAgent(self.knowledge_graph, self.llm_engine)

        # Reconnaissance phase
        recon_results = recon_agent.scan(target, scope)

        # Exploitation phase
        exploit_results = exploit_agent.exploit(target, recon_results)

        return {
            "target": target,
            "reconnaissance": recon_results,
            "exploitation": exploit_results,
            "vulnerabilities_found": len(exploit_results.get("vulnerabilities", [])),
        }

    def redblue_evaluate(self, red_team, blue_team, scenarios: int = 10) -> dict:
        """Evaluate red and blue team capabilities."""
        return self.redblue_arena.evaluate(red_team, blue_team, scenarios)

    def query_vulnerabilities(self, query: str) -> list:
        """Natural language query for vulnerabilities."""
        return self.llm_engine.query_knowledge_graph(query, self.knowledge_graph)
