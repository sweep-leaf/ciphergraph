"""
Knowledge Graph module for CipherGraph
Manages vulnerability relationships and attack paths using graph structures
"""

import networkx as nx
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
import json


class NodeType(Enum):
    """Types of nodes in the knowledge graph."""

    VULNERABILITY = "vulnerability"
    ATTACK_TECHNIQUE = "attack_technique"
    SYSTEM_ENTITY = "system_entity"
    ATTACK_PHASE = "attack_phase"
    MALWARE = "malware"
    TOOL = "tool"


class RelationType(Enum):
    """Types of relations between nodes."""

    ENABLES = "enables"
    TARGETS = "targets"
    USES = "uses"
    ACHIEVES = "achieves"
    EXPLOITS = "exploits"
    MITIGATES = "mitigates"
    DETECTS = "detects"
    COMPROMISES = "compromises"
    BELONGS_TO = "belongs_to"


@dataclass
class Vulnerability:
    """Represents a vulnerability in the knowledge graph."""

    cve_id: str
    description: str
    severity: float  # CVSS score 0-10
    attack_vector: str
    attack_complexity: str
    privileges_required: str
    user_interaction: str
    scope: str
    confidentiality_impact: str
    integrity_impact: str
    availability_impact: str
    affected_product: str
    published_date: str
    related_techniques: List[str] = field(default_factory=list)

    @property
    def cvss_category(self) -> str:
        """Categorize severity."""
        if self.severity >= 9.0:
            return "Critical"
        elif self.severity >= 7.0:
            return "High"
        elif self.severity >= 4.0:
            return "Medium"
        else:
            return "Low"


@dataclass
class AttackTechnique:
    """Represents an ATT&CK technique."""

    technique_id: str  # e.g., "T1190"
    name: str
    tactics: List[str]  # e.g., ["Initial Access", "Execution"]
    description: str
    detection: str
    mitigation: str
    related_vulnerabilities: List[str] = field(default_factory=list)


@dataclass
class SystemEntity:
    """Represents a system component."""

    entity_id: str
    name: str
    layer: str  # e.g., "presentation", "application", "data"
    os_type: str
    services: List[str] = field(default_factory=list)
    ports: List[int] = field(default_factory=list)
    protocols: List[str] = field(default_factory=list)


class KnowledgeGraph:
    """
    Knowledge graph for managing cybersecurity relationships.

    Supports:
    - Adding vulnerabilities, techniques, and system entities
    - Finding attack paths
    - Querying relationships
    - CVSS-based vulnerability ranking
    """

    def __init__(self, config: dict = None):
        self.config = config or {}
        self.graph = nx.DiGraph()
        self._node_index: Dict[str, dict] = {}
        self._initialized = False

    def add_vulnerability(self, vuln: Vulnerability) -> None:
        """Add a vulnerability node to the graph."""
        self.graph.add_node(
            vuln.cve_id,
            node_type=NodeType.VULNERABILITY.value,
            data=vuln,
        )
        self._node_index[vuln.cve_id] = {"type": NodeType.VULNERABILITY, "data": vuln}

        # Add edges to related attack techniques
        for technique_id in vuln.related_techniques:
            self.graph.add_edge(
                vuln.cve_id,
                technique_id,
                relation=RelationType.ENABLES.value,
            )

    def add_attack_technique(self, technique: AttackTechnique) -> None:
        """Add an attack technique node to the graph."""
        self.graph.add_node(
            technique.technique_id,
            node_type=NodeType.ATTACK_TECHNIQUE.value,
            data=technique,
        )
        self._node_index[technique.technique_id] = {
            "type": NodeType.ATTACK_TECHNIQUE,
            "data": technique,
        }

    def add_system_entity(self, entity: SystemEntity) -> None:
        """Add a system entity node to the graph."""
        self.graph.add_node(
            entity.entity_id,
            node_type=NodeType.SYSTEM_ENTITY.value,
            data=entity,
        )
        self._node_index[entity.entity_id] = {"type": NodeType.SYSTEM_ENTITY, "data": entity}

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        relation: RelationType,
        properties: dict = None,
    ) -> None:
        """Add a relationship between two nodes."""
        if source_id not in self.graph or target_id not in self.graph:
            raise ValueError(f"Nodes must exist before creating edge: {source_id} -> {target_id}")

        self.graph.add_edge(source_id, target_id, relation=relation.value, **(properties or {}))

    def find_attack_paths(
        self, entry_point: str, goal: str, max_depth: int = 10
    ) -> List[List[str]]:
        """
        Find all possible attack paths from entry point to goal.

        Args:
            entry_point: Starting node ID
            goal: Target node ID
            max_depth: Maximum path length

        Returns:
            List of paths, each path is a list of node IDs
        """
        if entry_point not in self.graph:
            self._create_dummy_node(entry_point, NodeType.SYSTEM_ENTITY)
        if goal not in self.graph:
            self._create_dummy_node(goal, NodeType.SYSTEM_ENTITY)

        try:
            all_paths = list(nx.all_simple_paths(self.graph, entry_point, goal, cutoff=max_depth))
        except nx.NetworkXNoPath:
            all_paths = []

        # Score and rank paths
        ranked_paths = self._rank_paths(all_paths)
        return ranked_paths

    def _rank_paths(self, paths: List[List[str]]) -> List[Dict]:
        """Rank attack paths by likelihood and impact."""
        ranked = []

        for path in paths:
            score = 0.0
            total_severity = 0.0

            for node_id in path:
                node_data = self._node_index.get(node_id)
                if node_data:
                    if node_data["type"] == NodeType.VULNERABILITY:
                        total_severity += node_data["data"].severity
                        score += node_data["data"].severity * 0.3
                    elif node_data["type"] == NodeType.ATTACK_TECHNIQUE:
                        score += 5.0  # Base score for technique usage

            # Normalize score
            if path:
                avg_severity = total_severity / len(path) if len(path) > 0 else 0
                path_score = score + avg_severity

                ranked.append({
                    "path": path,
                    "score": path_score,
                    "steps": len(path),
                    "avg_cvss": avg_severity,
                })

        # Sort by score descending
        ranked.sort(key=lambda x: x["score"], reverse=True)
        return ranked

    def get_vulnerabilities_by_severity(self, min_severity: float = 0.0) -> List[Vulnerability]:
        """Get vulnerabilities filtered by minimum CVSS severity."""
        results = []
        for node_id, node_data in self._node_index.items():
            if node_data["type"] == NodeType.VULNERABILITY:
                if node_data["data"].severity >= min_severity:
                    results.append(node_data["data"])
        return sorted(results, key=lambda v: v.severity, reverse=True)

    def get_neighbors_by_relation(
        self, node_id: str, relation: RelationType, direction: str = "out"
    ) -> List[str]:
        """Get neighboring nodes by relation type."""
        if node_id not in self.graph:
            return []

        neighbors = []
        if direction == "out":
            for successor in self.graph.successors(node_id):
                edge_data = self.graph.get_edge_data(node_id, successor)
                if edge_data and edge_data.get("relation") == relation.value:
                    neighbors.append(successor)
        else:
            for predecessor in self.graph.predecessors(node_id):
                edge_data = self.graph.get_edge_data(predecessor, node_id)
                if edge_data and edge_data.get("relation") == relation.value:
                    neighbors.append(predecessor)

        return neighbors

    def query_by_attack_tactic(self, tactic: str) -> List[AttackTechnique]:
        """Query attack techniques by tactic (e.g., 'Initial Access', 'Execution')."""
        results = []
        for node_id, node_data in self._node_index.items():
            if node_data["type"] == NodeType.ATTACK_TECHNIQUE:
                if tactic in node_data["data"].tactics:
                    results.append(node_data["data"])
        return results

    def get_attack_surface(self, entity_id: str, depth: int = 2) -> Dict:
        """
        Analyze the attack surface of a given entity.

        Returns:
            Dictionary containing reachable vulnerabilities and techniques
        """
        if entity_id not in self.graph:
            self._create_dummy_node(entity_id, NodeType.SYSTEM_ENTITY)

        reachable_vulns = []
        reachable_techniques = []

        # BFS to find reachable nodes
        for node in nx.descendants(self.graph, entity_id):
            node_data = self._node_index.get(node)
            if node_data:
                if node_data["type"] == NodeType.VULNERABILITY:
                    reachable_vulns.append(node_data["data"])
                elif node_data["type"] == NodeType.ATTACK_TECHNIQUE:
                    reachable_techniques.append(node_data["data"])

        return {
            "entity_id": entity_id,
            "reachable_vulnerabilities": reachable_vulns,
            "reachable_techniques": reachable_techniques,
            "attack_surface_size": len(reachable_vulns) + len(reachable_techniques),
        }

    def _create_dummy_node(self, node_id: str, node_type: NodeType) -> None:
        """Create a placeholder node for querying."""
        if node_type == NodeType.SYSTEM_ENTITY:
            dummy = SystemEntity(
                entity_id=node_id,
                name=node_id,
                layer="unknown",
                os_type="unknown",
            )
            self.add_system_entity(dummy)
        elif node_type == NodeType.VULNERABILITY:
            dummy = Vulnerability(
                cve_id=node_id,
                description="Unknown vulnerability",
                severity=5.0,
                attack_vector="N",
                attack_complexity="L",
                privileges_required="N",
                user_interaction="N",
                scope="U",
                confidentiality_impact="H",
                integrity_impact="H",
                availability_impact="H",
                affected_product="unknown",
                published_date="unknown",
            )
            self.add_vulnerability(dummy)

    def export_to_dict(self) -> dict:
        """Export graph to dictionary format."""
        nodes = []
        for node_id in self.graph.nodes():
            node_data = self._node_index.get(node_id, {})
            nodes.append({
                "id": node_id,
                "type": self.graph.nodes[node_id].get("node_type"),
                "data": node_data.get("data"),
            })

        edges = []
        for source, target, edge_data in self.graph.edges(data=True):
            edges.append({
                "source": source,
                "target": target,
                "relation": edge_data.get("relation"),
            })

        return {"nodes": nodes, "edges": edges}

    def get_statistics(self) -> Dict:
        """Get graph statistics."""
        vuln_count = sum(
            1 for n in self._node_index.values() if n["type"] == NodeType.VULNERABILITY
        )
        tech_count = sum(
            1 for n in self._node_index.values() if n["type"] == NodeType.ATTACK_TECHNIQUE
        )
        entity_count = sum(
            1 for n in self._node_index.values() if n["type"] == NodeType.SYSTEM_ENTITY
        )

        return {
            "total_nodes": self.graph.number_of_nodes(),
            "total_edges": self.graph.number_of_edges(),
            "vulnerabilities": vuln_count,
            "attack_techniques": tech_count,
            "system_entities": entity_count,
        }
