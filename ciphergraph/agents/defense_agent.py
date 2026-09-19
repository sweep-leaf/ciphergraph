"""
Defense Agent for CipherGraph
Simulates defensive security operations and generates mitigation recommendations
"""

from typing import Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime
import random


@dataclass
class DetectionEvent:
    """A detected security event."""

    event_id: str
    timestamp: str
    source: str
    event_type: str
    severity: str
    description: str
    detected_attack: Optional[str]
    confidence: float

    def to_dict(self) -> Dict:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "source": self.source,
            "event_type": self.event_type,
            "severity": self.severity,
            "description": self.description,
            "detected_attack": self.detected_attack,
            "confidence": self.confidence,
        }


@dataclass
class MitigationRecommendation:
    """Recommended mitigation action."""

    recommendation_id: str
    target_vulnerability: str
    action: str
    priority: str  # Critical, High, Medium, Low
    effort: str  # High, Medium, Low
    effectiveness: str  # Excellent, Good, Partial
    implementation: str

    def to_dict(self) -> Dict:
        return {
            "recommendation_id": self.recommendation_id,
            "target_vulnerability": self.target_vulnerability,
            "action": self.action,
            "priority": self.priority,
            "effort": self.effort,
            "effectiveness": self.effectiveness,
            "implementation": self.implementation,
        }


class DefenseAgent:
    """
    Defense agent for security operations simulation.

    Capabilities:
    - Attack detection simulation
    - Defense strategy generation
    - Mitigation recommendations
    - Security monitoring
    """

    def __init__(self, knowledge_graph, llm_engine, config: Dict = None):
        self.knowledge_graph = knowledge_graph
        self.llm_engine = llm_engine
        self.config = config or {}

    def simulate_detection(self, attack_type: str, target: str) -> DetectionEvent:
        """
        Simulate detection of a security attack.

        Args:
            attack_type: Type of attack being simulated
            target: Target system

        Returns:
            DetectionEvent with detection details
        """
        # Base detection rates by attack type
        detection_rates = {
            "port_scan": 0.85,
            "sql_injection": 0.75,
            "xss": 0.70,
            "rce": 0.90,
            "privilege_escalation": 0.60,
            "data_exfiltration": 0.80,
        }

        detection_rate = detection_rates.get(attack_type.lower(), 0.70)
        detected = random.random() < detection_rate

        severity_map = {
            "port_scan": "Low",
            "sql_injection": "High",
            "xss": "Medium",
            "rce": "Critical",
            "privilege_escalation": "High",
            "data_exfiltration": "Critical",
        }

        return DetectionEvent(
            event_id=f"DET-{int(datetime.now().timestamp())}",
            timestamp=datetime.now().isoformat(),
            source="Defense Agent Simulation",
            event_type=attack_type,
            severity=severity_map.get(attack_type.lower(), "Medium"),
            description=f"Simulated {attack_type} detected on {target}" if detected else f"Simulated {attack_type} went undetected on {target}",
            detected_attack=attack_type if detected else None,
            confidence=detection_rate if detected else 1.0 - detection_rate,
        )

    def generate_mitigations(self, vulnerabilities: List[Dict]) -> List[MitigationRecommendation]:
        """
        Generate mitigation recommendations for vulnerabilities.

        Args:
            vulnerabilities: List of vulnerability dictionaries

        Returns:
            List of prioritized mitigation recommendations
        """
        recommendations = []

        for vuln in vulnerabilities:
            cve_id = vuln.get("cve_id", "UNKNOWN")
            severity = vuln.get("severity", 5.0)

            # Determine priority based on severity
            if severity >= 9.0:
                priority = "Critical"
            elif severity >= 7.0:
                priority = "High"
            elif severity >= 4.0:
                priority = "Medium"
            else:
                priority = "Low"

            # Generate specific recommendations based on vulnerability type
            recs = self._generate_vulnerability_recommendations(cve_id, priority, vuln)
            recommendations.extend(recs)

        # Sort by priority
        priority_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        recommendations.sort(key=lambda x: priority_order.get(x.priority, 3))

        return recommendations

    def _generate_vulnerability_recommendations(
        self, cve_id: str, priority: str, vuln: Dict
    ) -> List[MitigationRecommendation]:
        """Generate specific recommendations for a vulnerability."""
        recommendations = []

        # Common recommendations based on CVE patterns
        recommendations.append(
            MitigationRecommendation(
                recommendation_id=f"REC-{cve_id}-1",
                target_vulnerability=cve_id,
                action="Apply security patches",
                priority=priority,
                effort="Low",
                effectiveness="Excellent",
                implementation=f"Update {vuln.get('affected_product', 'affected software')} to latest patched version",
            )
        )

        if "sql" in str(vuln.get("description", "")).lower():
            recommendations.append(
                MitigationRecommendation(
                    recommendation_id=f"REC-{cve_id}-2",
                    target_vulnerability=cve_id,
                    action="Implement input validation",
                    priority="High",
                    effort="Medium",
                    effectiveness="Good",
                    implementation="Add parameterized queries and input sanitization",
                )
            )

        if "xss" in str(vuln.get("description", "")).lower():
            recommendations.append(
                MitigationRecommendation(
                    recommendation_id=f"REC-{cve_id}-3",
                    target_vulnerability=cve_id,
                    action="Implement Content Security Policy",
                    priority="High",
                    effort="Medium",
                    effectiveness="Good",
                    implementation="Configure CSP headers and output encoding",
                )
            )

        recommendations.append(
            MitigationRecommendation(
                recommendation_id=f"REC-{cve_id}-4",
                target_vulnerability=cve_id,
                action="Deploy intrusion detection",
                priority="Medium",
                effort="Low",
                effectiveness="Partial",
                implementation="Configure IDS/IPS rules for known attack patterns",
            )
        )

        return recommendations

    def evaluate_defense_readiness(self, target: str, attack_scenario: Dict) -> Dict:
        """
        Evaluate defense readiness against a specific attack scenario.

        Args:
            target: Target system
            attack_scenario: Details of the attack scenario

        Returns:
            Evaluation report with scores and recommendations
        """
        attack_type = attack_scenario.get("attack_type", "unknown")
        severity = attack_scenario.get("severity", 5.0)

        # Simulate detection
        detection = self.simulate_detection(attack_type, target)

        # Calculate defense score
        base_score = 100
        if not detection.detected_attack:
            base_score -= severity * 5  # Undetected attacks reduce score

        detection_score = base_score if detection.detected_attack else base_score * 0.3

        return {
            "target": target,
            "attack_scenario": attack_scenario,
            "detection_event": detection.to_dict(),
            "defense_score": max(0, detection_score),
            "detection_rate": detection.confidence if detection.detected_attack else 0,
            "recommended_additional_controls": self._get_additional_controls(attack_type),
        }

    def _get_additional_controls(self, attack_type: str) -> List[str]:
        """Get additional control recommendations based on attack type."""
        controls = {
            "port_scan": [
                "Deploy rate limiting on network borders",
                "Implement port scan detection tools",
                "Configure firewall rules to block suspicious scanning",
            ],
            "sql_injection": [
                "Use WAF with SQL injection protection",
                "Implement database firewall",
                "Enable query logging and monitoring",
            ],
            "xss": [
                "Deploy XSS filter at WAF level",
                "Implement browser-based XSS protection",
                "Enable CSP with anti-XSS headers",
            ],
            "rce": [
                "Restrict command execution privileges",
                "Implement sandboxing for web applications",
                "Deploy runtime application self-protection (RASP)",
            ],
            "privilege_escalation": [
                "Implement principle of least privilege",
                "Enable privilege separation",
                "Monitor for unusual privilege usage",
            ],
            "data_exfiltration": [
                "Implement DLP solutions",
                "Monitor outbound traffic patterns",
                "Encrypt sensitive data at rest and in transit",
            ],
        }

        return controls.get(attack_type.lower(), ["Implement defense in depth strategy"])
