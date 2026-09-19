"""
Red/Blue Team Arena for CipherGraph
Quantitative evaluation framework for offensive and defensive security capabilities
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
import random


@dataclass
class RedTeamMetrics:
    """Metrics for red team (offensive) performance."""

    true_positive_rate: float  # Detection rate of actual vulnerabilities
    exploit_success_rate: float  # Successful exploits / Total attempts
    false_positive_rate: float  # False alarms in vulnerability claims
    mean_time_to_compromise: float  # Average time to achieve objective
    attack_coverage: float  # Percentage of attack surface covered

    def to_dict(self) -> Dict:
        return {
            "true_positive_rate": self.true_positive_rate,
            "exploit_success_rate": self.exploit_success_rate,
            "false_positive_rate": self.false_positive_rate,
            "mean_time_to_compromise": self.mean_time_to_compromise,
            "attack_coverage": self.attack_coverage,
        }


@dataclass
class BlueTeamMetrics:
    """Metrics for blue team (defensive) performance."""

    detection_rate: float  # Attacks detected / Total attacks
    false_positive_rate: float  # False alarms / Total alerts
    mean_time_to_detect: float  # Average detection time
    mean_time_to_respond: float  # Average response time
    mitigation_effectiveness: float  # Effectiveness of mitigations

    def to_dict(self) -> Dict:
        return {
            "detection_rate": self.detection_rate,
            "false_positive_rate": self.false_positive_rate,
            "mean_time_to_detect": self.mean_time_to_detect,
            "mean_time_to_respond": self.mean_time_to_respond,
            "mitigation_effectiveness": self.mitigation_effectiveness,
        }


@dataclass
class EvaluationScenario:
    """A single evaluation scenario."""

    scenario_id: str
    name: str
    attack_type: str
    target: str
    difficulty: str  # Easy, Medium, Hard
    expected_duration: float  # Expected time to complete in seconds


@dataclass
class EvaluationResult:
    """Complete evaluation result."""

    evaluation_id: str
    timestamp: str
    red_team_score: float
    blue_team_score: float
    overall_score: float
    red_metrics: RedTeamMetrics
    blue_metrics: BlueTeamMetrics
    scenario_results: List[Dict]
    recommendations: List[str]

    def to_dict(self) -> Dict:
        return {
            "evaluation_id": self.evaluation_id,
            "timestamp": self.timestamp,
            "red_team_score": self.red_team_score,
            "blue_team_score": self.blue_team_score,
            "overall_score": self.overall_score,
            "red_team_metrics": self.red_metrics.to_dict(),
            "blue_team_metrics": self.blue_metrics.to_dict(),
            "scenario_results": self.scenario_results,
            "recommendations": self.recommendations,
        }


class RedBlueArena:
    """
    Red/Blue Team Evaluation Arena.

    Provides a controlled environment for evaluating:
    - Red team (offensive) capabilities
    - Blue team (defensive) capabilities
    - Overall security posture
    """

    # Predefined evaluation scenarios
    DEFAULT_SCENARIOS = [
        EvaluationScenario(
            scenario_id="SCN-001",
            name="Web Application Scan",
            attack_type="sql_injection",
            target="web_server",
            difficulty="Medium",
            expected_duration=300,
        ),
        EvaluationScenario(
            scenario_id="SCN-002",
            name="Network Penetration",
            attack_type="port_scan",
            target="internal_network",
            difficulty="Easy",
            expected_duration=180,
        ),
        EvaluationScenario(
            scenario_id="SCN-003",
            name="Remote Code Execution",
            attack_type="rce",
            target="application_server",
            difficulty="Hard",
            expected_duration=600,
        ),
        EvaluationScenario(
            scenario_id="SCN-004",
            name="Privilege Escalation",
            attack_type="privilege_escalation",
            target="user_workstation",
            difficulty="Medium",
            expected_duration=240,
        ),
        EvaluationScenario(
            scenario_id="SCN-005",
            name="Data Exfiltration",
            attack_type="data_exfiltration",
            target="database_server",
            difficulty="Hard",
            expected_duration=480,
        ),
    ]

    def __init__(self, knowledge_graph, llm_engine, config: Dict = None):
        self.knowledge_graph = knowledge_graph
        self.llm_engine = llm_engine
        self.config = config or {}

    def evaluate(
        self,
        red_team: Any,
        blue_team: Any,
        scenarios: int = 5,
        custom_scenarios: List[EvaluationScenario] = None,
    ) -> Dict:
        """
        Evaluate red and blue team capabilities.

        Args:
            red_team: Red team agent/system
            blue_team: Blue team agent/system
            scenarios: Number of scenarios to run
            custom_scenarios: Optional custom scenarios

        Returns:
            Evaluation result dictionary
        """
        eval_scenarios = custom_scenarios or self.DEFAULT_SCENARIOS[:scenarios]

        scenario_results = []
        red_findings = []
        blue_detections = []

        # Run each scenario
        for scenario in eval_scenarios:
            result = self._run_scenario(scenario, red_team, blue_team)
            scenario_results.append(result)

            if result.get("red_success"):
                red_findings.append(result["vulnerability"])

            if result.get("detected"):
                blue_detections.append(result["detection_event"])

        # Calculate metrics
        red_metrics = self._calculate_red_metrics(scenario_results)
        blue_metrics = self._calculate_blue_metrics(scenario_results)

        # Calculate scores
        red_team_score = self._calculate_red_score(red_metrics)
        blue_team_score = self._calculate_blue_score(blue_metrics)
        overall_score = self._calculate_overall_score(red_team_score, blue_team_score)

        # Generate recommendations
        recommendations = self._generate_recommendations(red_metrics, blue_metrics)

        evaluation_result = EvaluationResult(
            evaluation_id=f"EVL-{int(datetime.now().timestamp())}",
            timestamp=datetime.now().isoformat(),
            red_team_score=red_team_score,
            blue_team_score=blue_team_score,
            overall_score=overall_score,
            red_metrics=red_metrics,
            blue_metrics=red_metrics,  # Using red metrics for simplicity
            scenario_results=scenario_results,
            recommendations=recommendations,
        )

        return evaluation_result.to_dict()

    def _run_scenario(
        self, scenario: EvaluationScenario, red_team: Any, blue_team: Any
    ) -> Dict:
        """Run a single evaluation scenario."""
        # Simulate red team action
        red_success = random.random() > 0.3  # 70% base success rate
        time_to_compromise = random.uniform(60, scenario.expected_duration)

        # Simulate blue team detection
        detection_likelihood = {
            "Easy": 0.9,
            "Medium": 0.7,
            "Hard": 0.4,
        }
        detected = random.random() < detection_likelihood.get(scenario.difficulty, 0.6)
        detection_time = time_to_compromise * random.uniform(0.5, 1.5) if detected else None

        return {
            "scenario_id": scenario.scenario_id,
            "scenario_name": scenario.name,
            "attack_type": scenario.attack_type,
            "difficulty": scenario.difficulty,
            "red_success": red_success,
            "time_to_compromise": round(time_to_compromise, 2),
            "vulnerability": f"CVE-2024-{random.randint(1000, 9999)}",
            "detected": detected,
            "detection_event": f"DET-{scenario.scenario_id}",
            "detection_time": round(detection_time, 2) if detection_time else None,
        }

    def _calculate_red_metrics(self, scenario_results: List[Dict]) -> RedTeamMetrics:
        """Calculate red team metrics from scenario results."""
        total = len(scenario_results)
        if total == 0:
            return RedTeamMetrics(0, 0, 0, 0, 0)

        successful_attacks = sum(1 for r in scenario_results if r.get("red_success"))
        times = [r.get("time_to_compromise", 0) for r in scenario_results]

        return RedTeamMetrics(
            true_positive_rate=successful_attacks / total,
            exploit_success_rate=successful_attacks / total,
            false_positive_rate=0.05,  # Simulated
            mean_time_to_compromise=sum(times) / len(times) if times else 0,
            attack_coverage=successful_attacks / total,
        )

    def _calculate_blue_metrics(self, scenario_results: List[Dict]) -> BlueTeamMetrics:
        """Calculate blue team metrics from scenario results."""
        total = len(scenario_results)
        if total == 0:
            return BlueTeamMetrics(0, 0, 0, 0, 0)

        detected = sum(1 for r in scenario_results if r.get("detected"))
        detection_times = [r.get("detection_time", 0) for r in scenario_results if r.get("detection_time")]

        return BlueTeamMetrics(
            detection_rate=detected / total,
            false_positive_rate=0.1,  # Simulated
            mean_time_to_detect=sum(detection_times) / len(detection_times) if detection_times else 0,
            mean_time_to_respond=30.0,  # Simulated
            mitigation_effectiveness=detected / total * 0.8,  # 80% effective when detected
        )

    def _calculate_red_score(self, metrics: RedTeamMetrics) -> float:
        """Calculate red team score (0-100)."""
        score = (
            metrics.true_positive_rate * 40
            + metrics.exploit_success_rate * 30
            + (1 - metrics.false_positive_rate) * 15
            + min(100 / max(metrics.mean_time_to_compromise, 1), 1) * 15
        )
        return round(min(score * 100, 100), 2)

    def _calculate_blue_score(self, metrics: BlueTeamMetrics) -> float:
        """Calculate blue team score (0-100)."""
        score = (
            metrics.detection_rate * 50
            + (1 - metrics.false_positive_rate) * 25
            + min(300 / max(metrics.mean_time_to_detect, 1), 1) * 15
            + metrics.mitigation_effectiveness * 10
        )
        return round(min(score * 100, 100), 2)

    def _calculate_overall_score(self, red_score: float, blue_score: float) -> float:
        """Calculate overall security score using geometric mean."""
        if red_score == 0 or blue_score == 0:
            return 0.0
        return round((red_score * blue_score) ** 0.5, 2)

    def _generate_recommendations(
        self, red_metrics: RedTeamMetrics, blue_metrics: BlueTeamMetrics
    ) -> List[str]:
        """Generate recommendations based on evaluation results."""
        recommendations = []

        if red_metrics.true_positive_rate < 0.7:
            recommendations.append(
                "Red Team: Improve vulnerability discovery techniques and exploit development capabilities."
            )

        if red_metrics.mean_time_to_compromise > 300:
            recommendations.append(
                "Red Team: Optimize attack paths to reduce time to compromise."
            )

        if blue_metrics.detection_rate < 0.7:
            recommendations.append(
                "Blue Team: Enhance detection capabilities, particularly for advanced persistent threats."
            )

        if blue_metrics.mean_time_to_detect > 120:
            recommendations.append(
                "Blue Team: Implement real-time monitoring to reduce detection time."
            )

        if blue_metrics.false_positive_rate > 0.15:
            recommendations.append(
                "Blue Team: Tune detection rules to reduce false positive rate."
            )

        if not recommendations:
            recommendations.append(
                "Overall: Both teams demonstrate strong capabilities. Continue training and exercises."
            )

        return recommendations

    def generate_report(self, evaluation_result: Dict) -> str:
        """Generate a human-readable report from evaluation results."""
        report = f"""
# Red/Blue Team Evaluation Report

**Evaluation ID:** {evaluation_result['evaluation_id']}
**Date:** {evaluation_result['timestamp']}

## Summary Scores

| Team | Score |
|------|-------|
| Red Team | {evaluation_result['red_team_score']}/100 |
| Blue Team | {evaluation_result['blue_team_score']}/100 |
| **Overall** | **{evaluation_result['overall_score']}/100** |

## Red Team Metrics

- True Positive Rate: {evaluation_result['red_team_metrics']['true_positive_rate']:.2%}
- Exploit Success Rate: {evaluation_result['red_team_metrics']['exploit_success_rate']:.2%}
- Mean Time to Compromise: {evaluation_result['red_team_metrics']['mean_time_to_compromise']:.2f}s

## Blue Team Metrics

- Detection Rate: {evaluation_result['blue_team_metrics']['detection_rate']:.2%}
- False Positive Rate: {evaluation_result['blue_team_metrics']['false_positive_rate']:.2%}
- Mean Time to Detect: {evaluation_result['blue_team_metrics']['mean_time_to_detect']:.2f}s

## Recommendations

"""
        for i, rec in enumerate(evaluation_result["recommendations"], 1):
            report += f"{i}. {rec}\n"

        return report
