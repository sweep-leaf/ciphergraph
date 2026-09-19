"""
Security Metrics and CVSS Calculation for CipherGraph
"""

from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from enum import Enum
import math


class SeverityLevel(Enum):
    """CVSS Severity Levels."""

    NONE = ("None", 0.0)
    LOW = ("Low", 0.1 - 3.9)
    MEDIUM = ("Medium", 4.0 - 6.9)
    HIGH = ("High", 7.0 - 8.9)
    CRITICAL = ("Critical", 9.0 - 10.0)

    def __init__(self, label, range_tuple):
        self.label = label
        self.range = range_tuple

    @classmethod
    def from_score(cls, score: float) -> "SeverityLevel":
        """Get severity level from CVSS score."""
        if score == 0.0:
            return cls.NONE
        elif score < 4.0:
            return cls.LOW
        elif score < 7.0:
            return cls.MEDIUM
        elif score < 9.0:
            return cls.HIGH
        else:
            return cls.CRITICAL


@dataclass
class CVSSMetrics:
    """CVSS v3.1 Base Metrics."""

    attack_vector: str = "N"  # N, A, L, P
    attack_complexity: str = "L"  # L, H
    privileges_required: str = "N"  # N, L, H
    user_interaction: str = "N"  # N, R
    scope: str = "U"  # U, C
    confidentiality_impact: str = "N"  # N, L, H
    integrity_impact: str = "N"  # N, L, H
    availability_impact: str = "N"  # N, L, H

    def to_dict(self) -> Dict:
        return {
            "AV": self.attack_vector,
            "AC": self.attack_complexity,
            "PR": self.privileges_required,
            "UI": self.user_interaction,
            "S": self.scope,
            "C": self.confidentiality_impact,
            "I": self.integrity_impact,
            "A": self.availability_impact,
        }


class CVSSCalculator:
    """
    CVSS v3.1 Calculator.

    Implements the CVSS 3.1 formula for calculating base scores.
    """

    # Metric values
    AV_VALUES = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
    AC_VALUES = {"L": 0.77, "H": 0.44}
    PR_VALUES_SCOPE_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
    PR_VALUES_SCOPE_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.36}
    UI_VALUES = {"N": 0.85, "R": 0.62}
    C_VALUES = {"N": 0.0, "L": 0.22, "H": 0.56}
    I_VALUES = {"N": 0.0, "L": 0.22, "H": 0.56}
    A_VALUES = {"N": 0.0, "L": 0.22, "H": 0.56}

    def __init__(self):
        pass

    def calculate_base_score(self, metrics: CVSSMetrics) -> Tuple[float, Dict]:
        """
        Calculate CVSS v3.1 Base Score.

        Args:
            metrics: CVSS metric values

        Returns:
            Tuple of (base_score, metric_scores)
        """
        # Get metric values
        av = self.AV_VALUES[self._normalize_metric(metrics.attack_vector, self.AV_VALUES)]
        ac = self.AC_VALUES[self._normalize_metric(metrics.attack_complexity, self.AC_VALUES)]

        # Privileges required depends on scope
        if metrics.scope in ("C", "Changed"):
            pr = self.PR_VALUES_SCOPE_CHANGED[
                self._normalize_metric(metrics.privileges_required, self.PR_VALUES_SCOPE_CHANGED)
            ]
        else:
            pr = self.PR_VALUES_SCOPE_UNCHANGED[
                self._normalize_metric(metrics.privileges_required, self.PR_VALUES_SCOPE_UNCHANGED)
            ]

        ui = self.UI_VALUES[self._normalize_metric(metrics.user_interaction, self.UI_VALUES)]

        c = self.C_VALUES[self._normalize_metric(metrics.confidentiality_impact, self.C_VALUES)]
        i = self.I_VALUES[self._normalize_metric(metrics.integrity_impact, self.I_VALUES)]
        a = self.A_VALUES[self._normalize_metric(metrics.availability_impact, self.A_VALUES)]

        # Calculate impact
        if metrics.scope in ("C", "Changed"):
            impact = 1 - (1 - c) * (1 - i) * (1 - a)
            impact = 7.52 * (impact - 0.029) - 3.25 * (impact - 0.02) ** 15
        else:
            impact = 1 - (1 - c) * (1 - i) * (1 - a)
            impact = 6.42 * impact

        # Calculate exploitability
        exploitability = 8.22 * av * ac * pr * ui

        # Calculate base score
        if impact <= 0:
            base_score = 0.0
        elif metrics.scope in ("C", "Changed"):
            base_score = (
                min(1.08 * (impact + exploitability), 10)
                if impact > 0
                else min(0.915 * exploitability, 10)
            )
        else:
            base_score = (
                min(impact + exploitability, 10)
                if impact > 0
                else min(exploitability, 10)
            )

        metric_scores = {
            "AV": av,
            "AC": ac,
            "PR": pr,
            "UI": ui,
            "C": c,
            "I": i,
            "A": a,
            "Impact": impact,
            "Exploitability": exploitability,
        }

        return round(base_score, 1), metric_scores

    def _normalize_metric(self, value: str, value_map: Dict) -> str:
        """Normalize metric value to valid key."""
        # Handle full words
        normalizations = {
            "Network": "N",
            "Adjacent": "A",
            "Local": "L",
            "Physical": "P",
            "Low": "L",
            "High": "H",
            "None": "N",
            "Required": "R",
            "Unchanged": "U",
            "Changed": "C",
        }

        if value in value_map:
            return value

        normalized = normalizations.get(value, value)
        if normalized in value_map:
            return normalized

        # Return first key as fallback
        return list(value_map.keys())[0]

    def predict_severity(
        self, description: str, affected_product: str, attack_vector: str = "N"
    ) -> Dict:
        """
        Predict severity based on vulnerability description.

        This is a heuristic prediction for cases where CVSS is not available.
        """
        description_lower = description.lower()
        product_lower = affected_product.lower()

        # Keyword-based severity estimation
        critical_keywords = ["remote code execution", "rce", "zero-day", "critical"]
        high_keywords = ["privilege escalation", "sql injection", "xss", "cross-site"]
        medium_keywords = ["denial of service", "dos", "information disclosure"]
        low_keywords = ["low severity", "minor", "enhancement"]

        severity_score = 5.0  # Default medium

        for keyword in critical_keywords:
            if keyword in description_lower:
                severity_score = 9.5
                break

        for keyword in high_keywords:
            if keyword in description_lower:
                severity_score = 7.5
                break

        for keyword in medium_keywords:
            if keyword in description_lower:
                severity_score = 5.0
                break

        for keyword in low_keywords:
            if keyword in description_lower:
                severity_score = 2.5
                break

        # Adjust based on attack vector
        if attack_vector == "N":
            severity_score *= 1.0
        elif attack_vector == "A":
            severity_score *= 0.95
        elif attack_vector == "L":
            severity_score *= 0.85
        else:
            severity_score *= 0.75

        return {
            "predicted_score": round(min(severity_score, 10.0), 1),
            "severity_level": SeverityLevel.from_score(severity_score).label,
            "confidence": 0.65,
            "method": "keyword_based_heuristic",
        }


class VulnerabilityMetrics:
    """
    Calculate metrics for vulnerability assessment.
    """

    def __init__(self):
        self.cvss_calculator = CVSSCalculator()

    def calculate_precision_recall(
        self, predicted: List[str], actual: List[str]
    ) -> Dict[str, float]:
        """
        Calculate precision and recall for vulnerability predictions.

        Args:
            predicted: List of predicted vulnerability IDs
            actual: List of actual vulnerability IDs

        Returns:
            Dictionary with precision, recall, F1
        """
        predicted_set = set(predicted)
        actual_set = set(actual)

        true_positives = len(predicted_set & actual_set)
        false_positives = len(predicted_set - actual_set)
        false_negatives = len(actual_set - predicted_set)

        precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0.0
        recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0.0
        f1 = (
            2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        )

        return {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
            "true_positives": true_positives,
            "false_positives": false_positives,
            "false_negatives": false_negatives,
        }

    def calculate_attack_coverage(
        self, vulnerabilities_found: List[Dict], all_vulnerabilities: List[Dict]
    ) -> Dict[str, float]:
        """
        Calculate coverage metrics for vulnerability discovery.

        Args:
            vulnerabilities_found: Discovered vulnerabilities
            all_vulnerabilities: All known vulnerabilities

        Returns:
            Coverage metrics
        """
        found_ids = {v.get("cve_id") for v in vulnerabilities_found}
        all_ids = {v.get("cve_id") for v in all_vulnerabilities}

        coverage = len(found_ids & all_ids) / len(all_ids) if len(all_ids) > 0 else 0.0

        # Calculate severity-weighted coverage
        total_severity = sum(v.get("severity", 0) for v in all_vulnerabilities)
        found_severity = sum(
            v.get("severity", 0) for v in vulnerabilities_found if v.get("cve_id") in all_ids
        )

        severity_coverage = found_severity / total_severity if total_severity > 0 else 0.0

        return {
            "vulnerability_coverage": round(coverage * 100, 2),
            "severity_weighted_coverage": round(severity_coverage * 100, 2),
            "vulnerabilities_found": len(found_ids & all_ids),
            "total_vulnerabilities": len(all_ids),
        }

    def calculate_attack_path_metrics(
        self, predicted_paths: List[List[str]], actual_paths: List[List[str]]
    ) -> Dict[str, float]:
        """
        Calculate metrics for attack path prediction.

        Args:
            predicted_paths: Predicted attack paths
            actual_paths: Actual/expected attack paths

        Returns:
            Path prediction metrics
        """
        predicted_set = {tuple(p) for p in predicted_paths}
        actual_set = {tuple(p) for p in actual_paths}

        exact_matches = len(predicted_set & actual_set)

        # Calculate Mean Reciprocal Rank (MRR)
        mrr = 0.0
        for actual_path in actual_set:
            for i, pred_path in enumerate(predicted_paths):
                if tuple(pred_path) == actual_path:
                    mrr += 1 / (i + 1)
                    break
        mrr /= len(actual_set) if len(actual_set) > 0 else 1

        # Calculate path accuracy
        accuracy = exact_matches / len(predicted_set) if len(predicted_set) > 0 else 0.0

        return {
            "exact_match_accuracy": round(accuracy, 4),
            "mean_reciprocal_rank": round(mrr, 4),
            "paths_predicted": len(predicted_paths),
            "paths_correct": exact_matches,
        }
