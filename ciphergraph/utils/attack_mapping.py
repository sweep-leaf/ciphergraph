"""
ATT&CK Mapping Utilities for CipherGraph
Maps vulnerabilities and attack patterns to MITRE ATT&CK framework
"""

from typing import Dict, List, Optional, Set
from dataclasses import dataclass
import json


@dataclass
class ATTACKTechnique:
    """Represents an ATT&CK technique."""

    technique_id: str  # e.g., "T1190"
    name: str
    tactics: List[str]
    description: str
    detection: str
    mitigation: str
    related_cves: List[str]


class ATTACKMapper:
    """
    Maps vulnerabilities and attack patterns to MITRE ATT&CK framework.

    Provides:
    - CVE to ATT&CK technique mapping
    - Attack technique to CVE mapping
    - Tactic-based technique queries
    """

    # Predefined mappings (subset of common CVEs to ATT&CK)
    CVE_TO_TECHNIQUE = {
        "CVE-2021-44228": "T1190",  # Log4j - Exploit Public-Facing Application
        "CVE-2021-45046": "T1190",
        "CVE-2022-22965": "T1190",  # Spring4Shell - Exploit Public-Facing Application
        "CVE-2021-26855": "T1190",  # ProxyLogon - Exploit Public-Facing Application
        "CVE-2021-26857": "T1210",  # ProxyLogon - Exploitation of Remote Services
        "CVE-2021-34523": "T1021",  # PrintNightmare - Remote Services
        "CVE-2021-1675": "T1021",
        "CVE-2020-1472": "T1210",  # Zerologon - Exploitation of Remote Services
        "CVE-2019-0708": "T1210",  # BlueKeep - Exploitation of Remote Services
        "CVE-2017-0144": "T1210",  # EternalBlue - Exploitation of Remote Services
        "CVE-2017-0145": "T1210",
    }

    # ATT&CK Technique definitions
    TECHNIQUES = {
        "T1190": ATTACKTechnique(
            technique_id="T1190",
            name="Exploit Public-Facing Application",
            tactics=["Initial Access"],
            description="Adversaries may exploit public-facing applications to gain initial access.",
            detection="Web application firewalls, logging, anomaly detection",
            mitigation="Patch management, WAF, input validation",
            related_cves=["CVE-2021-44228", "CVE-2021-45046", "CVE-2022-22965"],
        ),
        "T1210": ATTACKTechnique(
            technique_id="T1210",
            name="Exploitation of Remote Services",
            tactics=["Lateral Movement", "Initial Access"],
            description="Exploiting remote services to gain access to systems.",
            detection="Network monitoring, anomalous traffic",
            mitigation="Network segmentation, patching, monitoring",
            related_cves=["CVE-2020-1472", "CVE-2019-0708", "CVE-2017-0144"],
        ),
        "T1021": ATTACKTechnique(
            technique_id="T1021",
            name="Remote Services",
            tactics=["Lateral Movement"],
            description="Using legitimate services for lateral movement.",
            detection="Authentication logging, unusual service usage",
            mitigation="MFA, least privilege, service monitoring",
            related_cves=["CVE-2021-34523", "CVE-2021-1675"],
        ),
        "T1059": ATTACKTechnique(
            technique_id="T1059",
            name="Command and Scripting Interpreter",
            tactics=["Execution"],
            description="Execution of commands or scripts for execution.",
            detection="Command logging, script monitoring",
            mitigation="Restrict script execution, application whitelisting",
            related_cves=[],
        ),
        "T1055": ATTACKTechnique(
            technique_id="T1055",
            name="Process Injection",
            tactics=["Defense Evasion", "Privilege Escalation"],
            description="Injecting code into processes to evade detection.",
            detection="Process monitoring, behavior analysis",
            mitigation="EDR solutions, least privilege",
            related_cves=[],
        ),
        "T1547": ATTACKTechnique(
            technique_id="T1547",
            name="Boot or Logon Autostart Execution",
            tactics=["Persistence", "Privilege Escalation"],
            description="Modifying autostart locations for persistence.",
            detection="Registry monitoring, startup folder analysis",
            mitigation="Restrict autostart modifications, monitoring",
            related_cves=[],
        ),
        "T1068": ATTACKTechnique(
            technique_id="T1068",
            name="Exploitation for Privilege Escalation",
            tactics=["Privilege Escalation"],
            description="Exploiting vulnerabilities to gain higher privileges.",
            detection="Vulnerability scanning, privilege monitoring",
            mitigation="Patch management, least privilege",
            related_cves=[],
        ),
        "T1484": ATTACKTechnique(
            technique_id="T1484",
            name="Domain Trust Modification",
            tactics=["Defense Evasion", "Lateral Movement"],
            description="Modifying domain trust relationships.",
            detection="Authentication monitoring, trust relationship audits",
            mitigation="Secure trust configurations, monitoring",
            related_cves=[],
        ),
        "T1550": ATTACKTechnique(
            technique_id="T1550",
            name="Use Alternative Authentication Material",
            tactics=["Lateral Movement", "Defense Evasion"],
            description="Using alternate credentials for authentication.",
            detection="Credential usage monitoring",
            mitigation="MFA, credential rotation",
            related_cves=[],
        ),
        "T1070": ATTACKTechnique(
            technique_id="T1070",
            name="Indicator Removal",
            tactics=["Defense Evasion"],
            description="Removing indicators of compromise.",
            detection="File integrity monitoring, log analysis",
            mitigation="Centralized logging, immutable backups",
            related_cves=[],
        ),
    }

    # Tactic definitions
    TACTICS = {
        "Reconnaissance": "Gathering information about the target",
        "Resource Development": "Developing resources for operations",
        "Initial Access": "Finding a way into the target",
        "Execution": "Running malicious code",
        "Persistence": "Maintaining access",
        "Privilege Escalation": "Gaining higher privileges",
        "Defense Evasion": "Avoiding detection",
        "Credential Access": "Stealing credentials",
        "Discovery": "Exploring the environment",
        "Lateral Movement": "Moving through the environment",
        "Collection": "Gathering data",
        "Command and Control": "Communicating with compromised systems",
        "Exfiltration": "Stealing data",
        "Impact": "Manipulating or destroying data",
    }

    def __init__(self):
        self._technique_cache: Dict[str, ATTACKTechnique] = self.TECHNIQUES

    def get_technique(self, technique_id: str) -> Optional[ATTACKTechnique]:
        """Get ATT&CK technique by ID."""
        return self._technique_cache.get(technique_id)

    def get_techniques_by_tactic(self, tactic: str) -> List[ATTACKTechnique]:
        """Get all techniques for a specific tactic."""
        techniques = []
        for tech in self._technique_cache.values():
            if tactic in tech.tactics:
                techniques.append(tech)
        return techniques

    def get_techniques_by_cve(self, cve_id: str) -> List[ATTACKTechnique]:
        """Get techniques related to a CVE."""
        technique_ids = self.CVE_TO_TECHNIQUE.get(cve_id, [])
        if isinstance(technique_ids, str):
            technique_ids = [technique_ids]

        techniques = []
        for tech_id in technique_ids:
            tech = self.get_technique(tech_id)
            if tech:
                techniques.append(tech)
        return techniques

    def get_cves_by_technique(self, technique_id: str) -> List[str]:
        """Get CVEs related to a technique."""
        tech = self.get_technique(technique_id)
        if tech:
            return tech.related_cves

        # Search in CVE_TO_TECHNIQUE
        cves = []
        for cve, tech in self.CVE_TO_TECHNIQUE.items():
            if tech == technique_id:
                cves.append(cve)
        return cves

    def map_cve_to_technique(self, cve_id: str) -> Optional[str]:
        """Map a CVE to its primary ATT&CK technique."""
        return self.CVE_TO_TECHNIQUE.get(cve_id)

    def get_tactics_for_technique(self, technique_id: str) -> List[str]:
        """Get tactics for a technique."""
        tech = self.get_technique(technique_id)
        return tech.tactics if tech else []

    def get_attack_chain(self, technique_ids: List[str]) -> List[Dict]:
        """
        Generate an attack chain from technique IDs.

        Returns ordered list of techniques with tactics and descriptions.
        """
        chain = []
        for tech_id in technique_ids:
            tech = self.get_technique(tech_id)
            if tech:
                chain.append(
                    {
                        "technique_id": tech.technique_id,
                        "name": tech.name,
                        "tactics": tech.tactics,
                        "description": tech.description,
                    }
                )
        return chain

    def get_kill_chain_phases(self, technique_ids: List[str]) -> Dict[str, List[str]]:
        """
        Map techniques to MITRE ATT&CK kill chain phases.

        Returns:
            Dictionary mapping each kill chain phase to techniques in that phase
        """
        # Define kill chain phases
        kill_chain_order = [
            "Reconnaissance",
            "Weaponization",
            "Delivery",
            "Exploitation",
            "Installation",
            "Command and Control",
            "Actions on Objectives",
        ]

        # Map ATT&CK tactics to kill chain phases
        tactic_to_kill_chain = {
            "Reconnaissance": "Reconnaissance",
            "Resource Development": "Weaponization",
            "Initial Access": "Delivery",
            "Execution": "Exploitation",
            "Persistence": "Installation",
            "Privilege Escalation": "Installation",
            "Defense Evasion": "Installation",
            "Command and Control": "Command and Control",
            "Actions on Objectives": "Actions on Objectives",
        }

        phases = {phase: [] for phase in kill_chain_order}

        for tech_id in technique_ids:
            tech = self.get_technique(tech_id)
            if tech:
                for tactic in tech.tactics:
                    kill_chain_phase = tactic_to_kill_chain.get(tactic, "Exploitation")
                    if tech_id not in phases[kill_chain_phase]:
                        phases[kill_chain_phase].append(tech_id)

        return phases

    def get_coverage_matrix(self, techniques: List[str]) -> Dict:
        """
        Generate a coverage matrix for given techniques.

        Returns:
            Matrix showing tactic coverage
        """
        all_tactics = list(self.TACTICS.keys())
        coverage = {tactic: 0 for tactic in all_tactics}

        for tech_id in techniques:
            tech = self.get_technique(tech_id)
            if tech:
                for tactic in tech.tactics:
                    coverage[tactic] += 1

        return {
            "total_techniques": len(set(techniques)),
            "tactic_coverage": coverage,
            "covered_tactics": sum(1 for v in coverage.values() if v > 0),
            "total_tactics": len(all_tactics),
        }
