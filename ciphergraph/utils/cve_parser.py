"""
CVE Data Parser for CipherGraph
Parses vulnerability data from various sources into standardized format
"""

from typing import List, Dict, Optional
from dataclasses import asdict
import json
import re


class CVEParser:
    """
    Parser for CVE vulnerability data.

    Supports:
    - JSON format (NVD API response)
    - CSV format
    - CVE text format
    """

    def __init__(self):
        self.supported_formats = ["json", "csv", "text"]

    def parse_file(self, file_path: str) -> List[Dict]:
        """
        Parse CVE data from file.

        Args:
            file_path: Path to CVE data file

        Returns:
            List of vulnerability dictionaries
        """
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        if file_path.endswith(".json"):
            return self.parse_json(content)
        elif file_path.endswith(".csv"):
            return self.parse_csv(content)
        else:
            return self.parse_text(content)

    def parse_json(self, content: str) -> List[Dict]:
        """Parse CVE data from JSON format."""
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return []

        vulnerabilities = []

        # Handle NVD API v3.1 format
        if "vulnerabilities" in data:
            for vuln in data["vulnerabilities"]:
                cve = vuln.get("cve", {})
                vuln_data = self._parse_nvd_cve(cve)
                if vuln_data:
                    vulnerabilities.append(vuln_data)

        # Handle direct list format
        elif isinstance(data, list):
            for item in data:
                if "cve_id" in item:
                    vulnerabilities.append(item)
                elif "CVE" in str(item):
                    vulnerabilities.append(self._parse_text_cve(str(item)))

        return vulnerabilities

    def _parse_nvd_cve(self, cve: Dict) -> Optional[Dict]:
        """Parse NVD API CVE format."""
        cve_id = cve.get("id", "")
        if not cve_id:
            return None

        descriptions = cve.get("descriptions", [{}])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        # Extract CVSS metrics
        metrics = cve.get("metrics", {})
        cvss_v31 = metrics.get("cvssMetricV31", [{}])
        cvss_v30 = metrics.get("cvssMetricV30", [{}])
        cvss_v2 = metrics.get("cvssMetricV2", [{}])

        if cvss_v31:
            cvss_data = cvss_v31[0].get("cvssData", {})
            severity = cvss_data.get("baseScore", 5.0)
            attack_vector = cvss_data.get("attackVector", "N")
            attack_complexity = cvss_data.get("attackComplexity", "L")
            privileges_required = cvss_data.get("privilegesRequired", "N")
            user_interaction = cvss_data.get("userInteraction", "N")
            scope = cvss_data.get("scope", "U")
            confidentiality_impact = cvss_data.get("confidentialityImpact", "N")
            integrity_impact = cvss_data.get("integrityImpact", "N")
            availability_impact = cvss_data.get("availabilityImpact", "N")
        elif cvss_v30:
            cvss_data = cvss_v30[0].get("cvssData", {})
            severity = cvss_data.get("baseScore", 5.0)
            attack_vector = cvss_data.get("attackVector", "N")
            attack_complexity = cvss_data.get("attackComplexity", "L")
            privileges_required = cvss_data.get("privilegesRequired", "N")
            user_interaction = cvss_data.get("userInteraction", "N")
            scope = cvss_data.get("scope", "U")
            confidentiality_impact = cvss_data.get("confidentialityImpact", "N")
            integrity_impact = cvss_data.get("integrityImpact", "N")
            availability_impact = cvss_data.get("availabilityImpact", "N")
        elif cvss_v2:
            cvss_data = cvss_v2[0].get("cvssData", {})
            severity = cvss_data.get("baseScore", 5.0)
            attack_vector = cvss_data.get("accessVector", "N")[0] if cvss_data.get("accessVector") else "N"
            attack_complexity = cvss_data.get("accessComplexity", "L")[0] if cvss_data.get("accessComplexity") else "L"
            privileges_required = "N"
            user_interaction = "N"
            scope = "U"
            confidentiality_impact = cvss_data.get("confidentialityImpact", "N")[0] if cvss_data.get("confidentialityImpact") else "N"
            integrity_impact = cvss_data.get("integrityImpact", "N")[0] if cvss_data.get("integrityImpact") else "N"
            availability_impact = cvss_data.get("availabilityImpact", "N")[0] if cvss_data.get("availabilityImpact") else "N"
        else:
            severity = 5.0
            attack_vector = "N"
            attack_complexity = "L"
            privileges_required = "N"
            user_interaction = "N"
            scope = "U"
            confidentiality_impact = "N"
            integrity_impact = "N"
            availability_impact = "N"

        # Extract affected products
        configurations = cve.get("configurations", [])
        affected_products = []
        for config in configurations:
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if match.get("vulnerable", False):
                        cpe = match.get("criteria", "")
                        product = self._extract_product_from_cpe(cpe)
                        if product:
                            affected_products.append(product)

        # Extract references
        references = cve.get("references", [])
        reference_urls = [ref.get("url", "") for ref in references[:3]]

        return {
            "cve_id": cve_id,
            "description": description,
            "severity": float(severity),
            "attack_vector": attack_vector,
            "attack_complexity": attack_complexity,
            "privileges_required": privileges_required,
            "user_interaction": user_interaction,
            "scope": scope,
            "confidentiality_impact": confidentiality_impact,
            "integrity_impact": integrity_impact,
            "availability_impact": availability_impact,
            "affected_product": ", ".join(affected_products[:3]) if affected_products else "Unknown",
            "published_date": cve.get("published", ""),
            "last_modified": cve.get("lastModified", ""),
            "references": reference_urls,
        }

    def _extract_product_from_cpe(self, cpe: str) -> Optional[str]:
        """Extract product name from CPE string."""
        # CPE format: cpe:2.3:a:vendor:product:version:...
        parts = cpe.split(":")
        if len(parts) >= 4:
            return f"{parts[3]}"
        return None

    def parse_csv(self, content: str) -> List[Dict]:
        """Parse CVE data from CSV format."""
        lines = content.strip().split("\n")
        if not lines:
            return []

        vulnerabilities = []
        headers = [h.strip().lower() for h in lines[0].split(",")]

        for line in lines[1:]:
            values = line.split(",")
            if len(values) < len(headers):
                continue

            vuln = {}
            for i, header in enumerate(headers):
                if i < len(values):
                    vuln[header.strip()] = values[i].strip()

            if "cve_id" in vuln or "cveid" in vuln:
                vuln["cve_id"] = vuln.get("cve_id", vuln.get("cveid", ""))
                vulnerabilities.append(vuln)

        return vulnerabilities

    def parse_text(self, content: str) -> List[Dict]:
        """Parse CVE data from text format."""
        vulnerabilities = []

        # Pattern: CVE-YYYY-NNNNN+
        cve_pattern = r"(CVE-\d{4}-\d{4,})"

        matches = re.findall(cve_pattern, content)
        for cve_id in set(matches):
            vuln = self._parse_text_cve(cve_id)
            if vuln:
                vulnerabilities.append(vuln)

        return vulnerabilities

    def _parse_text_cve(self, cve_str: str) -> Dict:
        """Parse a single CVE from text."""
        cve_id = re.search(r"CVE-\d{4}-\d{4,}", cve_str)
        if not cve_id:
            return {}

        return {
            "cve_id": cve_id.group(),
            "description": cve_str,
            "severity": 5.0,
            "attack_vector": "N",
            "attack_complexity": "L",
            "privileges_required": "N",
            "user_interaction": "N",
            "scope": "U",
            "confidentiality_impact": "N",
            "integrity_impact": "N",
            "availability_impact": "N",
            "affected_product": "Unknown",
            "published_date": "",
        }

    def filter_by_severity(
        self, vulnerabilities: List[Dict], min_severity: float = 7.0
    ) -> List[Dict]:
        """Filter vulnerabilities by minimum CVSS severity."""
        return [v for v in vulnerabilities if v.get("severity", 0) >= min_severity]

    def filter_by_keyword(
        self, vulnerabilities: List[Dict], keyword: str
    ) -> List[Dict]:
        """Filter vulnerabilities by keyword in description."""
        keyword_lower = keyword.lower()
        return [
            v
            for v in vulnerabilities
            if keyword_lower in v.get("description", "").lower()
        ]
