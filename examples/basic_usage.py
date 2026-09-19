"""
Basic usage example for CipherGraph
"""

from ciphergraph import CipherGraph
from ciphergraph.core.knowledge_graph import KnowledgeGraph, Vulnerability, AttackTechnique, SystemEntity
from ciphergraph.evaluation.metrics import CVSSCalculator, CVSSMetrics


def main():
    print("=" * 60)
    print("CipherGraph - Basic Usage Example")
    print("=" * 60)

    # Initialize CipherGraph
    print("\n[1] Initializing CipherGraph...")
    cg = CipherGraph()

    # Create knowledge graph with sample data
    print("\n[2] Building knowledge graph with sample vulnerabilities...")
    kg = KnowledgeGraph()

    # Add sample vulnerabilities
    vulns = [
        Vulnerability(
            cve_id="CVE-2024-0001",
            description="Remote code execution via HTTP request",
            severity=9.8,
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="U",
            confidentiality_impact="H",
            integrity_impact="H",
            availability_impact="H",
            affected_product="Apache 2.4.41",
            published_date="2024-01-15",
            related_techniques=["T1190"],
        ),
        Vulnerability(
            cve_id="CVE-2024-0002",
            description="SQL injection in authentication bypass",
            severity=8.2,
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="U",
            confidentiality_impact="H",
            integrity_impact="H",
            availability_impact="L",
            affected_product="MySQL 8.0.32",
            published_date="2024-02-01",
            related_techniques=["T1190", "T1210"],
        ),
        Vulnerability(
            cve_id="CVE-2024-0003",
            description="Privilege escalation via kernel exploit",
            severity=7.8,
            attack_vector="L",
            attack_complexity="H",
            privileges_required="L",
            user_interaction="N",
            scope="C",
            confidentiality_impact="H",
            integrity_impact="H",
            availability_impact="H",
            affected_product="Linux Kernel 5.15",
            published_date="2024-02-20",
            related_techniques=["T1068"],
        ),
    ]

    for vuln in vulns:
        kg.add_vulnerability(vuln)

    print(f"   Added {len(vulns)} vulnerabilities")

    # Get statistics
    stats = kg.get_statistics()
    print(f"\n[3] Knowledge Graph Statistics:")
    print(f"   Total nodes: {stats['total_nodes']}")
    print(f"   Vulnerabilities: {stats['vulnerabilities']}")
    print(f"   Attack techniques: {stats['attack_techniques']}")

    # Find attack paths
    print("\n[4] Finding attack paths...")
    paths = kg.find_attack_paths("web_server", "database")
    print(f"   Found {len(paths)} potential attack paths")

    # CVSS Calculator
    print("\n[5] CVSS Score Calculation:")
    calculator = CVSSCalculator()
    metrics = CVSSMetrics(
        attack_vector="N",
        attack_complexity="L",
        privileges_required="N",
        user_interaction="N",
        scope="U",
        confidentiality_impact="H",
        integrity_impact="H",
        availability_impact="H",
    )
    score, detail = calculator.calculate_base_score(metrics)
    print(f"   Calculated CVSS Score: {score}")
    print(f"   Impact: {detail['Impact']:.2f}")
    print(f"   Exploitability: {detail['Exploitability']:.2f}")

    # Query vulnerabilities
    print("\n[6] Querying high-severity vulnerabilities...")
    high_severity = kg.get_vulnerabilities_by_severity(min_severity=8.0)
    for vuln in high_severity:
        print(f"   - {vuln.cve_id}: CVSS {vuln.severity} ({vuln.cvss_category})")

    print("\n" + "=" * 60)
    print("Example completed successfully!")
    print("=" * 60)


if __name__ == "__main__":
    main()
