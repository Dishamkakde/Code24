import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.services.classification_service import (
    get_attack_dataset_metadata,
    get_stix_technique_by_id,
    classify_finding,
    calculate_cvss31_score,
)
from app.models.schemas import EvidenceBasedClassification, Finding


class TestEvidenceBasedClassification(unittest.TestCase):
    def test_stix_dataset_metadata(self):
        """Verify the versioned MITRE ATT&CK dataset metadata is loaded and valid."""
        meta = get_attack_dataset_metadata()
        self.assertEqual(meta["attack_version"], "v15.1")
        self.assertIn("MITRE ATT&CK Enterprise", meta["dataset_name"])
        self.assertEqual(meta["spec_version"], "2.1")
        self.assertTrue(len(meta["retrieval_date"]) > 0)
        self.assertTrue(meta["source_url"].startswith("https://raw.githubusercontent.com/mitre"))
        self.assertGreater(meta["total_techniques_loaded"], 5)

    def test_stix_technique_lookup(self):
        """Verify lookup of techniques from the authoritative STIX dataset."""
        t1190 = get_stix_technique_by_id("T1190")
        self.assertIsNotNone(t1190)
        self.assertEqual(t1190["technique_id"], "T1190")
        self.assertEqual(t1190["name"], "Exploit Public-Facing Application")
        self.assertIn("Initial Access", t1190["tactics"])

        t1059_004 = get_stix_technique_by_id("T1059.004")
        self.assertIsNotNone(t1059_004)
        self.assertEqual(t1059_004["name"], "Command and Scripting Interpreter: Unix Shell")
        self.assertIn("Execution", t1059_004["tactics"])

    def test_sql_injection_classification_positive_attack(self):
        """Verify SQL injection maps to CWE-89, OWASP A03:2021, and ATT&CK T1190 with defensible reasoning."""
        raw_dict = classify_finding(
            scanner_name="bandit",
            scanner_rule_id="B608",
            raw_cwe="CWE-89",
            scanner_severity="HIGH",
            scanner_confidence="HIGH",
            scanner_message="Hardcoded SQL string formatting detected",
            file_path="app.py",
            cvss_score=8.5,
        )

        # Validate against Pydantic schema
        classification = EvidenceBasedClassification(**raw_dict)

        # CWE Software Weakness
        self.assertEqual(classification.cwe.id, "CWE-89")
        self.assertIn("SQL Command", classification.cwe.name)
        self.assertEqual(classification.cwe.url, "https://cwe.mitre.org/data/definitions/89.html")

        # OWASP Risk Taxonomy
        self.assertIsNotNone(classification.owasp)
        self.assertEqual(classification.owasp.code, "A03:2021")
        self.assertEqual(classification.owasp.category, "Injection")

        # MITRE ATT&CK Adversary Technique (authoritative STIX)
        self.assertIsNotNone(classification.attack)
        self.assertEqual(classification.attack.technique_id, "T1190")
        self.assertEqual(classification.attack.technique_name, "Exploit Public-Facing Application")
        self.assertIn("Initial Access", classification.attack.tactics)
        self.assertEqual(classification.attack.confidence, "HIGH")

        # Custom in-house application code must NEVER have a fake CVE assigned
        self.assertIsNone(classification.cve)

        # CVSS must be calculated from formula, not fabricated
        self.assertEqual(classification.cvss.source_type, "calculated")
        self.assertEqual(classification.cvss.score, 8.5)
        self.assertIn("CVSS:3.1", classification.cvss.vector)

        # Traceability statement must document all distinct evidence sources
        self.assertTrue(len(classification.traceability_statement) > 20)
        self.assertIn("bandit", classification.traceability_statement)
        self.assertIn("CWE-89", classification.traceability_statement)
        self.assertIn("T1190", classification.traceability_statement)

    def test_defensive_omission_negative_attack(self):
        """Verify defensive omission (e.g. missing security headers / CWE-693) explicitly maps to ATT&CK: None."""
        raw_dict = classify_finding(
            scanner_name="semgrep",
            scanner_rule_id="python.flask.security.audit.missing-security-headers",
            raw_cwe="CWE-693",
            scanner_severity="LOW",
            scanner_confidence="MEDIUM",
            scanner_message="Missing HTTP Security Headers on web response",
            file_path="server.py",
            cvss_score=3.5,
        )

        classification = EvidenceBasedClassification(**raw_dict)

        self.assertEqual(classification.cwe.id, "CWE-693")
        # Negative ATT&CK mapping: MUST be None, not an invented tactic
        self.assertIsNone(classification.attack)
        # Custom code MUST have cve: None
        self.assertIsNone(classification.cve)
        self.assertIn("no defensible adversary ttp exists", classification.traceability_statement.lower())

    def test_dependency_vulnerability_with_sourced_cve_and_cvss(self):
        """Verify dependency finding retains actual package, version, CVE and sourced CVSS."""
        raw_dict = classify_finding(
            scanner_name="pip-audit",
            scanner_rule_id="PYSEC-2023-1234",
            raw_cwe="CWE-1333",
            scanner_severity="HIGH",
            scanner_confidence="HIGH",
            scanner_message="Inefficient Regular Expression Complexity in urllib3",
            file_path="requirements.txt",
            cvss_score=7.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            dependency_pkg="urllib3",
            dependency_version="1.26.4",
            cve_id="CVE-2023-43804",
            advisory_url="https://nvd.nist.gov/vuln/detail/CVE-2023-43804",
            advisory_summary="Cookie request header leakage on redirect",
        )

        classification = EvidenceBasedClassification(**raw_dict)

        # CVE
        self.assertIsNotNone(classification.cve)
        self.assertEqual(classification.cve.cve_id, "CVE-2023-43804")
        self.assertEqual(classification.cve.package_name, "urllib3")
        self.assertEqual(classification.cve.declared_version, "1.26.4")

        # CVSS
        self.assertEqual(classification.cvss.source_type, "sourced")
        self.assertEqual(classification.cvss.score, 7.5)
        self.assertIn("OSV / NVD", classification.cvss.source_authority)
        self.assertEqual(classification.cvss.vector, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H")

    def test_cvss31_formula_accuracy(self):
        """Verify the CVSS 3.1 base score formula computes accurately per specification."""
        # Critical test vector: Network, Low complexity, None privileges, None user interaction, Unchanged scope, High C, High I, High A -> 9.8
        score_crit = calculate_cvss31_score(
            av="N", ac="L", pr="N", ui="N", scope="U", c="H", i="H", a="H"
        )
        self.assertEqual(score_crit, 9.8)

        # Medium test vector: Local, Low complexity, Low privileges, None UI, Unchanged scope, Low C, None I, None A -> 3.3
        score_med = calculate_cvss31_score(
            av="L", ac="L", pr="L", ui="N", scope="U", c="L", i="N", a="N"
        )
        self.assertEqual(score_med, 3.3)


if __name__ == "__main__":
    unittest.main()
