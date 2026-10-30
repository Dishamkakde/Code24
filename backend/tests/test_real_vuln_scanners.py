import sys
import unittest
from pathlib import Path

# Add backend directory to path
backend_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(backend_dir))

from app.services.vuln_engine import (
    identify_project_environment,
    run_bandit_scanner,
    run_semgrep_scanner,
    run_pip_audit_scanner,
    run_npm_audit_scanner,
    run_vulnerability_engine
)
from app.services.zip_service import redact_secrets, is_safe_path
from app.config import FIXTURES_DIR

VULN_FIXTURE_DIR = FIXTURES_DIR / "deliberately_vulnerable_fixture"
SAFE_FIXTURE_DIR = FIXTURES_DIR / "safe_fixture"

class TestRealVulnerabilityScanners(unittest.TestCase):

    def test_01_pre_analysis_identification(self):
        """Test pre-analysis detection of languages, frameworks, manifests, and scanners."""
        vuln_env = identify_project_environment(VULN_FIXTURE_DIR)
        self.assertIn("Python", vuln_env.languages)
        self.assertIn("requirements.txt", vuln_env.manifests)
        self.assertIn("package.json", vuln_env.manifests)
        self.assertIn("bandit", vuln_env.applicable_scanners)
        self.assertIn("semgrep", vuln_env.applicable_scanners)
        self.assertIn("pip-audit", vuln_env.applicable_scanners)
        self.assertIn("npm-audit", vuln_env.applicable_scanners)
        self.assertGreater(vuln_env.total_files, 0)
        self.assertGreater(vuln_env.total_lines, 0)

        safe_env = identify_project_environment(SAFE_FIXTURE_DIR)
        self.assertIn("Python", safe_env.languages)
        self.assertIn("bandit", safe_env.applicable_scanners)
        self.assertIn("semgrep", safe_env.applicable_scanners)

    def test_02_bandit_on_vulnerable_fixture(self):
        """Test Bandit on vulnerable fixture: verifies genuine findings and schema."""
        record, findings = run_bandit_scanner(VULN_FIXTURE_DIR)
        self.assertEqual(record.scanner_name, "bandit")
        self.assertEqual(record.status, "success")
        self.assertIsNotNone(record.scanner_version)
        self.assertGreater(len(findings), 0, "Bandit should detect real flaws in vulnerable fixture")

        # Check that Bandit detected SQL injection or shell=True or chmod or pickle
        test_ids = [f.rule_identifier for f in findings]
        self.assertTrue(any("B608" in tid or "B602" in tid or "B103" in tid or "B301" in tid for tid in test_ids),
                        f"Expected Bandit rules (e.g. B608, B602, B103, B301), got: {test_ids}")

        # Verify normalized schema on first finding
        f = findings[0]
        self.assertEqual(f.scanner_name, "bandit")
        self.assertIn("app.py", f.file)
        self.assertGreater(f.line, 0)
        self.assertGreater(f.end_line, 0)
        self.assertIn(f.severity, ["Urgent", "Important", "Needs attention"])
        self.assertIsNotNone(f.source_evidence)
        self.assertTrue(len(f.cwe_identifiers) > 0)
        self.assertTrue(f.cwe.startswith("CWE-"))
        self.assertIsNotNone(f.why_matched)
        self.assertIsNotNone(f.remediation_guidance)
        # Verify honesty constraint: static finding is NOT marked as experimentally verified
        self.assertIsNone(f.exploit_before)
        self.assertEqual(f.status, "suspected_pattern")
        self.assertEqual(f.verified_status, "unpatched")

    def test_03_semgrep_on_vulnerable_fixture(self):
        """Test Semgrep on vulnerable fixture using maintained security rules."""
        record, findings = run_semgrep_scanner(VULN_FIXTURE_DIR, ["Python"])
        self.assertEqual(record.scanner_name, "semgrep")
        self.assertEqual(record.status, "success")
        self.assertGreater(len(findings), 0, "Semgrep should detect real flaws in vulnerable fixture")

        rule_ids = [f.rule_identifier for f in findings]
        self.assertTrue(any("python-sqli" in rid or "command" in rid or "deserialization" in rid or "permission" in rid for rid in rule_ids),
                        f"Expected Semgrep rule matches, got: {rule_ids}")

        # Check that affected source lines are captured and evidence is populated
        f = findings[0]
        self.assertEqual(f.scanner_name, "semgrep")
        self.assertIn("app.py", f.file)
        self.assertGreater(len(f.snippet), 0)
        self.assertIn(f.confidence, ["HIGH", "MEDIUM", "LOW"])
        # Verify honesty constraint: static finding is NOT marked as experimentally verified
        self.assertIsNone(f.exploit_before)

    def test_04_pip_audit_on_vulnerable_fixture(self):
        """Test pip-audit runner explicitly handles dependency vulnerabilities or network failures."""
        record, findings = run_pip_audit_scanner(VULN_FIXTURE_DIR)
        self.assertEqual(record.scanner_name, "pip-audit")
        # In online environments it succeeds with findings; if offline, it reports failed without faking!
        if record.status == "success":
            self.assertGreater(len(findings), 0, "pip-audit should detect vulnerabilities in jinja2==2.11.2 or urllib3==1.26.4")
            f = findings[0]
            self.assertIn("requirements.txt", f.file)
            self.assertEqual(f.cwe, "CWE-1395")
            self.assertIsNone(f.exploit_before)
        else:
            self.assertIn(record.status, ["failed", "timed_out"])
            self.assertIsNotNone(record.error_message)
            self.assertEqual(len(findings), 0, "When scanner fails, no fabricated findings should be returned")

    def test_05_npm_audit_lockfile_handling(self):
        """Test npm-audit explicitly skips and reports missing lockfile instead of fabricating results."""
        record, findings = run_npm_audit_scanner(VULN_FIXTURE_DIR)
        self.assertEqual(record.scanner_name, "npm-audit")
        self.assertEqual(record.status, "skipped_missing_lockfile")
        self.assertIn("package-lock.json", record.error_message)
        self.assertEqual(len(findings), 0)

    def test_06_safe_fixture_clean_analysis(self):
        """Test safe fixture: parameterized SQL and secure calls produce no high-severity vulnerabilities."""
        env, reports, findings = run_vulnerability_engine(SAFE_FIXTURE_DIR)
        self.assertIn("Python", env.languages)

        # Bandit and Semgrep should find 0 critical/high issues on the safe fixture
        high_sev_findings = [f for f in findings if f.severity == "Urgent" or "SQLI" in f.rule or "CMD_INJECTION" in f.rule]
        self.assertEqual(len(high_sev_findings), 0,
                         f"Safe fixture should have 0 SQLi or Command Injection findings, got: {[f.title for f in high_sev_findings]}")

    def test_07_secret_redaction(self):
        """Test secret redaction prevents AWS keys, GitHub tokens, and passwords from leaking."""
        secret_sample = 'aws_key = "AKIA1234567890ABCDEF"; token = "ghp_123456789012345678901234567890123456"; Bearer eyJhbGciOiJIUzI1Ni...'
        redacted = redact_secrets(secret_sample)
        self.assertNotIn("AKIA1234567890ABCDEF", redacted)
        self.assertIn("[REDACTED_AWS_KEY]", redacted)
        self.assertNotIn("ghp_123456789012345678901234567890123456", redacted)
        self.assertIn("[REDACTED_GITHUB_TOKEN]", redacted)

    def test_08_path_traversal_zip_slip_protection(self):
        """Test path traversal protection rejects escaping paths."""
        base = Path("C:/project/working")
        safe_child = Path("C:/project/working/app/sub.py")
        evil_child = Path("C:/project/working/../../Windows/System32/evil.bat")

        self.assertTrue(is_safe_path(base, safe_child))
        self.assertFalse(is_safe_path(base, evil_child))

if __name__ == "__main__":
    unittest.main()
