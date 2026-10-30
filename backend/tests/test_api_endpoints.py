import unittest
import requests

BASE_URL = "http://127.0.0.1:8000"

class PatchProofLiveApiTests(unittest.TestCase):
    def test_01_health_check(self):
        r = requests.get(f"{BASE_URL}/api/health")
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data["status"], "healthy")
        self.assertEqual(data["service"], "PatchProof API")

    def test_02_frontend_index_and_assets(self):
        r = requests.get(f"{BASE_URL}/")
        self.assertEqual(r.status_code, 200)
        self.assertIn("PATCHPROOF", r.text)

    def test_03_learn_concepts(self):
        r = requests.get(f"{BASE_URL}/api/learn")
        self.assertEqual(r.status_code, 200)
        concepts = r.json()
        self.assertGreaterEqual(len(concepts), 3)
        self.assertTrue(any(c["id"] == "sql-injection" for c in concepts))
        self.assertTrue(any(c["id"] == "idor" for c in concepts))
        self.assertTrue(any(c["id"] == "path-traversal" for c in concepts))

    def test_04_demo_lifecycle_and_verification(self):
        # 1. Load demo project
        load_res = requests.post(f"{BASE_URL}/api/projects/load-demo")
        self.assertEqual(load_res.status_code, 200)
        project = load_res.json()
        project_id = project["id"]
        self.assertTrue(project_id.startswith("demo-"))
        self.assertIn("Python", project["languages"])

        # 2. Run scan
        scan_res = requests.post(f"{BASE_URL}/api/scan/{project_id}")
        self.assertEqual(scan_res.status_code, 200)
        scan_data = scan_res.json()
        summary = scan_data["summary"]
        self.assertEqual(summary["candidates"], 4)
        self.assertEqual(summary["confirmed"], 3)
        self.assertEqual(summary["false_positives"], 1)

        # 3. Check findings structure
        findings = scan_data["findings"]
        self.assertEqual(len(findings), 4)
        
        sqli = next(f for f in findings if f["rule"] == "SQLI" and f["function"] == "login")
        self.assertEqual(sqli["status"], "confirmed")
        self.assertEqual(sqli["severity"], "Urgent")
        self.assertTrue(sqli["exploit_before"])
        self.assertIn("analogy_title", sqli["eli12"])

        # 4. Verify false positive
        safe_sqli = next(f for f in findings if f["rule"] == "SQLI" and f["function"] == "list_notes")
        self.assertEqual(safe_sqli["status"], "false_positive")
        self.assertFalse(safe_sqli["exploit_before"])

        # 5. Apply patch to isolated working copy
        patch_res = requests.post(f"{BASE_URL}/api/patch/apply", json={
            "project_id": project_id,
            "finding_id": sqli["id"],
            "confirm_isolated_copy": True
        })
        self.assertEqual(patch_res.status_code, 200)
        patch_data = patch_res.json()
        self.assertTrue(patch_data["success"])
        self.assertTrue(patch_data["applied_to_working_copy"])

        # 6. Verify patch with deterministic proof
        verify_res = requests.post(f"{BASE_URL}/api/verify/{project_id}/{sqli['id']}")
        self.assertEqual(verify_res.status_code, 200)
        ver_data = verify_res.json()
        self.assertEqual(ver_data["status"], "fixed_verified")
        self.assertTrue(ver_data["exploit_before"])
        self.assertFalse(ver_data["exploit_after"])
        self.assertTrue(ver_data["all_regressions_passed"])

        # 7. Check reports
        report_res = requests.get(f"{BASE_URL}/api/reports/{project_id}")
        self.assertEqual(report_res.status_code, 200)
        report_data = report_res.json()
        self.assertIn("executive_summary", report_data)
        self.assertEqual(report_data["executive_summary"]["fixes_verified"], 1)

        # 8. Check printable HTML report
        report_html_res = requests.get(f"{BASE_URL}/api/reports/{project_id}/html")
        self.assertEqual(report_html_res.status_code, 200)
        self.assertIn("Security Audit & Verification Report", report_html_res.text)

if __name__ == "__main__":
    unittest.main()
