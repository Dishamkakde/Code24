"""End-to-end acceptance test for DAMage CTRL backend.
Tests:
  1. Scan of demo_app confirms planted vulnerabilities and false positive.
  2. Fix produces unified diff, passes py_compile, and auto-reverts regressions.
  3. Patched demo app starts; normal login and note retrieval work.
  4. Rescan of patched copy shows 0 vulnerabilities, false positive still safe.
  5. FastAPI REST endpoints (POST /api/demo, upload, scan, fix, rescan, download).
"""
import io
import json
import os
import shutil
import sys
import zipfile
from pathlib import Path

# Ensure repo root is on sys.path
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

import engine
import main
from fastapi.testclient import TestClient


def run_acceptance_tests():
    print("=" * 70)
    print("DAMage CTRL - ACCEPTANCE TEST SUITE")
    print("Tagline: 'Find the Flaw. Prove the Fix.'")
    print("=" * 70)

    # -------------------------------------------------------------
    # Step 1: Scan on demo_app
    # -------------------------------------------------------------
    print("\n[STEP 1] Running scan_project('demo_app')...")
    scan_result = engine.scan_project(ROOT / "demo_app")
    counts = scan_result["counts"]
    findings = scan_result["findings"]

    print(f"Total findings observed: {counts['total']}")
    print(f"  - Vulnerabilities: {counts['vuln']}")
    print(f"  - False Positives: {counts['false_positive']}")
    print(f"  - Critical: {counts['critical']}")
    print(f"  - High: {counts['high']}")
    print(f"  - Medium: {counts['medium']}")

    print("\nDetailed Findings:")
    for f in findings:
        status_tag = "[VULN]" if f["status"] == "vuln" else "[SAFE / FP]"
        print(f"  {status_tag} {f['id']} | {f['rule']} ({f['severity']}) on line {f['line']}: {f['snippet']}")

    assert counts["vuln"] == 5, f"Expected 5 vulnerabilities, got {counts['vuln']}"
    assert counts["false_positive"] == 1, f"Expected 1 false positive, got {counts['false_positive']}"
    print("\n>>> STEP 1 PASSED: Exactly 5 vulnerabilities and 1 false positive detected.")

    # -------------------------------------------------------------
    # Step 2: Fix project demo_app -> workspace/test_<id>/patched
    # -------------------------------------------------------------
    import uuid
    test_id = f"test_{uuid.uuid4().hex[:8]}"
    test_workspace = ROOT / "workspace" / test_id
    original_copy = test_workspace / "original"
    patched_copy = test_workspace / "patched"

    original_copy.mkdir(parents=True, exist_ok=True)
    shutil.copytree(ROOT / "demo_app", original_copy, dirs_exist_ok=True)

    print("\n[STEP 2] Running fix_project(original, patched)...")
    fix_result = engine.fix_project(original_copy, patched_copy)

    diff = fix_result["diff"]
    reverted = fix_result["reverted_files"]
    before_c = fix_result["before_counts"]
    after_c = fix_result["after_counts"]

    print("Unified Diff Generated:")
    print("-" * 50)
    print(diff)
    print("-" * 50)
    print(f"Auto-reverted files: {len(reverted)}")
    assert len(reverted) == 0, f"Expected 0 auto-reverted files, got {reverted}"
    assert diff.strip() != "", "Expected non-empty unified diff"
    print(">>> STEP 2 PASSED: Unified diff produced and all patched files compiled cleanly.")

    # -------------------------------------------------------------
    # Step 3: Run patched demo app and test functionality
    # -------------------------------------------------------------
    print("\n[STEP 3] Starting patched demo app and testing normal operations...")
    sys.path.insert(0, str(patched_copy))
    # Reload or import patched app
    import app as patched_app

    flask_client = patched_app.app.test_client()

    # 3a. Normal login
    login_resp = flask_client.post("/login", json={"username": "alice", "password": "password123"})
    print(f"  * Normal login POST /login: HTTP {login_resp.status_code} -> {login_resp.get_json()}")
    assert login_resp.status_code == 200
    assert login_resp.get_json()["username"] == "alice"
    assert login_resp.get_json()["user_id"] == 1

    # 3b. Normal note retrieval (Alice retrieves note 1)
    note_resp = flask_client.get("/notes/1")
    print(f"  * Normal note GET /notes/1: HTTP {note_resp.status_code} -> {note_resp.get_json()}")
    assert note_resp.status_code == 200
    assert note_resp.get_json()["id"] == 1
    assert "Alice Secret" in note_resp.get_json()["title"]

    # 3c. IDOR prevention (Alice tries to read Bob's note 2)
    idor_resp = flask_client.get("/notes/2")
    print(f"  * IDOR attempt GET /notes/2: HTTP {idor_resp.status_code} (access denied as expected)")
    assert idor_resp.status_code == 404

    # 3d. Normal file download
    dl_resp = flask_client.get("/download/sample.txt")
    print(f"  * Normal file download GET /download/sample.txt: HTTP {dl_resp.status_code}")
    assert dl_resp.status_code == 200

    # 3e. Path traversal blocked
    pt_resp = flask_client.get("/download/../server_secret.txt")
    print(f"  * Path traversal attempt GET /download/../server_secret.txt: HTTP {pt_resp.status_code} (blocked)")
    assert pt_resp.status_code == 400

    # 3f. False positive route (int wrapper)
    fp_resp = flask_client.get("/user-notes-count?user_id=1")
    print(f"  * Integer route GET /user-notes-count?user_id=1: HTTP {fp_resp.status_code} -> {fp_resp.get_json()}")
    assert fp_resp.status_code == 200
    print(">>> STEP 3 PASSED: Patched app started and all operations verified.")

    # -------------------------------------------------------------
    # Step 4: Re-scan of patched copy
    # -------------------------------------------------------------
    print("\n[STEP 4] Re-scanning patched copy...")
    rescan_result = engine.scan_project(patched_copy)
    rescan_counts = rescan_result["counts"]
    print(f"Observed counts on patched copy:")
    print(f"  - Vulnerabilities: {rescan_counts['vuln']}")
    print(f"  - False Positives (Safe): {rescan_counts['false_positive']}")
    print(f"  - Total Findings: {rescan_counts['total']}")

    assert rescan_counts["vuln"] == 0, f"Expected 0 vulnerabilities, got {rescan_counts['vuln']}"
    assert rescan_counts["false_positive"] == 1, f"Expected 1 false positive, got {rescan_counts['false_positive']}"
    print(">>> STEP 4 PASSED: Rescan shows exactly 0 vulnerabilities; false positive safely preserved.")

    # -------------------------------------------------------------
    # Step 5: Test FastAPI endpoints
    # -------------------------------------------------------------
    print("\n[STEP 5] Testing FastAPI REST endpoints...")
    client = TestClient(main.app)

    # 5a. POST /api/demo
    r = client.post("/api/demo")
    assert r.status_code == 200
    demo_id = r.json()["project_id"]
    print(f"  * POST /api/demo -> {r.json()}")

    # 5b. POST /api/{id}/scan
    r = client.post(f"/api/{demo_id}/scan")
    assert r.status_code == 200
    demo_scan = r.json()
    assert demo_scan["counts"]["vuln"] == 5
    assert demo_scan["counts"]["false_positive"] == 1
    print(f"  * POST /api/{demo_id}/scan -> {demo_scan['counts']}")

    # 5c. POST /api/{id}/fix
    r = client.post(f"/api/{demo_id}/fix")
    assert r.status_code == 200
    demo_fix = r.json()
    assert demo_fix["after_counts"]["vuln"] == 0
    assert demo_fix["after_counts"]["false_positive"] == 1
    print(f"  * POST /api/{demo_id}/fix -> after_counts: {demo_fix['after_counts']}")

    # 5d. POST /api/{id}/rescan
    r = client.post(f"/api/{demo_id}/rescan")
    assert r.status_code == 200
    assert r.json()["counts"]["vuln"] == 0
    print(f"  * POST /api/{demo_id}/rescan -> counts: {r.json()['counts']}")

    # 5e. GET /api/{id}/download
    r = client.get(f"/api/{demo_id}/download")
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/zip"
    zf = zipfile.ZipFile(io.BytesIO(r.content))
    assert "app.py" in zf.namelist()
    print(f"  * GET /api/{demo_id}/download -> valid ZIP with files: {zf.namelist()}")

    # 5f. POST /api/upload - Valid ZIP upload
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w") as z:
        z.writestr("app.py", "import os\nprint('hello')\n")
    zip_buf.seek(0)
    r = client.post("/api/upload", files={"file": ("project.zip", zip_buf, "application/zip")})
    assert r.status_code == 200
    upload_id = r.json()["project_id"]
    print(f"  * POST /api/upload (valid ZIP) -> project_id: {upload_id}")

    # 5g. POST /api/upload - Zip-slip protection test
    slip_buf = io.BytesIO()
    with zipfile.ZipFile(slip_buf, "w") as z:
        z.writestr("../evil.py", "malicious code")
    slip_buf.seek(0)
    r = client.post("/api/upload", files={"file": ("slip.zip", slip_buf, "application/zip")})
    print(f"  * POST /api/upload (zip-slip attempt): HTTP {r.status_code} ({r.json().get('detail')})")
    assert r.status_code == 400

    # 5h. POST /api/upload - Invalid ZIP test
    r = client.post("/api/upload", files={"file": ("fake.zip", io.BytesIO(b"not a zip file"), "application/zip")})
    print(f"  * POST /api/upload (invalid ZIP): HTTP {r.status_code} ({r.json().get('detail')})")
    assert r.status_code == 400

    # 5i. Project ID validation test (prevent traversal in id)
    r = client.post("/api/..%2F..%2Fetc/scan")
    assert r.status_code in (400, 404)
    print("  * Invalid project_id traversal test properly rejected.")

    # 5j. GET / serves static UI
    r = client.get("/")
    assert r.status_code == 200
    assert "DAMage CTRL" in r.text
    print("  * GET / serves static index.html UI.")

    print("\n>>> STEP 5 PASSED: All FastAPI endpoints verified.")

    print("\n" + "=" * 70)
    print("ALL ACCEPTANCE CHECKS PASSED PERFECTLY!")
    print("SUMMARY OF OBSERVED COUNTS:")
    print("  - Initial scan on demo_app: 5 Vulnerabilities, 1 False Positive")
    print("  - Post-fix rescan on patched copy: 0 Vulnerabilities, 1 False Positive")
    print("=" * 70)


if __name__ == "__main__":
    run_acceptance_tests()
