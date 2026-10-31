#!/usr/bin/env python3
"""Functional regression test runner for DAMage CTRL.
Ensures that all legitimate application features work on the PATCHED demo app:
  1. Home route responds (GET /)
  2. Login works for a valid user (POST /login)
  3. User can read their own note (GET /notes/1)
  4. Download of a legitimate file works (GET /download/sample.txt)
All must pass.
"""
import os
import sys
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def run_regression_suite(target_dir=None):
    import engine

    if target_dir is None:
        if len(sys.argv) > 1:
            target_dir = sys.argv[1]
        else:
            # Prepare a patched demo app copy if not specified
            target_dir = str(ROOT / "workspace" / "regression_demo_patched")
            os.makedirs(target_dir, exist_ok=True)
            engine.fix_project(ROOT / "demo_app", target_dir)

    target_path = Path(target_dir).resolve()
    if not target_path.exists():
        raise RuntimeError(f"Target directory {target_path} does not exist")

    # Import target app
    sys.path.insert(0, str(target_path))
    if "app" in sys.modules:
        del sys.modules["app"]
    import app

    client = app.app.test_client()
    tests = []

    # 1. Home route responds
    try:
        r = client.get("/")
        passed = (r.status_code == 200)
        detail = f"HTTP {r.status_code} ({r.get_json() if r.is_json else 'OK'})"
        tests.append({"name": "Home route responds (GET /)", "passed": passed, "detail": detail})
    except Exception as e:
        tests.append({"name": "Home route responds (GET /)", "passed": False, "detail": f"Error: {e}"})

    # 2. Login works for a valid user
    try:
        r = client.post("/login", json={"username": "alice", "password": "password123"})
        passed = (r.status_code == 200 and r.get_json().get("username") == "alice")
        detail = f"HTTP {r.status_code} (User logged in as {r.get_json().get('username')})"
        tests.append({"name": "Valid user login (POST /login)", "passed": passed, "detail": detail})
    except Exception as e:
        tests.append({"name": "Valid user login (POST /login)", "passed": False, "detail": f"Error: {e}"})

    # 3. User can read their own note
    try:
        # Alice is logged in (session has user_id = 1)
        r = client.get("/notes/1")
        passed = (r.status_code == 200 and r.get_json().get("id") == 1)
        detail = f"HTTP {r.status_code} (Retrieved note: '{r.get_json().get('title')}')"
        tests.append({"name": "Owner reads own note (GET /notes/1)", "passed": passed, "detail": detail})
    except Exception as e:
        tests.append({"name": "Owner reads own note (GET /notes/1)", "passed": False, "detail": f"Error: {e}"})

    # 4. Download of legitimate file works
    try:
        r = client.get("/download/sample.txt")
        passed = (r.status_code == 200 and len(r.data) > 0)
        detail = f"HTTP {r.status_code} (Successfully downloaded {len(r.data)} bytes)"
        tests.append({"name": "Download legitimate file (GET /download/sample.txt)", "passed": passed, "detail": detail})
    except Exception as e:
        tests.append({"name": "Download legitimate file (GET /download/sample.txt)", "passed": False, "detail": f"Error: {e}"})

    all_passed = all(t["passed"] for t in tests)
    passed_count = sum(1 for t in tests if t["passed"])

    print("=" * 70)
    print(f"[*] Running Functional Regression Suite against: {target_path}")
    print("=" * 70)
    for t in tests:
        status_tag = "[PASS]" if t["passed"] else "[FAIL]"
        print(f"  {status_tag} {t['name']}: {t['detail']}")
    print("-" * 70)
    print(f"[*] Regression Suite Summary: {passed_count}/{len(tests)} tests passed")
    if all_passed:
        print("[+] ALL REGRESSION TESTS PASSED (100% Feature Integrity Verified)")
    else:
        print("[-] REGRESSION FAILURE DETECTED")
    print("=" * 70)

    return {
        "total": len(tests),
        "passed": passed_count,
        "all_passed": all_passed,
        "tests": tests
    }


if __name__ == "__main__":
    res = run_regression_suite()
    sys.exit(0 if res["all_passed"] else 1)
