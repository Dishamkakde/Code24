import io
import requests
import zipfile

BASE = "http://127.0.0.1:8000/api"

def run_diagnostics():
    print("=== PATCHPROOF AUDIT DIAGNOSTIC RUN ===")

    # 1. Health
    h = requests.get(f"{BASE}/health").json()
    print("1. Health Endpoint:", h)

    # 2. Load Demo
    demo = requests.post(f"{BASE}/projects/load-demo").json()
    demo_id = demo["id"]
    print("2. Load Demo Project:", demo_id, demo["name"])

    # 3. Scan Demo
    scan_demo = requests.post(f"{BASE}/scan/{demo_id}").json()
    print("3. Scan Demo Summary:", scan_demo["summary"])

    # 4. Apply Patch Demo PP-01
    patch_demo = requests.post(
        f"{BASE}/patch/apply",
        json={"project_id": demo_id, "finding_id": "PP-01", "confirm_isolated_copy": True}
    ).json()
    print("4. Apply Patch Demo PP-01:", patch_demo["success"], patch_demo["message"])

    # 5. Verify Patch Demo PP-01
    verify_demo = requests.post(f"{BASE}/verify/{demo_id}/PP-01").json()
    print("5. Verify Patch Demo PP-01 Status:", verify_demo["status"])

    # 6. Upload Custom Project ZIP (Non-demo Python code)
    buf = io.BytesIO()
    custom_code = (
        'import sqlite3\n\n'
        'def search_items(query):\n'
        '    conn = sqlite3.connect("data.db")\n'
        '    return conn.execute(f"SELECT * FROM inventory WHERE name = \'{query}\'")\n'
    )
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("search.py", custom_code)
    buf.seek(0)

    up_resp = requests.post(
        f"{BASE}/projects/upload-zip",
        files={"file": ("custom_project.zip", buf, "application/zip")}
    )
    print("6. Upload Custom ZIP Status:", up_resp.status_code)
    up_proj = up_resp.json()
    up_id = up_proj["id"]
    print("   Project ID:", up_id, "Languages:", up_proj.get("languages"))

    # 7. Scan Custom Project
    scan_up_resp = requests.post(f"{BASE}/scan/{up_id}")
    print("7. Scan Custom Project Status:", scan_up_resp.status_code)
    scan_up = scan_up_resp.json()
    print("   Summary:", scan_up["summary"])
    print("   Findings count:", len(scan_up["findings"]))
    for f in scan_up["findings"]:
        print(f"   -> Finding: {f['id']} Rule: {f['rule']} in {f['file']}:{f['line']}")
        print(f"      'where' field: {f['five_sections']['where']}")
        print(f"      'proof' field: {f['five_sections']['proof']}")
        print(f"      'patch_original': {f.get('patch_original')}")
        print(f"      'patch_corrected': {f.get('patch_corrected')}")

    # 8. Apply Patch to Custom Project
    if scan_up["findings"]:
        f_id = scan_up["findings"][0]["id"]
        patch_up_resp = requests.post(
            f"{BASE}/patch/apply",
            json={"project_id": up_id, "finding_id": f_id, "confirm_isolated_copy": True}
        )
        print("8. Apply Patch to Custom Project Status:", patch_up_resp.status_code)
        print("   Response:", patch_up_resp.text[:200])

        # 9. Verify Patch for Custom Project
        verify_up_resp = requests.post(f"{BASE}/verify/{up_id}/{f_id}")
        print("9. Verify Patch Custom Project Status:", verify_up_resp.status_code)
        print("   Response:", verify_up_resp.text[:200])

    # 10. Test Website URL behavior (simulate submitting a URL to github import)
    url_req = requests.post(f"{BASE}/projects/import-github", json={"repo_url": "https://example.com"})
    print("10. Submit Website URL Status to GitHub import:", url_req.status_code)
    print("    Detail:", url_req.json().get("detail"))

    # 11. Test Live Website Security Inspection (/api/projects/scan-url)
    url_scan_resp = requests.post(f"{BASE}/projects/scan-url", json={"url": "https://example.com"})
    print("11. Live Website Scan Status:", url_scan_resp.status_code)
    if url_scan_resp.status_code == 200:
        url_proj = url_scan_resp.json()
        print("    Project ID:", url_proj["id"], url_proj["name"])
        scan_url_res = requests.post(f"{BASE}/scan/{url_proj['id']}").json()
        print("    Findings count on example.com:", len(scan_url_res["findings"]))
        for f in scan_url_res["findings"]:
            print(f"    -> {f['id']} {f['rule']} CVSS:{f['cvss']} Title: {f['title']}")

if __name__ == "__main__":
    run_diagnostics()
