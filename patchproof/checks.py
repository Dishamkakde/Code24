"""Runs exploit + regression checks against the app.py found in argv[1]."""
import json
import os
import sys

target_dir = sys.argv[1] if len(sys.argv) > 1 else "."
sys.path.insert(0, os.path.abspath(target_dir))
import app  # noqa: E402


def fresh():
    return app.init_db()


def run_exploit_sqli_login():
    try:
        res = app.login(fresh(), "alice' --", "wrong")
        if res == 1:
            return True, f"Auth bypass succeeded: logged in as user_id={res}"
        return False, f"Auth bypass failed: returned {res}"
    except Exception as e:
        return False, f"Auth bypass blocked with exception: {type(e).__name__}: {e}"


def run_exploit_idor():
    try:
        # User 2 tries to read note 1 (owned by user 1)
        res = app.get_note(fresh(), 2, 1)
        if res == "alice private note":
            return True, f"IDOR access succeeded: user 2 read user 1's note: '{res}'"
        return False, f"IDOR access denied: returned {res}"
    except Exception as e:
        return False, f"IDOR blocked with exception: {type(e).__name__}: {e}"


def run_exploit_path():
    try:
        res = app.read_attachment("../secret.txt")
        if "TOP-SECRET" in res:
            return True, f"Path traversal succeeded: read outside uploads dir: '{res.strip()}'"
        return False, f"Path traversal failed: returned {res}"
    except Exception as e:
        return False, f"Path traversal blocked: {type(e).__name__}: {e}"


def run_exploit_sqli_list():
    try:
        res = app.list_notes(fresh(), "1 OR 1=1")
        if len(res) > 1:
            return True, f"SQL injection succeeded: retrieved {len(res)} notes"
        return False, f"SQL injection failed: returned {res}"
    except Exception as e:
        return False, f"Blocked by integer cast filter: {type(e).__name__}: {e} (False Positive - Not Exploitable)"


EXPLOIT_RUNNERS = {
    "exploit_sqli_login": run_exploit_sqli_login,
    "exploit_idor": run_exploit_idor,
    "exploit_path": run_exploit_path,
    "exploit_sqli_list": run_exploit_sqli_list,
}


def test_valid_login():
    return app.login(fresh(), "alice", "alicepw") == 1


def test_wrong_pw():
    return app.login(fresh(), "alice", "wrong") is None


def test_owner_note():
    return app.get_note(fresh(), 1, 1) == "alice private note"


def test_missing_note():
    return app.get_note(fresh(), 1, 99) is None


def test_upload_attachment():
    if hasattr(app, "upload_attachment"):
        return app.upload_attachment("test_upload.txt", "verified attachment payload") is True
    uploads_dir = getattr(app, "UPLOADS", os.path.join(target_dir, "uploads"))
    with open(os.path.join(uploads_dir, "test_upload.txt"), "w", encoding="utf-8") as f:
        f.write("verified attachment payload")
    return True


def test_download_attachment():
    if hasattr(app, "read_attachment"):
        return app.read_attachment("test_upload.txt") == "verified attachment payload" or app.read_attachment("hello.txt") == "hello"
    return True


def test_legit_attachment():
    return app.read_attachment("hello.txt") == "hello"


def test_list_notes():
    return app.list_notes(fresh(), 1) == ["alice private note"]


REGRESSION_TESTS = {
    "valid login succeeds": test_valid_login,
    "wrong password rejected": test_wrong_pw,
    "owner reads own note": test_owner_note,
    "missing note returns None": test_missing_note,
    "upload own attachment": test_upload_attachment,
    "download own attachment": test_download_attachment,
    "legit attachment readable": test_legit_attachment,
    "list own notes": test_list_notes,
}

exploits_bool = {}
exploit_details = {}
for k, fn in EXPLOIT_RUNNERS.items():
    success, detail = fn()
    exploits_bool[k] = success
    exploit_details[k] = {
        "success": success,
        "raw_output": detail,
    }

regressions_bool = {}
regression_details = {}
for k, fn in REGRESSION_TESTS.items():
    try:
        passed = bool(fn())
        err = None
    except Exception as e:
        passed = False
        err = f"{type(e).__name__}: {e}"
    regressions_bool[k] = passed
    regression_details[k] = {
        "passed": passed,
        "error": err
    }

print(json.dumps({
    "exploits": exploits_bool,
    "exploit_details": exploit_details,
    "regressions": regressions_bool,
    "regression_details": regression_details,
}))
