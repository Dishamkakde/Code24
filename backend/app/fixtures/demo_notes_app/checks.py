"""Runs exploit + regression checks against the app.py found in argv[1]."""
import json
import sys

sys.path.insert(0, sys.argv[1])
import app  # noqa: E402


def fresh():
    return app.init_db()


EXPLOITS = {
    "exploit_sqli_login": lambda: app.login(fresh(), "alice' --", "wrong") == 1,
    "exploit_idor": lambda: app.get_note(fresh(), 2, 1) == "alice private note",
    "exploit_path": lambda: "TOP-SECRET" in app.read_attachment("../secret.txt"),
    "exploit_sqli_list": lambda: len(app.list_notes(fresh(), "1 OR 1=1")) > 1,
}

REGRESSIONS = {
    "valid login succeeds": lambda: app.login(fresh(), "alice", "alicepw") == 1,
    "wrong password rejected": lambda: app.login(fresh(), "alice", "nope") is None,
    "owner reads own note": lambda: app.get_note(fresh(), 1, 1) == "alice private note",
    "missing note returns None": lambda: app.get_note(fresh(), 1, 99) is None,
    "list own notes": lambda: app.list_notes(fresh(), 1) == ["alice private note"],
    "legit attachment readable": lambda: app.read_attachment("hello.txt") == "hello",
}


def safe(fn):
    try:
        return bool(fn())
    except Exception:
        return False


print(json.dumps({
    "exploits": {k: safe(v) for k, v in EXPLOITS.items()},
    "regressions": {k: safe(v) for k, v in REGRESSIONS.items()},
}))
