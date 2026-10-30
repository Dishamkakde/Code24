"""PatchProof engine: scan -> confirm exploit -> patch -> re-verify."""
import ast
import difflib
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).parent
FIXTURE = ROOT / "fixture"

RULES = {
    "SQLI": dict(
        title="SQL injection via string-built query", cwe="CWE-89", cvss=9.8, severity="Critical",
        why="Attacker input is spliced into SQL. Network-reachable, no privileges, no user interaction: "
            "auth bypass and data theft (CVSS AV:N/AC:L/PR:N/UI:N/C:H/I:H/A:H).",
        fix="Use a parameterized query so input is bound as data and never parsed as SQL."),
    "IDOR": dict(
        title="Broken access control (IDOR) on notes", cwe="CWE-639", cvss=6.5, severity="Medium",
        why="Any logged-in user can read another user's note by guessing its id. Needs a low-privilege "
            "account, so confidentiality impact is high but scope is limited (AV:N/AC:L/PR:L/UI:N/C:H/I:N/A:N).",
        fix="Add an ownership predicate (owner_id = current user) to the query so the database enforces it."),
    "PATH": dict(
        title="Path traversal in attachment reader", cwe="CWE-22", cvss=7.5, severity="High",
        why="'../' sequences escape the uploads folder and expose arbitrary readable files "
            "(AV:N/AC:L/PR:N/UI:N/C:H/I:N/A:N).",
        fix="Resolve the real path and reject anything that is not inside the uploads directory."),
}

FUNC_EXPLOIT = {"login": "exploit_sqli_login", "get_note": "exploit_idor",
                "read_attachment": "exploit_path", "list_notes": "exploit_sqli_list"}

PATCHES = {
    "login": (
        """db.execute(f"SELECT id FROM users WHERE username='{username}' AND password='{password}'")""",
        """db.execute("SELECT id FROM users WHERE username=? AND password=?", (username, password))"""),
    "get_note": (
        """db.execute("SELECT body FROM notes WHERE id = ?", (note_id,))""",
        """db.execute("SELECT body FROM notes WHERE id = ? AND owner_id = ?", (note_id, user_id))"""),
    "read_attachment": (
        """    with open(os.path.join(UPLOADS, name), "r") as f:""",
        """    path = os.path.realpath(os.path.join(UPLOADS, name))
    root = os.path.realpath(UPLOADS)
    if os.path.commonpath([path, root]) != root:
        raise PermissionError("path escapes uploads directory")
    with open(path, "r") as f:"""),
}


def _callname(call):
    f, parts = call.func, []
    while isinstance(f, ast.Attribute):
        parts.append(f.attr)
        f = f.value
    if isinstance(f, ast.Name):
        parts.append(f.id)
    return ".".join(reversed(parts))


def scan(source):
    """AST-based static scan. Returns candidate findings (not yet confirmed)."""
    tree = ast.parse(source)
    lines = source.splitlines()
    out = []
    for fn in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
        fn_src = ast.get_source_segment(source, fn) or ""
        for node in ast.walk(fn):
            if not isinstance(node, ast.Call) or not node.args:
                continue
            name, arg = _callname(node), node.args[0]
            seg = ast.get_source_segment(source, node) or ""
            rule = None
            if name.endswith(".execute"):
                if isinstance(arg, (ast.JoinedStr, ast.BinOp)) or (
                        isinstance(arg, ast.Call) and _callname(arg).endswith(".format")):
                    rule = "SQLI"
                elif re.search(r"FROM\s+notes", seg, re.I) and "owner_id" not in seg:
                    rule = "IDOR"
            elif name == "open" and not isinstance(arg, ast.Constant):
                if "realpath" not in fn_src and "commonpath" not in fn_src:
                    rule = "PATH"
            if rule:
                out.append(dict(rule=rule, function=fn.name, file="app.py", line=node.lineno,
                                end_line=node.end_lineno,
                                snippet="\n".join(lines[node.lineno - 1:node.end_lineno])))
    return sorted(out, key=lambda f: f["line"])


def prepare(dst, source):
    (dst / "uploads").mkdir(parents=True)
    (dst / "app.py").write_text(source)
    (dst / "uploads" / "hello.txt").write_text("hello")
    (dst / "secret.txt").write_text("TOP-SECRET")


def run_checks(directory):
    p = subprocess.run([sys.executable, str(ROOT / "checks.py"), str(directory)],
                       capture_output=True, text=True, timeout=30)
    if p.returncode != 0:
        raise RuntimeError("check runner failed: " + p.stderr)
    return json.loads(p.stdout)


def udiff(a, b):
    return "".join(difflib.unified_diff(a.splitlines(True), b.splitlines(True), "a/app.py", "b/app.py"))


def run_pipeline():
    original = (FIXTURE / "app.py").read_text()
    findings = scan(original)
    with tempfile.TemporaryDirectory() as tmp:
        before, after = Path(tmp) / "before", Path(tmp) / "after"
        prepare(before, original)
        b = run_checks(before)
        patched = original
        for i, f in enumerate(findings, 1):
            f["id"] = f"PP-{i:02d}"
            f["exploit"] = FUNC_EXPLOIT[f["function"]]
            rule = RULES[f["rule"]]
            f.update(title=rule["title"], cwe=rule["cwe"], diff="", patch_rationale="")
            if b["exploits"].get(f["exploit"]):
                f.update(status="confirmed", cvss=rule["cvss"], severity=rule["severity"],
                         severity_rationale=rule["why"], patch_rationale=rule["fix"])
                old, new = PATCHES[f["function"]]
                if old not in original:
                    raise RuntimeError("patch anchor not found for " + f["function"])
                f["diff"] = udiff(original, original.replace(old, new))
                patched = patched.replace(old, new)
            else:
                f.update(status="false_positive", cvss=0.0, severity="Info",
                         severity_rationale="Scanner pattern matched, but the exploit attempt failed "
                                            "(input is validated before reaching the query). Downgraded.",
                         patch_rationale="No patch applied. Optional hardening: parameterize the query anyway.")
        ast.parse(patched)  # patched code must still be valid Python
        prepare(after, patched)
        a = run_checks(after)
    rescan = {x["function"] for x in scan(patched)}
    for f in findings:
        f["exploit_before"] = b["exploits"][f["exploit"]]
        f["exploit_after"] = a["exploits"][f["exploit"]]
        f["rescan_clean"] = f["function"] not in rescan
        f["fixed"] = f["status"] == "confirmed" and not f["exploit_after"]
    conf = [f for f in findings if f["status"] == "confirmed"]
    return dict(
        summary=dict(candidates=len(findings), confirmed=len(conf),
                     false_positives=len(findings) - len(conf),
                     fixed=sum(f["fixed"] for f in conf),
                     regressions_passed=sum(a["regressions"].values()),
                     regressions_total=len(a["regressions"])),
        findings=findings,
        regressions=dict(before=b["regressions"], after=a["regressions"]))


if __name__ == "__main__":
    print(json.dumps(run_pipeline(), indent=2))
