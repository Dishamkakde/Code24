import os
import sys
import json
import time
import shutil
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from app.models.schemas import (
    Finding,
    ScannerExecutionRecord,
    ProjectEnvironment,
    ELI12Content,
    FiveSections,
    EvidenceBasedClassification
)
from app.services.zip_service import redact_secrets
from app.services.scanner_service import calculate_cvss31, generate_contextual_patch, RULE_METADATA
from app.services.patch_service import create_unified_diff
from app.services.classification_service import classify_finding

# Scanner binaries and paths
PYTHON_EXE = sys.executable
SCRIPTS_DIR = Path(PYTHON_EXE).parent / "Scripts"
SEMGREP_CORE_CANDIDATES = [
    Path(PYTHON_EXE).parent / "Lib" / "site-packages" / "semgrep" / "bin" / "semgrep-core.exe",
    Path(PYTHON_EXE).parent / "Lib" / "site-packages" / "semgrep" / "bin" / "semgrep-core",
    SCRIPTS_DIR / "semgrep-core.exe",
    SCRIPTS_DIR / "semgrep-core"
]

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"
PYTHON_RULES_FILE = RULES_DIR / "python_security.yaml"
JS_RULES_FILE = RULES_DIR / "javascript_security.yaml"

def get_semgrep_core_executable() -> Optional[Path]:
    for cand in SEMGREP_CORE_CANDIDATES:
        if cand.exists():
            return cand
    which_core = shutil.which("semgrep-core")
    return Path(which_core) if which_core else None

SEMGREP_CLI_CANDIDATES = [
    SCRIPTS_DIR / "semgrep.exe",
    SCRIPTS_DIR / "semgrep",
    Path(PYTHON_EXE).parent / "bin" / "semgrep",
]

def get_semgrep_cli_executable() -> Optional[Path]:
    for cand in SEMGREP_CLI_CANDIDATES:
        if cand.exists():
            return cand
    which_cli = shutil.which("semgrep")
    return Path(which_cli) if which_cli else None

def get_installed_version(package_name: str) -> Optional[str]:
    try:
        import importlib.metadata
        return importlib.metadata.version(package_name)
    except Exception:
        return None

def identify_project_environment(project_dir: Path) -> ProjectEnvironment:
    """
    Inspects project directory to detect programming languages, frameworks,
    dependency manifests, and applicable security scanners.
    """
    languages_set = set()
    frameworks_set = set()
    manifests_list = []
    total_files = 0
    total_lines = 0

    manifest_names = {
        "requirements.txt", "Pipfile", "pyproject.toml", "setup.py",
        "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
        "go.mod", "go.sum", "Gemfile", "pom.xml", "build.gradle"
    }

    for root, dirs, files in os.walk(project_dir):
        if "node_modules" in root or ".git" in root or "__pycache__" in root:
            continue
        for f in files:
            total_files += 1
            f_path = Path(root) / f
            ext = f_path.suffix.lower()

            if f in manifest_names:
                rel_m = str(f_path.relative_to(project_dir)).replace("\\", "/")
                manifests_list.append(rel_m)

            # Language detection
            if ext == ".py":
                languages_set.add("Python")
            elif ext in {".js", ".jsx", ".mjs", ".cjs"}:
                languages_set.add("JavaScript")
            elif ext in {".ts", ".tsx"}:
                languages_set.add("TypeScript")
            elif ext == ".go":
                languages_set.add("Go")
            elif ext in {".html", ".htm"}:
                languages_set.add("HTML")
            elif ext in {".css", ".scss"}:
                languages_set.add("CSS")
            elif ext == ".php":
                languages_set.add("PHP")
            elif ext == ".rb":
                languages_set.add("Ruby")
            elif ext == ".java":
                languages_set.add("Java")

            # Simple line counting
            try:
                if ext in {".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".html", ".css", ".json", ".yaml", ".yml", ".md"}:
                    with open(f_path, "r", encoding="utf-8", errors="ignore") as fp:
                        total_lines += sum(1 for _ in fp)
            except Exception:
                pass

    # Framework detection
    py_files = list(project_dir.glob("**/*.py"))
    for pf in py_files[:15]:
        try:
            content = pf.read_text(encoding="utf-8", errors="ignore")
            if "fastapi" in content.lower():
                frameworks_set.add("FastAPI")
            if "flask" in content.lower():
                frameworks_set.add("Flask")
            if "django" in content.lower():
                frameworks_set.add("Django")
            if "tornado" in content.lower():
                frameworks_set.add("Tornado")
        except Exception:
            pass

    pkg_json = project_dir / "package.json"
    if pkg_json.exists():
        try:
            pj = json.loads(pkg_json.read_text(encoding="utf-8", errors="ignore"))
            deps = {**pj.get("dependencies", {}), **pj.get("devDependencies", {})}
            if "react" in deps:
                frameworks_set.add("React")
            if "express" in deps:
                frameworks_set.add("Express")
            if "next" in deps:
                frameworks_set.add("Next.js")
            if "vue" in deps:
                frameworks_set.add("Vue")
        except Exception:
            pass

    applicable_scanners = []
    if "Python" in languages_set:
        applicable_scanners.append("bandit")
        applicable_scanners.append("semgrep")
    if any("requirements" in m or "pyproject" in m for m in manifests_list):
        applicable_scanners.append("pip-audit")
    if "JavaScript" in languages_set or "TypeScript" in languages_set:
        if "semgrep" not in applicable_scanners:
            applicable_scanners.append("semgrep")
    if any("package.json" in m for m in manifests_list):
        applicable_scanners.append("npm-audit")
    if "Go" in languages_set and "semgrep" not in applicable_scanners:
        applicable_scanners.append("semgrep")

    return ProjectEnvironment(
        languages=sorted(list(languages_set)),
        frameworks=sorted(list(frameworks_set)),
        manifests=sorted(manifests_list),
        applicable_scanners=sorted(applicable_scanners),
        total_files=total_files,
        total_lines=total_lines
    )

def read_source_snippet(file_path: Path, start_line: int, end_line: int, padding: int = 1) -> Tuple[str, str]:
    """Reads the exact source snippet and discovers surrounding function name."""
    if not file_path.exists():
        return "", "unknown"
    try:
        lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        total = len(lines)
        s = max(1, start_line - padding)
        e = min(total, max(end_line, start_line) + padding)
        snippet_lines = lines[s - 1:e]
        snippet = "\n".join(snippet_lines)

        # Detect function name by scanning backwards
        func_name = "app_logic"
        for i in range(min(start_line - 1, total - 1), -1, -1):
            line_str = lines[i].strip()
            if line_str.startswith("def ") or line_str.startswith("async def "):
                parts = line_str.split("(")
                if len(parts) > 0:
                    func_name = parts[0].replace("async def ", "").replace("def ", "").strip()
                break
            elif line_str.startswith("function ") or " = function" in line_str or " => " in line_str:
                func_name = line_str.split("(")[0].replace("function", "").replace("export", "").strip() or "anonymous"
                break
        return snippet, func_name
    except Exception:
        return "", "unknown"

# -------------------------------------------------------------
# 1. BANDIT SCANNER RUNNER
# -------------------------------------------------------------
def run_bandit_scanner(project_dir: Path) -> Tuple[ScannerExecutionRecord, List[Finding]]:
    t0 = time.time()
    version = get_installed_version("bandit") or "1.9.4"
    cmd = [PYTHON_EXE, "-m", "bandit", "-r", str(project_dir), "-f", "json", "--exit-zero"]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        dur = round(time.time() - t0, 3)
        stdout = proc.stdout.strip()
        
        # Parse JSON output
        if "{" not in stdout:
            return ScannerExecutionRecord(
                scanner_name="bandit",
                scanner_version=version,
                status="failed",
                exit_code=proc.returncode,
                duration_seconds=dur,
                command=cmd,
                raw_stdout=stdout,
                raw_stderr=proc.stderr,
                error_message=f"Bandit returned non-JSON output: {proc.stderr[:300]}",
                findings_count=0
            ), []

        raw_json = stdout[stdout.find("{"):stdout.rfind("}") + 1]
        data = json.loads(raw_json)
        results = data.get("results", [])

        findings: List[Finding] = []
        for idx, item in enumerate(results, 1):
            filename_str = item.get("filename", "")
            try:
                rel_path = str(Path(filename_str).resolve().relative_to(project_dir.resolve())).replace("\\", "/")
            except Exception:
                rel_path = filename_str.replace("\\", "/")

            start_l = int(item.get("line_number", 1))
            line_range = item.get("line_range", [start_l])
            end_l = int(line_range[-1]) if line_range else start_l

            raw_code = item.get("code", "")
            source_evidence = redact_secrets(raw_code.strip())

            # Read full snippet and function from disk
            snippet, func_name = read_source_snippet(project_dir / rel_path, start_l, end_l)
            if not snippet:
                snippet = source_evidence

            b_sev = item.get("issue_severity", "MEDIUM").upper()
            if b_sev == "HIGH":
                sev_label = "Urgent"
                sev_level = 3
                cvss_score = calculate_cvss31("N", "L", "N", "N", "U", "H", "H", "H")
            elif b_sev == "MEDIUM":
                sev_label = "Important"
                sev_level = 2
                cvss_score = calculate_cvss31("N", "L", "N", "N", "U", "H", "N", "N")
            else:
                sev_label = "Needs attention"
                sev_level = 1
                cvss_score = calculate_cvss31("L", "L", "L", "N", "U", "L", "L", "N")

            cwe_obj = item.get("issue_cwe", {})
            cwe_id = f"CWE-{cwe_obj.get('id')}" if cwe_obj.get("id") else "CWE-20"
            refs = [item.get("more_info", "https://bandit.readthedocs.io/")]

            rule_id = item.get("test_id", "B000")
            test_name = item.get("test_name", "bandit_issue")
            issue_title = item.get("issue_text", "Security flaw detected by Bandit")
            confidence = item.get("issue_confidence", "MEDIUM")

            # Determine rule key for patching
            if "B608" in rule_id or "sql" in test_name.lower():
                rule_key = "SQLI"
            elif "B602" in rule_id or "B605" in rule_id or "subprocess" in test_name.lower():
                rule_key = "CMD_INJECTION"
            elif "B103" in rule_id or "chmod" in test_name.lower():
                rule_key = "INSECURE_PERMS"
            elif "B301" in rule_id or "pickle" in test_name.lower():
                rule_key = "INSECURE_DESERIALIZATION"
            else:
                rule_key = "SUSPICIOUS_CALL"

            meta = RULE_METADATA.get(rule_key, RULE_METADATA["SQLI"])
            patch_orig, patch_corr, patch_rationale = generate_contextual_patch(rule_key, snippet, func_name)
            diff = create_unified_diff(patch_orig, patch_corr, rel_path)

            five_sec = dict(meta["five_sections"])
            five_sec["where"] = f"In {rel_path} at line {start_l} inside {func_name}()."
            five_sec["proof"] = f"Bandit security scanner flagged rule {rule_id} ({test_name}) with {confidence} confidence at line {start_l}. Source evidence shows suspicious pattern."

            classif_dict = classify_finding(
                scanner_name="bandit",
                scanner_rule_id=rule_id,
                raw_cwe=cwe_id,
                scanner_severity=b_sev,
                scanner_confidence=confidence,
                scanner_message=issue_title,
                file_path=rel_path,
                cvss_score=cvss_score
            )

            f = Finding(
                id=f"PP-BND-{idx:02d}",
                rule=rule_id,
                cwe=cwe_id,
                title=f"{issue_title}",
                technical_title=f"Bandit {rule_id} ({test_name})",
                severity=sev_label,
                severity_level=sev_level,
                status="suspected_pattern",
                cvss=cvss_score,
                file=rel_path,
                function=func_name,
                line=start_l,
                end_line=end_l,
                snippet=snippet,
                eli12=meta["eli12"],
                five_sections=FiveSections(**five_sec),
                diff=diff,
                patch_original=patch_orig,
                patch_corrected=patch_corr,
                patch_rationale=patch_rationale,
                patch_plain_english=meta["patch_plain_english"],
                exploit_name="",
                exploit_before=None, # Pure static finding: NOT experimentally verified
                exploit_after=None,
                rescan_clean=None,
                fixed=False,
                verified_status="unpatched",
                scanner_name="bandit",
                scanner_version=version,
                rule_identifier=rule_id,
                confidence=confidence,
                cwe_identifiers=[cwe_id],
                relevant_references=refs,
                source_evidence=source_evidence,
                why_matched=f"Bandit rule {rule_id} ({test_name}) detected: {issue_title}",
                remediation_guidance=patch_rationale,
                classification=EvidenceBasedClassification(**classif_dict)
            )
            findings.append(f)

        record = ScannerExecutionRecord(
            scanner_name="bandit",
            scanner_version=version,
            status="success",
            exit_code=proc.returncode,
            duration_seconds=dur,
            command=cmd,
            raw_stdout=stdout,
            raw_stderr=proc.stderr,
            findings_count=len(findings)
        )
        return record, findings

    except subprocess.TimeoutExpired:
        return ScannerExecutionRecord(
            scanner_name="bandit",
            scanner_version=version,
            status="timed_out",
            duration_seconds=60.0,
            command=cmd,
            error_message="Bandit scan timed out after 60 seconds",
            findings_count=0
        ), []
    except Exception as e:
        return ScannerExecutionRecord(
            scanner_name="bandit",
            scanner_version=version,
            status="failed",
            error_message=f"Error executing Bandit: {str(e)}",
            command=cmd,
            findings_count=0
        ), []

# -------------------------------------------------------------
# 2. SEMGREP SCANNER RUNNER
# -------------------------------------------------------------
def run_semgrep_scanner(project_dir: Path, languages: List[str]) -> Tuple[ScannerExecutionRecord, List[Finding]]:
    t0 = time.time()
    version = get_installed_version("semgrep") or "1.183.0"
    semgrep_core = get_semgrep_core_executable()
    semgrep_cli = get_semgrep_cli_executable()

    if not (semgrep_core and semgrep_core.exists()) and not (semgrep_cli and semgrep_cli.exists()):
        return ScannerExecutionRecord(
            scanner_name="semgrep",
            scanner_version=version,
            status="missing_dependency",
            error_message="Neither semgrep nor semgrep-core binary found in python environment",
            findings_count=0
        ), []

    # Map project files to rules
    targets: List[Tuple[Path, Path, str]] = []  # (file_path, rules_file, lang_code)
    for root, _, files in os.walk(project_dir):
        if "node_modules" in root or ".git" in root or "__pycache__" in root:
            continue
        for f in files:
            fp = Path(root) / f
            ext = fp.suffix.lower()
            if ext == ".py" and PYTHON_RULES_FILE.exists():
                targets.append((fp, PYTHON_RULES_FILE, "py"))
            elif ext in {".js", ".jsx", ".ts", ".tsx"} and JS_RULES_FILE.exists():
                targets.append((fp, JS_RULES_FILE, "javascript"))

    if not targets:
        return ScannerExecutionRecord(
            scanner_name="semgrep",
            scanner_version=version,
            status="skipped_no_targets",
            error_message="No supported source code files found for Semgrep analysis",
            findings_count=0
        ), []

    all_matches = []
    raw_outputs = []
    has_errors = False
    err_msgs = []

    for target_path, rule_file, lang_code in targets:
        if semgrep_core and semgrep_core.exists():
            cmd = [str(semgrep_core), "-rules", str(rule_file), "-lang", lang_code, str(target_path), "-json"]
        else:
            cmd = [str(semgrep_cli), "scan", "--config", str(rule_file), str(target_path), "--json", "--metrics=off", "--disable-version-check"]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=25)
            stdout = proc.stdout.strip()
            if "{" in stdout:
                raw_json = stdout[stdout.find("{"):stdout.rfind("}") + 1]
                data = json.loads(raw_json)
                results = data.get("results", [])
                all_matches.extend(results)
                raw_outputs.append(f"File {target_path.name}: {len(results)} matches")
            elif proc.returncode != 0:
                has_errors = True
                err_msgs.append(proc.stderr[:150])
        except subprocess.TimeoutExpired:
            has_errors = True
            err_msgs.append(f"Timeout scanning {target_path.name}")
        except Exception as e:
            has_errors = True
            err_msgs.append(f"Error scanning {target_path.name}: {str(e)}")

    dur = round(time.time() - t0, 3)
    findings: List[Finding] = []

    for idx, match in enumerate(all_matches, 1):
        target_f = match.get("path", "")
        try:
            rel_path = str(Path(target_f).resolve().relative_to(project_dir.resolve())).replace("\\", "/")
        except Exception:
            rel_path = str(target_f).replace("\\", "/")

        start_l = int(match.get("start", {}).get("line", 1))
        end_l = int(match.get("end", {}).get("line", start_l))
        extra = match.get("extra", {})
        meta_dict = extra.get("metadata", {})

        raw_lines = extra.get("lines", "")
        source_evidence = redact_secrets(raw_lines.strip())

        snippet, func_name = read_source_snippet(project_dir / rel_path, start_l, end_l)
        if not snippet:
            snippet = source_evidence

        s_sev = extra.get("severity", "WARNING").upper()
        if s_sev == "ERROR":
            sev_label = "Urgent"
            sev_level = 3
            cvss_score = calculate_cvss31("N", "L", "N", "N", "U", "H", "H", "H")
        elif s_sev == "WARNING":
            sev_label = "Important"
            sev_level = 2
            cvss_score = calculate_cvss31("N", "L", "N", "N", "U", "H", "N", "N")
        else:
            sev_label = "Needs attention"
            sev_level = 1
            cvss_score = calculate_cvss31("L", "L", "L", "N", "U", "L", "L", "N")

        cwe_raw = meta_dict.get("cwe", "CWE-20")
        cwe_id = cwe_raw if isinstance(cwe_raw, str) else (cwe_raw[0] if cwe_raw else "CWE-20")
        check_id = match.get("check_id", "semgrep-rule")
        message = extra.get("message", "Semgrep security pattern matched")
        confidence = meta_dict.get("confidence", "HIGH")
        references = meta_dict.get("references", ["https://semgrep.dev/"])
        remediation = meta_dict.get("remediation", "Review and sanitize input before processing.")

        if "sqli" in check_id.lower():
            rule_key = "SQLI"
        elif "command" in check_id.lower() or "exec" in check_id.lower():
            rule_key = "CMD_INJECTION"
        elif "path" in check_id.lower() or "traversal" in check_id.lower():
            rule_key = "PATH"
        elif "deserialization" in check_id.lower() or "pickle" in check_id.lower():
            rule_key = "INSECURE_DESERIALIZATION"
        elif "permission" in check_id.lower() or "chmod" in check_id.lower():
            rule_key = "INSECURE_PERMS"
        else:
            rule_key = "SQLI"

        rule_meta = RULE_METADATA.get(rule_key, RULE_METADATA["SQLI"])
        patch_orig, patch_corr, patch_rationale = generate_contextual_patch(rule_key, snippet, func_name)
        diff = create_unified_diff(patch_orig, patch_corr, rel_path)

        five_sec = dict(rule_meta["five_sections"])
        five_sec["where"] = f"In {rel_path} at line {start_l} inside {func_name}()."
        five_sec["proof"] = f"Semgrep security rule '{check_id}' matched at line {start_l}. Analysis detected suspicious AST structure requiring remediation."

        classif_dict = classify_finding(
            scanner_name="semgrep",
            scanner_rule_id=check_id,
            raw_cwe=cwe_id,
            scanner_severity=s_sev,
            scanner_confidence=confidence,
            scanner_message=message,
            file_path=rel_path,
            cvss_score=cvss_score
        )

        f = Finding(
            id=f"PP-SEM-{idx:02d}",
            rule=check_id,
            cwe=cwe_id,
            title=message,
            technical_title=f"Semgrep: {check_id}",
            severity=sev_label,
            severity_level=sev_level,
            status="suspected_pattern",
            cvss=cvss_score,
            file=rel_path,
            function=func_name,
            line=start_l,
            end_line=end_l,
            snippet=snippet,
            eli12=rule_meta["eli12"],
            five_sections=FiveSections(**five_sec),
            diff=diff,
            patch_original=patch_orig,
            patch_corrected=patch_corr,
            patch_rationale=remediation or patch_rationale,
            patch_plain_english=rule_meta["patch_plain_english"],
            exploit_name="",
            exploit_before=None, # Static finding: NOT experimentally verified
            exploit_after=None,
            rescan_clean=None,
            fixed=False,
            verified_status="unpatched",
            scanner_name="semgrep",
            scanner_version=version,
            rule_identifier=check_id,
            confidence=confidence,
            cwe_identifiers=[cwe_id],
            relevant_references=references,
            source_evidence=source_evidence,
            why_matched=f"Semgrep rule '{check_id}' triggered: {message}",
            remediation_guidance=remediation,
            classification=EvidenceBasedClassification(**classif_dict)
        )
        findings.append(f)

    status_str = "success" if not has_errors or findings else "failed"
    record = ScannerExecutionRecord(
        scanner_name="semgrep",
        scanner_version=version,
        status=status_str,
        duration_seconds=dur,
        command=[str(semgrep_core), "-rules", "<rules>", "-targets", "<files>", "-json"],
        raw_stdout="\n".join(raw_outputs),
        raw_stderr="\n".join(err_msgs) if err_msgs else None,
        error_message="; ".join(err_msgs) if (err_msgs and not findings) else None,
        findings_count=len(findings)
    )
    return record, findings

# -------------------------------------------------------------
# 3. PIP-AUDIT RUNNER
# -------------------------------------------------------------
def run_pip_audit_scanner(project_dir: Path) -> Tuple[ScannerExecutionRecord, List[Finding]]:
    t0 = time.time()
    version = get_installed_version("pip-audit") or "2.10.1"
    req_file = project_dir / "requirements.txt"

    if not req_file.exists():
        reqs = list(project_dir.glob("**/*requirements*.txt"))
        if reqs:
            req_file = reqs[0]

    if not req_file or not req_file.exists():
        return ScannerExecutionRecord(
            scanner_name="pip-audit",
            scanner_version=version,
            status="skipped_no_manifest",
            error_message="No requirements.txt manifest found in project",
            findings_count=0
        ), []

    cmd = [PYTHON_EXE, "-m", "pip_audit", "-r", str(req_file), "-f", "json", "--desc", "on", "--timeout", "5"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        dur = round(time.time() - t0, 3)
        stdout = proc.stdout.strip()

        if "{" not in stdout:
            # Check if dependencies failed to collect or network error
            err_msg = proc.stderr.strip() or stdout or "Failed to run pip-audit"
            return ScannerExecutionRecord(
                scanner_name="pip-audit",
                scanner_version=version,
                status="failed",
                exit_code=proc.returncode,
                duration_seconds=dur,
                command=cmd,
                raw_stdout=stdout,
                raw_stderr=proc.stderr,
                error_message=f"pip-audit execution error: {err_msg[:300]}",
                findings_count=0
            ), []

        raw_json = stdout[stdout.find("{"):stdout.rfind("}") + 1]
        data = json.loads(raw_json)
        dependencies = data.get("dependencies", [])

        findings: List[Finding] = []
        rel_req = str(req_file.relative_to(project_dir)).replace("\\", "/")
        req_lines = req_file.read_text(encoding="utf-8", errors="ignore").splitlines()

        count = 1
        for dep in dependencies:
            name = dep.get("name", "package")
            ver = dep.get("version", "unknown")
            vulns = dep.get("vulns", [])

            # Locate line in requirements.txt
            line_no = 1
            for idx, rl in enumerate(req_lines, 1):
                if rl.strip().lower().startswith(name.lower()):
                    line_no = idx
                    break

            for v in vulns:
                vuln_id = v.get("id", "VULN-001")
                desc = v.get("description", f"Known security vulnerability in {name} {ver}")
                fix_vers = v.get("fix_versions", [])
                aliases = v.get("aliases", [])

                cwe_id = "CWE-1395" # Dependency with known vulnerabilities
                sev_label = "Important"
                sev_level = 2
                cvss_score = calculate_cvss31("N", "L", "N", "N", "U", "H", "N", "N")

                fix_target = fix_vers[0] if fix_vers else "latest"
                patch_orig = f"{name}=={ver}"
                patch_corr = f"{name}>={fix_target}" if fix_vers else f"# Upgrade {name}"
                patch_rationale = f"Upgrade {name} from {ver} to {', '.join(fix_vers) or 'a patched release'} to resolve {vuln_id}."
                diff = create_unified_diff(patch_orig, patch_corr, rel_req)

                refs = [f"https://osv.dev/vulnerability/{vuln_id}"]
                for a in aliases:
                    if a.startswith("CVE-"):
                        refs.append(f"https://nvd.nist.gov/vuln/detail/{a}")

                five_sec = {
                    "what": f"Dependency {name} version {ver} is vulnerable to {vuln_id}.",
                    "why": desc,
                    "where": f"In {rel_req} at line {line_no}.",
                    "how": f"An attacker can exploit known vulnerabilities in {name} {ver}.",
                    "proof": f"pip-audit matched package {name}=={ver} against vulnerability database entry {vuln_id}."
                }

                eli12 = ELI12Content(
                    analogy_title="Using an Outdated Building Part",
                    analogy_story=f"Using an old version of {name} is like installing a lock that has a known master key in circulation.",
                    simple_explanation=f"Updating {name} replaces the vulnerable library with a secure, patched version.",
                    icon_name="ShieldAlert"
                )

                real_cve = vuln_id if vuln_id.startswith("CVE-") else None
                if not real_cve and aliases:
                    for a in aliases:
                        if a.startswith("CVE-"):
                            real_cve = a
                            break

                classif_dict = classify_finding(
                    scanner_name="pip-audit",
                    scanner_rule_id=vuln_id,
                    raw_cwe=cwe_id,
                    scanner_severity=sev_label,
                    scanner_confidence="HIGH",
                    scanner_message=desc,
                    file_path=rel_req,
                    cvss_score=cvss_score,
                    dependency_pkg=name,
                    dependency_version=ver,
                    cve_id=real_cve,
                    advisory_url=refs[0] if refs else None,
                    advisory_summary=desc
                )

                f = Finding(
                    id=f"PP-AUD-{count:02d}",
                    rule=vuln_id,
                    cwe=cwe_id,
                    title=f"Vulnerable Dependency: {name} {ver} ({vuln_id})",
                    technical_title=f"pip-audit: {vuln_id} ({name}=={ver})",
                    severity=sev_label,
                    severity_level=sev_level,
                    status="suspected_pattern",
                    cvss=cvss_score,
                    file=rel_req,
                    function="dependencies",
                    line=line_no,
                    end_line=line_no,
                    snippet=f"{name}=={ver}",
                    eli12=eli12,
                    five_sections=FiveSections(**five_sec),
                    diff=diff,
                    patch_original=patch_orig,
                    patch_corrected=patch_corr,
                    patch_rationale=patch_rationale,
                    patch_plain_english=f"Update {name} in {rel_req} to a secure release.",
                    exploit_name="",
                    exploit_before=None,
                    exploit_after=None,
                    rescan_clean=None,
                    fixed=False,
                    verified_status="unpatched",
                    scanner_name="pip-audit",
                    scanner_version=version,
                    rule_identifier=vuln_id,
                    confidence="HIGH",
                    cwe_identifiers=[cwe_id],
                    relevant_references=refs,
                    source_evidence=f"{name}=={ver}",
                    why_matched=f"{name} {ver} contains known vulnerability {vuln_id}: {desc[:200]}",
                    remediation_guidance=patch_rationale,
                    classification=EvidenceBasedClassification(**classif_dict)
                )
                findings.append(f)
                count += 1

        record = ScannerExecutionRecord(
            scanner_name="pip-audit",
            scanner_version=version,
            status="success",
            exit_code=proc.returncode,
            duration_seconds=dur,
            command=cmd,
            raw_stdout=stdout,
            raw_stderr=proc.stderr,
            findings_count=len(findings)
        )
        return record, findings

    except subprocess.TimeoutExpired:
        return ScannerExecutionRecord(
            scanner_name="pip-audit",
            scanner_version=version,
            status="timed_out",
            duration_seconds=35.0,
            command=cmd,
            error_message="pip-audit timed out waiting for vulnerability database response",
            findings_count=0
        ), []
    except Exception as e:
        return ScannerExecutionRecord(
            scanner_name="pip-audit",
            scanner_version=version,
            status="failed",
            command=cmd,
            error_message=f"Error running pip-audit: {str(e)}",
            findings_count=0
        ), []

# -------------------------------------------------------------
# 4. NPM AUDIT RUNNER
# -------------------------------------------------------------
def run_npm_audit_scanner(project_dir: Path) -> Tuple[ScannerExecutionRecord, List[Finding]]:
    t0 = time.time()
    npm_path = shutil.which("npm")
    pkg_json = project_dir / "package.json"
    lock_file = project_dir / "package-lock.json"

    if not pkg_json.exists():
        return ScannerExecutionRecord(
            scanner_name="npm-audit",
            status="skipped_no_manifest",
            error_message="No package.json manifest found in project",
            findings_count=0
        ), []

    if not npm_path:
        return ScannerExecutionRecord(
            scanner_name="npm-audit",
            status="missing_dependency",
            error_message="npm binary not found on host system",
            findings_count=0
        ), []

    if not lock_file.exists():
        return ScannerExecutionRecord(
            scanner_name="npm-audit",
            status="skipped_missing_lockfile",
            error_message="npm audit requires package-lock.json to inspect dependency graph",
            findings_count=0
        ), []

    cmd = [npm_path, "audit", "--json"]
    try:
        proc = subprocess.run(cmd, cwd=str(project_dir), capture_output=True, text=True, timeout=35)
        dur = round(time.time() - t0, 3)
        stdout = proc.stdout.strip()

        if "{" not in stdout:
            return ScannerExecutionRecord(
                scanner_name="npm-audit",
                status="failed",
                exit_code=proc.returncode,
                duration_seconds=dur,
                command=cmd,
                raw_stdout=stdout,
                raw_stderr=proc.stderr,
                error_message=f"npm audit returned non-JSON output: {proc.stderr[:300]}",
                findings_count=0
            ), []

        raw_json = stdout[stdout.find("{"):stdout.rfind("}") + 1]
        data = json.loads(raw_json)
        vulns = data.get("vulnerabilities", {})

        findings: List[Finding] = []
        rel_pkg = str(pkg_json.relative_to(project_dir)).replace("\\", "/")
        pkg_content = pkg_json.read_text(encoding="utf-8", errors="ignore")

        idx = 1
        for pkg_name, info in vulns.items():
            sev = info.get("severity", "moderate")
            if sev == "critical":
                sev_label = "Urgent"
                sev_level = 3
                cvss_score = 9.8
            elif sev == "high":
                sev_label = "Urgent"
                sev_level = 3
                cvss_score = 7.5
            elif sev == "moderate":
                sev_label = "Important"
                sev_level = 2
                cvss_score = 5.3
            else:
                sev_label = "Needs attention"
                sev_level = 1
                cvss_score = 3.1

            effects = info.get("effects", [])
            via = info.get("via", [])
            advisory_title = "Vulnerable npm package"
            cwe_id = "CWE-1395"
            adv_url = "https://www.npmjs.com/"

            if via and isinstance(via[0], dict):
                advisory_title = via[0].get("title", advisory_title)
                adv_url = via[0].get("url", adv_url)
                if via[0].get("cwe"):
                    cwes = via[0].get("cwe")
                    cwe_id = cwes[0] if isinstance(cwes, list) and cwes else str(cwes)

            patch_rationale = f"Run 'npm audit fix' or update '{pkg_name}' to resolve this advisory."
            patch_orig = f'"{pkg_name}":'
            patch_corr = f'"{pkg_name}": /* updated */'
            diff = create_unified_diff(patch_orig, patch_corr, rel_pkg)

            classif_dict = classify_finding(
                scanner_name="npm-audit",
                scanner_rule_id=f"npm-{pkg_name}",
                raw_cwe=cwe_id,
                scanner_severity=sev_label,
                scanner_confidence="HIGH",
                scanner_message=advisory_title,
                file_path=rel_pkg,
                cvss_score=cvss_score,
                dependency_pkg=pkg_name,
                dependency_version="declared",
                cve_id=cwe_id if cwe_id.startswith("CVE-") else None,
                advisory_url=adv_url,
                advisory_summary=advisory_title
            )

            f = Finding(
                id=f"PP-NPM-{idx:02d}",
                rule=f"NPM-{pkg_name}",
                cwe=cwe_id,
                title=f"Vulnerable Dependency: {pkg_name} ({advisory_title})",
                technical_title=f"npm-audit: {pkg_name} ({sev})",
                severity=sev_label,
                severity_level=sev_level,
                status="suspected_pattern",
                cvss=cvss_score,
                file=rel_pkg,
                function="dependencies",
                line=1,
                end_line=1,
                snippet=f'"{pkg_name}" declared in package.json',
                eli12=ELI12Content(
                    analogy_title="Unsafe Building Material",
                    analogy_story=f"Using an old version of {pkg_name} is like building with defective bricks.",
                    simple_explanation="Updating the package pulls in the security fix published by the maintainers.",
                    icon_name="ShieldAlert"
                ),
                five_sections=FiveSections(
                    what=f"Package {pkg_name} has a {sev} vulnerability: {advisory_title}.",
                    why="Dependency manifests specify an older or unpatched version.",
                    where=f"In {rel_pkg}.",
                    how="An attacker can leverage vulnerabilities in third-party library code.",
                    proof=f"npm audit identified security advisory for {pkg_name}: {adv_url}"
                ),
                diff=diff,
                patch_original=patch_orig,
                patch_corrected=patch_corr,
                patch_rationale=patch_rationale,
                patch_plain_english=f"Update {pkg_name} via npm.",
                exploit_name="",
                exploit_before=None,
                exploit_after=None,
                rescan_clean=None,
                fixed=False,
                verified_status="unpatched",
                scanner_name="npm-audit",
                scanner_version=None,
                rule_identifier=f"npm-{pkg_name}",
                confidence="HIGH",
                cwe_identifiers=[cwe_id],
                relevant_references=[adv_url],
                source_evidence=f'"{pkg_name}" in {rel_pkg}',
                why_matched=f"npm audit advisory: {advisory_title}",
                remediation_guidance=patch_rationale,
                classification=EvidenceBasedClassification(**classif_dict)
            )
            findings.append(f)
            idx += 1

        record = ScannerExecutionRecord(
            scanner_name="npm-audit",
            status="success",
            exit_code=proc.returncode,
            duration_seconds=dur,
            command=cmd,
            raw_stdout=stdout,
            raw_stderr=proc.stderr,
            findings_count=len(findings)
        )
        return record, findings

    except subprocess.TimeoutExpired:
        return ScannerExecutionRecord(
            scanner_name="npm-audit",
            status="timed_out",
            duration_seconds=35.0,
            command=cmd,
            error_message="npm audit timed out",
            findings_count=0
        ), []
    except Exception as e:
        return ScannerExecutionRecord(
            scanner_name="npm-audit",
            status="failed",
            command=cmd,
            error_message=f"Error executing npm audit: {str(e)}",
            findings_count=0
        ), []

# -------------------------------------------------------------
# UNIFIED ENGINE ORCHESTRATOR
# -------------------------------------------------------------
def run_vulnerability_engine(project_dir: Path) -> Tuple[ProjectEnvironment, List[ScannerExecutionRecord], List[Finding]]:
    """
    Executes the multi-scanner vulnerability analysis engine across the project:
    - Pre-identifies environment, manifests, and applicable tools
    - Runs Semgrep, Bandit, pip-audit, and npm-audit where applicable
    - Deduplicates identical findings across scanners
    - Preserves all raw execution records for debugging and review
    """
    env = identify_project_environment(project_dir)
    reports: List[ScannerExecutionRecord] = []
    raw_findings: List[Finding] = []

    # 1. Run Bandit if Python is detected
    if "bandit" in env.applicable_scanners:
        b_rec, b_findings = run_bandit_scanner(project_dir)
        reports.append(b_rec)
        raw_findings.extend(b_findings)

    # 2. Run Semgrep if supported source code is detected
    if "semgrep" in env.applicable_scanners:
        s_rec, s_findings = run_semgrep_scanner(project_dir, env.languages)
        reports.append(s_rec)
        raw_findings.extend(s_findings)

    # 3. Run pip-audit if Python dependencies manifest is detected
    if "pip-audit" in env.applicable_scanners:
        p_rec, p_findings = run_pip_audit_scanner(project_dir)
        reports.append(p_rec)
        raw_findings.extend(p_findings)

    # 4. Run npm-audit if package.json is detected
    if "npm-audit" in env.applicable_scanners:
        n_rec, n_findings = run_npm_audit_scanner(project_dir)
        reports.append(n_rec)
        raw_findings.extend(n_findings)

    # Deduplicate findings on the same file and overlapping line range
    deduped: List[Finding] = []
    seen_locations = set()

    for f in raw_findings:
        loc_key = (f.file, f.line, f.cwe)
        if loc_key in seen_locations:
            # Merge references and secondary scanner name into existing finding
            for existing in deduped:
                if (existing.file, existing.line, existing.cwe) == loc_key:
                    if f.scanner_name not in existing.technical_title:
                        existing.technical_title += f" + {f.scanner_name}"
                    if f.relevant_references:
                        for ref in f.relevant_references:
                            if ref not in existing.relevant_references:
                                existing.relevant_references.append(ref)
                    break
            continue
        seen_locations.add(loc_key)
        deduped.append(f)

    # Renumber findings cleanly and ensure every finding has evidence-based classification
    for idx, f in enumerate(deduped, 1):
        f.id = f"PP-{idx:02d}"
        if not f.classification:
            classif_dict = classify_finding(
                scanner_name=f.scanner_name,
                scanner_rule_id=f.rule_identifier or f.rule,
                raw_cwe=f.cwe,
                scanner_severity=f.severity,
                scanner_confidence=f.confidence,
                scanner_message=f.title,
                file_path=f.file,
                cvss_score=f.cvss
            )
            f.classification = EvidenceBasedClassification(**classif_dict)

    return env, reports, deduped
