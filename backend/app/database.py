import sqlite3
import json
from datetime import datetime
from typing import Any, Dict, List, Optional
from app.config import DB_PATH

def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH), timeout=30.0)
    conn.row_factory = sqlite3.Row
    return conn

def init_db() -> None:
    with get_db_connection() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS projects (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            source_type TEXT NOT NULL,
            project_path TEXT NOT NULL,
            created_at TEXT NOT NULL,
            languages_json TEXT,
            frameworks_json TEXT,
            file_count INTEGER DEFAULT 0,
            line_count INTEGER DEFAULT 0,
            status TEXT DEFAULT 'ready'
        );

        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            started_at TEXT,
            completed_at TEXT,
            scanned_at TEXT,
            error_message TEXT,
            summary_json TEXT,
            findings_json TEXT,
            regressions_json TEXT,
            scanner_reports_json TEXT,
            project_environment_json TEXT,
            attack_dataset_metadata_json TEXT,
            FOREIGN KEY (project_id) REFERENCES projects(id)
        );

        CREATE TABLE IF NOT EXISTS findings (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            project_id TEXT NOT NULL,
            rule TEXT,
            cwe TEXT,
            title TEXT,
            technical_title TEXT,
            severity TEXT,
            severity_level INTEGER,
            status TEXT,
            cvss REAL,
            file TEXT,
            function TEXT,
            line INTEGER,
            end_line INTEGER,
            snippet TEXT,
            scanner_name TEXT,
            scanner_version TEXT,
            rule_identifier TEXT,
            confidence TEXT,
            source_evidence TEXT,
            why_matched TEXT,
            remediation_guidance TEXT,
            classification_json TEXT,
            eli12_json TEXT,
            five_sections_json TEXT,
            diff TEXT,
            patch_original TEXT,
            patch_corrected TEXT,
            patch_rationale TEXT,
            patch_plain_english TEXT,
            verified_status TEXT DEFAULT 'unpatched',
            fixed INTEGER DEFAULT 0,
            data_json TEXT,
            created_at TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id),
            FOREIGN KEY (project_id) REFERENCES projects(id)
        );

        CREATE TABLE IF NOT EXISTS scan_jobs (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            project_id TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'queued',
            created_at TEXT NOT NULL,
            started_at TEXT,
            finished_at TEXT,
            error_message TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id),
            FOREIGN KEY (project_id) REFERENCES projects(id)
        );

        CREATE TABLE IF NOT EXISTS patches (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL,
            finding_id TEXT NOT NULL,
            status TEXT NOT NULL,
            patch_diff TEXT NOT NULL,
            patch_explanation TEXT,
            approved_at TEXT,
            verified_at TEXT,
            verification_data_json TEXT,
            FOREIGN KEY (project_id) REFERENCES projects(id)
        );
        """)

        # Migration: ensure scans table has all required columns
        existing_cols = {r[1] for r in conn.execute("PRAGMA table_info(scans)").fetchall()}
        scans_needed = [
            ("status", "TEXT NOT NULL DEFAULT 'completed'"),
            ("started_at", "TEXT"),
            ("completed_at", "TEXT"),
            ("error_message", "TEXT"),
            ("scanner_reports_json", "TEXT"),
            ("project_environment_json", "TEXT"),
            ("attack_dataset_metadata_json", "TEXT"),
        ]
        for col_name, col_def in scans_needed:
            if col_name not in existing_cols:
                try:
                    conn.execute(f"ALTER TABLE scans ADD COLUMN {col_name} {col_def}")
                except Exception:
                    pass

        conn.commit()

# Project helpers
def save_project(project_data: Dict[str, Any]) -> None:
    with get_db_connection() as conn:
        conn.execute("""
        INSERT OR REPLACE INTO projects 
        (id, name, source_type, project_path, created_at, languages_json, frameworks_json, file_count, line_count, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            project_data["id"],
            project_data["name"],
            project_data["source_type"],
            project_data["project_path"],
            project_data.get("created_at", datetime.now().isoformat()),
            json.dumps(project_data.get("languages", [])),
            json.dumps(project_data.get("frameworks", [])),
            project_data.get("file_count", 0),
            project_data.get("line_count", 0),
            project_data.get("status", "ready")
        ))
        conn.commit()

def get_all_projects() -> List[Dict[str, Any]]:
    with get_db_connection() as conn:
        rows = conn.execute("SELECT * FROM projects ORDER BY created_at DESC").fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["languages"] = json.loads(d.get("languages_json") or "[]")
            d["frameworks"] = json.loads(d.get("frameworks_json") or "[]")
            result.append(d)
        return result

def get_project_by_id(project_id: str) -> Optional[Dict[str, Any]]:
    with get_db_connection() as conn:
        row = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["languages"] = json.loads(d.get("languages_json") or "[]")
        d["frameworks"] = json.loads(d.get("frameworks_json") or "[]")
        return d

# Scan helpers
def create_scan_record(scan_id: str, project_id: str, status: str = "pending") -> Dict[str, Any]:
    now = datetime.now().isoformat()
    with get_db_connection() as conn:
        conn.execute("""
        INSERT OR REPLACE INTO scans 
        (id, project_id, status, started_at, scanned_at, error_message, summary_json, findings_json, regressions_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_id,
            project_id,
            status,
            now,
            now,
            None,
            json.dumps({"candidates": 0, "confirmed": 0, "false_positives": 0, "fixed": 0, "regressions_passed": 0, "regressions_total": 0, "safety_rating": "Scan queued", "safety_percentage": 0}),
            json.dumps([]),
            json.dumps({})
        ))
        conn.commit()
    return {"id": scan_id, "project_id": project_id, "status": status, "started_at": now}

def update_scan_status(
    scan_id: str,
    status: str,
    error_message: Optional[str] = None,
    summary: Optional[Dict[str, Any]] = None,
    findings: Optional[List[Dict[str, Any]]] = None,
    regressions: Optional[Dict[str, Any]] = None,
    scanner_reports: Optional[List[Dict[str, Any]]] = None,
    project_environment: Optional[Dict[str, Any]] = None,
    attack_dataset_metadata: Optional[Dict[str, Any]] = None
) -> None:
    now = datetime.now().isoformat()
    with get_db_connection() as conn:
        updates = ["status = ?"]
        params: List[Any] = [status]

        if status == "running":
            updates.append("started_at = ?")
            params.append(now)
        elif status in ["completed", "failed"]:
            updates.append("completed_at = ?")
            params.append(now)

        if error_message is not None:
            updates.append("error_message = ?")
            params.append(error_message)
        if summary is not None:
            updates.append("summary_json = ?")
            params.append(json.dumps(summary))
        if findings is not None:
            updates.append("findings_json = ?")
            params.append(json.dumps(findings))
        if regressions is not None:
            updates.append("regressions_json = ?")
            params.append(json.dumps(regressions))
        if scanner_reports is not None:
            updates.append("scanner_reports_json = ?")
            params.append(json.dumps(scanner_reports))
        if project_environment is not None:
            updates.append("project_environment_json = ?")
            params.append(json.dumps(project_environment))
        if attack_dataset_metadata is not None:
            updates.append("attack_dataset_metadata_json = ?")
            params.append(json.dumps(attack_dataset_metadata))

        params.append(scan_id)
        query = f"UPDATE scans SET {', '.join(updates)} WHERE id = ?"
        conn.execute(query, tuple(params))
        conn.commit()

def get_scan_by_id(scan_id: str) -> Optional[Dict[str, Any]]:
    with get_db_connection() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["summary"] = json.loads(d["summary_json"]) if d.get("summary_json") else {"candidates": 0, "confirmed": 0, "false_positives": 0, "fixed": 0, "regressions_passed": 0, "regressions_total": 0, "safety_rating": "", "safety_percentage": 0}
        d["findings"] = json.loads(d["findings_json"]) if d.get("findings_json") else []
        d["regressions"] = json.loads(d["regressions_json"]) if d.get("regressions_json") else {}
        d["scanner_reports"] = json.loads(d["scanner_reports_json"]) if d.get("scanner_reports_json") else []
        d["project_environment"] = json.loads(d["project_environment_json"]) if d.get("project_environment_json") else None
        d["attack_dataset_metadata"] = json.loads(d["attack_dataset_metadata_json"]) if d.get("attack_dataset_metadata_json") else None
        env = d["project_environment"] or {}
        d["languages_detected"] = env.get("languages", [])
        d["frameworks_detected"] = env.get("frameworks", [])
        return d

def get_latest_scan_for_project(project_id: str) -> Optional[Dict[str, Any]]:
    with get_db_connection() as conn:
        row = conn.execute("SELECT * FROM scans WHERE project_id = ? ORDER BY COALESCE(completed_at, started_at, scanned_at) DESC LIMIT 1", (project_id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["summary"] = json.loads(d["summary_json"]) if d.get("summary_json") else {"candidates": 0, "confirmed": 0, "false_positives": 0, "fixed": 0, "regressions_passed": 0, "regressions_total": 0, "safety_rating": "", "safety_percentage": 0}
        d["findings"] = json.loads(d["findings_json"]) if d.get("findings_json") else []
        d["regressions"] = json.loads(d["regressions_json"]) if d.get("regressions_json") else {}
        d["scanner_reports"] = json.loads(d["scanner_reports_json"]) if d.get("scanner_reports_json") else []
        d["project_environment"] = json.loads(d["project_environment_json"]) if d.get("project_environment_json") else None
        d["attack_dataset_metadata"] = json.loads(d["attack_dataset_metadata_json"]) if d.get("attack_dataset_metadata_json") else None
        env = d["project_environment"] or {}
        d["languages_detected"] = env.get("languages", [])
        d["frameworks_detected"] = env.get("frameworks", [])
        return d

def save_scan(scan_data: Dict[str, Any]) -> None:
    """Saves scan result and syncs individual findings into the findings table."""
    now = datetime.now().isoformat()
    scan_id = scan_data["id"]
    project_id = scan_data["project_id"]

    with get_db_connection() as conn:
        conn.execute("""
        INSERT OR REPLACE INTO scans 
        (id, project_id, status, started_at, completed_at, scanned_at, error_message, summary_json, findings_json, regressions_json, scanner_reports_json, project_environment_json, attack_dataset_metadata_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_id,
            project_id,
            scan_data.get("status", "completed"),
            scan_data.get("started_at", now),
            now,
            scan_data.get("scanned_at", now),
            scan_data.get("error_message"),
            json.dumps(scan_data["summary"]),
            json.dumps(scan_data["findings"]),
            json.dumps(scan_data.get("regressions", {})),
            json.dumps(scan_data.get("scanner_reports", [])),
            json.dumps(scan_data.get("project_environment")),
            json.dumps(scan_data.get("attack_dataset_metadata"))
        ))

        # Insert or replace individual findings
        for f in scan_data.get("findings", []):
            f_id = f.get("id") or f"FIND-{project_id[:6]}-{f.get('line', 1)}"
            conn.execute("""
            INSERT OR REPLACE INTO findings (
                id, scan_id, project_id, rule, cwe, title, technical_title,
                severity, severity_level, status, cvss, file, function, line, end_line,
                snippet, scanner_name, scanner_version, rule_identifier, confidence,
                source_evidence, why_matched, remediation_guidance, classification_json,
                eli12_json, five_sections_json, diff, patch_original, patch_corrected,
                patch_rationale, patch_plain_english, verified_status, fixed, data_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                f_id,
                scan_id,
                project_id,
                f.get("rule"),
                f.get("cwe"),
                f.get("title"),
                f.get("technical_title"),
                f.get("severity"),
                f.get("severity_level", 1),
                f.get("status", "suspected_pattern"),
                float(f.get("cvss", 0.0)),
                f.get("file"),
                f.get("function"),
                int(f.get("line", 1)),
                int(f.get("end_line", 1)),
                f.get("snippet"),
                f.get("scanner_name"),
                f.get("scanner_version"),
                f.get("rule_identifier"),
                f.get("confidence"),
                f.get("source_evidence"),
                f.get("why_matched"),
                f.get("remediation_guidance"),
                json.dumps(f.get("classification")),
                json.dumps(f.get("eli12")),
                json.dumps(f.get("five_sections")),
                f.get("diff", ""),
                f.get("patch_original", ""),
                f.get("patch_corrected", ""),
                f.get("patch_rationale", ""),
                f.get("patch_plain_english", ""),
                f.get("verified_status", "unpatched"),
                1 if f.get("fixed") else 0,
                json.dumps(f),
                now
            ))
        conn.commit()

# Individual findings helpers
def get_findings_for_scan(scan_id: str) -> List[Dict[str, Any]]:
    with get_db_connection() as conn:
        rows = conn.execute("SELECT data_json FROM findings WHERE scan_id = ? ORDER BY severity_level DESC, line ASC", (scan_id,)).fetchall()
        result = []
        for r in rows:
            if r["data_json"]:
                result.append(json.loads(r["data_json"]))
        return result

def get_findings_for_project(project_id: str) -> List[Dict[str, Any]]:
    with get_db_connection() as conn:
        # Get latest scan ID
        scan_row = conn.execute("SELECT id FROM scans WHERE project_id = ? ORDER BY COALESCE(completed_at, started_at, scanned_at) DESC LIMIT 1", (project_id,)).fetchone()
        if not scan_row:
            return []
        scan_id = scan_row["id"]
        return get_findings_for_scan(scan_id)

# Background job queue helpers
def enqueue_scan_job(job_id: str, scan_id: str, project_id: str) -> Dict[str, Any]:
    now = datetime.now().isoformat()
    with get_db_connection() as conn:
        conn.execute("""
        INSERT OR REPLACE INTO scan_jobs (id, scan_id, project_id, status, created_at)
        VALUES (?, ?, ?, 'queued', ?)
        """, (job_id, scan_id, project_id, now))
        conn.commit()
    return {"id": job_id, "scan_id": scan_id, "project_id": project_id, "status": "queued", "created_at": now}

def fetch_next_queued_job() -> Optional[Dict[str, Any]]:
    with get_db_connection() as conn:
        row = conn.execute("SELECT * FROM scan_jobs WHERE status = 'queued' ORDER BY created_at ASC LIMIT 1").fetchone()
        return dict(row) if row else None

def mark_job_status(job_id: str, status: str, error_message: Optional[str] = None) -> None:
    now = datetime.now().isoformat()
    with get_db_connection() as conn:
        if status == "running":
            conn.execute("UPDATE scan_jobs SET status = ?, started_at = ? WHERE id = ?", (status, now, job_id))
        elif status in ["completed", "failed"]:
            conn.execute("UPDATE scan_jobs SET status = ?, finished_at = ?, error_message = ? WHERE id = ?", (status, now, error_message, job_id))
        else:
            conn.execute("UPDATE scan_jobs SET status = ? WHERE id = ?", (status, job_id))
        conn.commit()

# Patch helpers
def save_patch_record(patch_data: Dict[str, Any]) -> None:
    with get_db_connection() as conn:
        conn.execute("""
        INSERT OR REPLACE INTO patches 
        (id, project_id, finding_id, status, patch_diff, patch_explanation, approved_at, verified_at, verification_data_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            patch_data["id"],
            patch_data["project_id"],
            patch_data["finding_id"],
            patch_data["status"],
            patch_data["patch_diff"],
            patch_data.get("patch_explanation", ""),
            patch_data.get("approved_at"),
            patch_data.get("verified_at"),
            json.dumps(patch_data.get("verification_data", {}))
        ))
        conn.commit()
