import uuid
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
from pydantic import BaseModel
from fastapi import APIRouter, HTTPException, Query, BackgroundTasks

from app.database import (
    get_project_by_id,
    save_scan,
    create_scan_record,
    get_scan_by_id,
    get_latest_scan_for_project,
    get_findings_for_scan,
    get_findings_for_project,
    enqueue_scan_job
)
from app.models.schemas import ScanResult, Finding, ScanSummary
from app.worker import execute_scan_task, KNOWN_PATCHES

router = APIRouter(prefix="/api/scan", tags=["scan"])

class ScanInitiationResponse(BaseModel):
    id: str
    scan_id: str
    project_id: str
    status: str
    started_at: str
    message: str

class ScanStatusResponse(BaseModel):
    scan_id: str
    project_id: str
    status: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    error_message: Optional[str] = None
    findings_count: int = 0
    safety_percentage: int = 0
    safety_rating: str = ""

@router.post("/start/{project_id}", response_model=ScanInitiationResponse)
async def start_background_scan(project_id: str, background_tasks: BackgroundTasks):
    """
    Initiates an asynchronous background security analysis scan for the project.
    Enqueues the job in SQLite and returns immediately with scan_id and 'pending' status.
    """
    project = get_project_by_id(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    project_dir = Path(project["project_path"])
    if not project_dir.exists():
        raise HTTPException(status_code=404, detail="Project directory does not exist on disk")

    scan_id = f"scan-{uuid.uuid4().hex[:8]}"
    job_id = f"job-{uuid.uuid4().hex[:8]}"

    # Record scan in SQLite as pending
    rec = create_scan_record(scan_id, project_id, status="pending")

    # Enqueue job in SQLite
    enqueue_scan_job(job_id, scan_id, project_id)

    # Trigger background execution
    background_tasks.add_task(execute_scan_task, project_id, scan_id)

    return ScanInitiationResponse(
        id=scan_id,
        scan_id=scan_id,
        project_id=project_id,
        status="pending",
        started_at=rec["started_at"],
        message="Background security scan initiated successfully"
    )

@router.get("/status/{scan_id}", response_model=ScanStatusResponse)
async def get_scan_status(scan_id: str):
    """
    Polls the real-time status of an ongoing or completed scan from SQLite.
    """
    scan = get_scan_by_id(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan record not found")

    summary = scan.get("summary") or {}
    findings = scan.get("findings") or []

    return ScanStatusResponse(
        scan_id=scan_id,
        project_id=scan["project_id"],
        status=scan.get("status", "pending"),
        started_at=scan.get("started_at"),
        completed_at=scan.get("completed_at"),
        error_message=scan.get("error_message"),
        findings_count=len(findings),
        safety_percentage=summary.get("safety_percentage", 0),
        safety_rating=summary.get("safety_rating", "")
    )

@router.get("/{scan_id}/findings", response_model=List[Dict[str, Any]])
async def get_scan_findings(scan_id: str):
    """
    Returns persistent findings for a specific scan directly from the SQLite database.
    """
    scan = get_scan_by_id(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan record not found")

    findings = get_findings_for_scan(scan_id)
    return findings

@router.get("/project/{project_id}/findings", response_model=List[Dict[str, Any]])
async def get_project_findings(project_id: str):
    """
    Returns the latest persistent findings for a project from the SQLite database.
    """
    project = get_project_by_id(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    findings = get_findings_for_project(project_id)
    return findings

@router.get("/{scan_id}", response_model=ScanResult)
async def get_scan_details(scan_id: str):
    """
    Retrieves the complete scan results from SQLite including environment, reports, and findings.
    """
    scan = get_scan_by_id(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan record not found")
    return scan

@router.post("/{project_id}", response_model=ScanResult)
async def scan_project_endpoint(project_id: str, wait: bool = Query(True)):
    """
    Executes or enqueues scan. When wait=True (default for frontend compatibility),
    executes the scan engine and returns the persistent ScanResult directly.
    """
    project = get_project_by_id(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    project_dir = Path(project["project_path"])
    if not project_dir.exists():
        raise HTTPException(status_code=404, detail="Project directory does not exist on disk")

    scan_id = f"scan-{uuid.uuid4().hex[:8]}"
    create_scan_record(scan_id, project_id, status="running")

    # Execute scan directly using real scanners (Semgrep, Bandit, pip-audit, npm-audit)
    result = execute_scan_task(project_id, scan_id)
    if result["status"] == "failed":
        raise HTTPException(status_code=500, detail=result.get("error", "Scan analysis failed"))

    saved_scan = get_scan_by_id(scan_id)
    if not saved_scan:
        raise HTTPException(status_code=500, detail="Scan record could not be loaded from database")

    return saved_scan
