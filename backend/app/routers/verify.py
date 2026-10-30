from pathlib import Path
from fastapi import APIRouter, HTTPException
from app.config import PROJECTS_DIR, FIXTURES_DIR
from app.database import get_project_by_id, get_latest_scan_for_project, save_scan, save_patch_record
from app.models.schemas import VerificationResult
from app.services.verification_engine import verify_single_patch
from app.routers.scan import KNOWN_PATCHES

router = APIRouter(prefix="/api/verify", tags=["verify"])

@router.post("/{project_id}/{finding_id}", response_model=VerificationResult)
async def verify_patch_endpoint(project_id: str, finding_id: str):
    project = get_project_by_id(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    scan_res = get_latest_scan_for_project(project_id)
    if not scan_res:
        raise HTTPException(status_code=400, detail="Scan results not found")

    finding = next((f for f in scan_res["findings"] if f["id"] == finding_id), None)
    if not finding:
        raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found")

    func_name = finding["function"]
    original_file = Path(project["project_path"]) / finding["file"]
    if not original_file.exists():
        raise HTTPException(status_code=404, detail=f"Original file {finding['file']} not found")

    original_code = original_file.read_text(encoding="utf-8")

    # Check working copy or construct patched version
    working_dir = PROJECTS_DIR / f"{project_id}_working"
    patched_file = working_dir / finding["file"] if working_dir.exists() else None

    if patched_file and patched_file.exists():
        patched_code = patched_file.read_text(encoding="utf-8")
    else:
        # If not yet written to working copy, generate patched code from known patch
        if func_name in KNOWN_PATCHES:
            old_c, new_c = KNOWN_PATCHES[func_name]
            patched_code = original_code.replace(old_c, new_c)
        else:
            patched_code = original_code

    checks_script = Path(project["project_path"]) / "checks.py"
    if not checks_script.exists():
        checks_script = FIXTURES_DIR / "demo_notes_app" / "checks.py"

    ver_res = verify_single_patch(
        original_code,
        patched_code,
        func_name,
        checks_script,
        file_rel_path=finding.get("file", "app.py"),
        rule_key=finding.get("rule", ""),
        line_number=finding.get("line", 1)
    )

    # Update finding in stored scan
    finding["exploit_before"] = ver_res["exploit_before"]
    finding["exploit_after"] = ver_res["exploit_after"]
    finding["rescan_clean"] = ver_res["rescan_clean"]
    finding["fixed"] = ver_res["status"] == "fixed_verified"
    finding["verified_status"] = "fixed_verified" if ver_res["status"] == "fixed_verified" else "unverified"

    # Recalculate summary
    fixed_count = sum(1 for f in scan_res["findings"] if f.get("fixed", False))
    confirmed_count = scan_res["summary"]["confirmed"]
    scan_res["summary"]["fixed"] = fixed_count
    
    if fixed_count == confirmed_count and confirmed_count > 0:
        scan_res["summary"]["safety_rating"] = "All confirmed flaws verified & fixed! 100% safe."
        scan_res["summary"]["safety_percentage"] = 100
    else:
        scan_res["summary"]["safety_percentage"] = int(25 + (75 * (fixed_count / max(1, confirmed_count))))
        scan_res["summary"]["safety_rating"] = f"{fixed_count}/{confirmed_count} issues verified & fixed"

    save_scan(scan_res)

    return VerificationResult(
        finding_id=finding_id,
        status=ver_res["status"],
        exploit_before=ver_res["exploit_before"],
        exploit_after=ver_res["exploit_after"],
        rescan_clean=ver_res["rescan_clean"],
        regressions=ver_res["regressions"],
        all_regressions_passed=ver_res["all_regressions_passed"],
        proof_summary=ver_res["proof_summary"],
        proof_steps=ver_res["proof_steps"]
    )
