from pathlib import Path
from fastapi import APIRouter, HTTPException
from app.config import PROJECTS_DIR
from app.database import get_project_by_id, get_latest_scan_for_project, save_patch_record, save_scan
from app.models.schemas import PatchApplyRequest, PatchApplyResponse
from app.services.patch_service import create_isolated_working_copy, apply_patch_to_file
from app.routers.scan import KNOWN_PATCHES

router = APIRouter(prefix="/api/patch", tags=["patch"])

@router.post("/apply", response_model=PatchApplyResponse)
async def apply_patch(req: PatchApplyRequest):
    project = get_project_by_id(req.project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    if not req.confirm_isolated_copy:
        raise HTTPException(
            status_code=400,
            detail="User confirmation is required to apply the patch to an isolated working copy."
        )

    scan_res = get_latest_scan_for_project(req.project_id)
    if not scan_res:
        raise HTTPException(status_code=400, detail="Please run a scan before applying patches.")

    finding = next((f for f in scan_res["findings"] if f["id"] == req.finding_id), None)
    if not finding:
        raise HTTPException(status_code=404, detail=f"Finding {req.finding_id} not found in latest scan")

    func_name = finding["function"]
    old_code = None
    new_code = None
    if func_name in KNOWN_PATCHES:
        old_code, new_code = KNOWN_PATCHES[func_name]
    elif finding.get("patch_original") and finding.get("patch_corrected"):
        old_code = finding["patch_original"]
        new_code = finding["patch_corrected"]

    if not old_code or not new_code:
        raise HTTPException(status_code=400, detail=f"No defensive patch recipe available for {func_name}")

    # Create isolated working directory
    original_project_dir = Path(project["project_path"])
    working_dir = PROJECTS_DIR / f"{req.project_id}_working"
    
    if not working_dir.exists():
        create_isolated_working_copy(original_project_dir, working_dir)

    target_file = working_dir / finding["file"]
    success, message, diff = apply_patch_to_file(
        target_file,
        old_code,
        new_code,
        line_number=finding.get("line")
    )
    
    if not success:
        raise HTTPException(status_code=400, detail=message)

    # Update finding in stored scan
    finding["diff"] = diff
    finding["verified_status"] = "patch_suggested"
    save_scan(scan_res)

    # Save patch record
    patch_data = {
        "id": f"patch-{req.finding_id}",
        "project_id": req.project_id,
        "finding_id": req.finding_id,
        "status": "applied_to_working_copy",
        "patch_diff": diff,
        "patch_explanation": finding.get("patch_plain_english", ""),
        "approved_at": None,
        "verified_at": None,
        "verification_data": {}
    }
    save_patch_record(patch_data)

    return PatchApplyResponse(
        finding_id=req.finding_id,
        success=True,
        message="Patch applied safely to isolated working copy. Your original code is untouched.",
        diff=diff,
        applied_to_working_copy=True,
        status="patch_applied"
    )
