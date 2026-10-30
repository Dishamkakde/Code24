import shutil
import uuid
import zipfile
from datetime import datetime
from pathlib import Path
from pydantic import BaseModel
from fastapi import APIRouter, UploadFile, File, HTTPException
from fastapi.responses import FileResponse
from app.config import PROJECTS_DIR, TEMP_DIR, FIXTURES_DIR
from app.database import save_project, get_all_projects, get_project_by_id, get_latest_scan_for_project
from app.models.schemas import ProjectInfo, GitHubImportRequest
from app.services.zip_service import extract_safe_zip
from app.services.github_service import import_public_github_repo
from app.services.scanner_service import detect_languages_and_frameworks

router = APIRouter(prefix="/api/projects", tags=["projects"])

class UpdateFrameworksRequest(BaseModel):
    frameworks: list[str]

@router.post("/load-demo", response_model=ProjectInfo)
async def load_demo_project():
    project_id = f"demo-{uuid.uuid4().hex[:8]}"
    project_dir = PROJECTS_DIR / project_id
    demo_source = FIXTURES_DIR / "demo_notes_app"
    
    if project_dir.exists():
        shutil.rmtree(project_dir)
    shutil.copytree(demo_source, project_dir)

    languages, frameworks, file_count, line_count, file_items = detect_languages_and_frameworks(project_dir)
    if "SQLite" not in frameworks:
        frameworks.append("SQLite")

    project_data = {
        "id": project_id,
        "name": "Notes & Attachments App (Demonstration)",
        "source_type": "demo",
        "project_path": str(project_dir),
        "created_at": datetime.now().isoformat(),
        "languages": languages or ["Python", "SQL"],
        "frameworks": frameworks or ["SQLite"],
        "file_count": file_count,
        "line_count": line_count,
        "files": file_items,
        "status": "ready"
    }
    save_project(project_data)
    return project_data

@router.post("/upload-zip", response_model=ProjectInfo)
async def upload_zip_project(file: UploadFile = File(...)):
    if not file.filename or not file.filename.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="Uploaded file must be a valid .zip archive.")

    project_id = f"proj-{uuid.uuid4().hex[:8]}"
    project_dir = PROJECTS_DIR / project_id
    temp_zip_path = TEMP_DIR / f"{project_id}_{file.filename}"

    try:
        # Save temp zip
        with open(temp_zip_path, "wb") as f:
            content = await file.read()
            f.write(content)

        success, message, _ = extract_safe_zip(temp_zip_path, project_dir)
        if not success:
            if project_dir.exists():
                shutil.rmtree(project_dir)
            raise HTTPException(status_code=400, detail=message)

        languages, frameworks, file_count, line_count, file_items = detect_languages_and_frameworks(project_dir)

        project_name = Path(file.filename).stem or "Uploaded Project"
        project_data = {
            "id": project_id,
            "name": project_name,
            "source_type": "upload",
            "project_path": str(project_dir),
            "created_at": datetime.now().isoformat(),
            "languages": languages,
            "frameworks": frameworks,
            "file_count": file_count,
            "line_count": line_count,
            "files": file_items,
            "status": "ready"
        }
        save_project(project_data)
        return project_data
    finally:
        if temp_zip_path.exists():
            try:
                temp_zip_path.unlink()
            except Exception:
                pass

@router.post("/import-github", response_model=ProjectInfo)
async def import_github_project(req: GitHubImportRequest):
    project_id = f"gh-{uuid.uuid4().hex[:8]}"
    project_dir = PROJECTS_DIR / project_id

    success, message, _ = import_public_github_repo(req.repo_url, project_dir)
    if not success:
        if project_dir.exists():
            shutil.rmtree(project_dir)
        raise HTTPException(status_code=400, detail=message)

    languages, frameworks, file_count, line_count, file_items = detect_languages_and_frameworks(project_dir)
    repo_name = req.repo_url.strip().rstrip("/").split("/")[-1]

    project_data = {
        "id": project_id,
        "name": f"GitHub: {repo_name}",
        "source_type": "github",
        "project_path": str(project_dir),
        "created_at": datetime.now().isoformat(),
        "languages": languages,
        "frameworks": frameworks,
        "file_count": file_count,
        "line_count": line_count,
        "files": file_items,
        "status": "ready"
    }
    save_project(project_data)
    return project_data

class WebsiteURLRequest(BaseModel):
    url: str

@router.post("/scan-url", response_model=ProjectInfo)
async def scan_website_url(req: WebsiteURLRequest):
    raw_url = req.url.strip()
    if not raw_url:
        raise HTTPException(status_code=400, detail="Please enter a valid website URL.")
    if not (raw_url.startswith("http://") or raw_url.startswith("https://")):
        raw_url = f"https://{raw_url}"

    import json
    import requests
    from urllib.parse import urlparse

    project_id = f"url-{uuid.uuid4().hex[:8]}"
    project_dir = PROJECTS_DIR / project_id
    project_dir.mkdir(parents=True, exist_ok=True)

    headers = {"User-Agent": "PatchProof-Security-Audit/1.0"}
    try:
        r = requests.get(raw_url, headers=headers, timeout=12, allow_redirects=True)
        resp_headers = dict(r.headers)
        status_code = r.status_code
        final_url = str(r.url)
    except Exception as e:
        if project_dir.exists():
            shutil.rmtree(project_dir)
        raise HTTPException(status_code=400, detail=f"Could not connect to {raw_url}: {str(e)}")

    audit_data = {
        "target_url": raw_url,
        "final_url": final_url,
        "status_code": status_code,
        "headers": resp_headers,
        "is_https": final_url.startswith("https://")
    }

    (project_dir / "audit.json").write_text(json.dumps(audit_data, indent=2), encoding="utf-8")

    detected_frameworks = []
    server_h = resp_headers.get("Server", "") or resp_headers.get("server", "")
    powered_by = resp_headers.get("X-Powered-By", "") or resp_headers.get("x-powered-by", "")
    if "nginx" in server_h.lower():
        detected_frameworks.append("Nginx")
    if "apache" in server_h.lower():
        detected_frameworks.append("Apache")
    if "cloudflare" in server_h.lower():
        detected_frameworks.append("Cloudflare")
    if "express" in powered_by.lower():
        detected_frameworks.append("Express.js")
    if "next" in powered_by.lower():
        detected_frameworks.append("Next.js")

    domain = urlparse(final_url).netloc or raw_url

    file_items = [{
        "path": "audit.json",
        "size": len(json.dumps(audit_data)),
        "lines": len(audit_data["headers"]),
        "language": "JSON"
    }]

    project_data = {
        "id": project_id,
        "name": f"Website: {domain}",
        "source_type": "url",
        "project_path": str(project_dir),
        "created_at": datetime.now().isoformat(),
        "languages": ["HTTP", "TLS/SSL"],
        "frameworks": detected_frameworks or ["Web Server"],
        "file_count": 1,
        "line_count": len(audit_data["headers"]),
        "files": file_items,
        "status": "ready"
    }
    save_project(project_data)
    return project_data

@router.get("", response_model=list[dict])
async def list_projects():
    projects = get_all_projects()
    for p in projects:
        latest_scan = get_latest_scan_for_project(p["id"])
        p["latest_scan"] = latest_scan
    return projects

@router.get("/{project_id}")
async def get_project(project_id: str):
    p = get_project_by_id(project_id)
    if not p:
        raise HTTPException(status_code=404, detail="Project not found")
    p["latest_scan"] = get_latest_scan_for_project(project_id)
    return p

@router.put("/{project_id}/frameworks")
async def update_frameworks(project_id: str, req: UpdateFrameworksRequest):
    p = get_project_by_id(project_id)
    if not p:
        raise HTTPException(status_code=404, detail="Project not found")
    p["frameworks"] = req.frameworks
    save_project(p)
    return p

@router.get("/{project_id}/download-patched")
async def download_patched_project(project_id: str):
    p = get_project_by_id(project_id)
    if not p:
        raise HTTPException(status_code=404, detail="Project not found")
    
    project_dir = Path(p["project_path"])
    # If working copy exists, zip that, else zip original
    working_dir = PROJECTS_DIR / f"{project_id}_working"
    source_dir = working_dir if working_dir.exists() else project_dir

    zip_output = TEMP_DIR / f"{p['name']}_patched.zip"
    with zipfile.ZipFile(zip_output, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, _, files in shutil.os.walk(source_dir):
            for file in files:
                file_path = Path(root) / file
                rel_path = file_path.relative_to(source_dir)
                zf.write(file_path, arcname=str(rel_path))

    return FileResponse(
        path=zip_output,
        filename=f"{p['name']}_patched.zip",
        media_type="application/zip"
    )
