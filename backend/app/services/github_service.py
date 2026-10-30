import re
import requests
from pathlib import Path
from typing import Tuple, List, Dict, Any
from app.config import MAX_ZIP_SIZE_BYTES, TEMP_DIR
from app.services.zip_service import extract_safe_zip

GITHUB_URL_PATTERN = re.compile(r"^https://github\.com/([a-zA-Z0-9_.-]+)/([a-zA-Z0-9_.-]+)(?:/)?$")

def validate_github_url(url: str) -> Tuple[bool, str, str, str]:
    clean_url = url.strip().rstrip("/")
    # Strip .git suffix if present
    if clean_url.endswith(".git"):
        clean_url = clean_url[:-4]
    match = GITHUB_URL_PATTERN.match(clean_url)
    if not match:
        return False, "", "", "Please provide a valid public GitHub URL in the format: https://github.com/owner/repository"
    owner, repo = match.group(1), match.group(2)
    return True, owner, repo, ""

def import_public_github_repo(repo_url: str, target_dir: Path) -> Tuple[bool, str, List[Dict[str, Any]]]:
    valid, owner, repo, err_msg = validate_github_url(repo_url)
    if not valid:
        return False, err_msg, []

    # Attempt main or master branch zip download
    branches = ["main", "master"]
    zip_temp_path = TEMP_DIR / f"{owner}_{repo}.zip"

    headers = {
        "User-Agent": "PatchProof-Security-Companion/1.0"
    }

    downloaded = False
    download_error = ""

    for branch in branches:
        download_url = f"https://github.com/{owner}/{repo}/archive/refs/heads/{branch}.zip"
        try:
            with requests.get(download_url, headers=headers, stream=True, timeout=15) as r:
                if r.status_code == 200:
                    total_downloaded = 0
                    with open(zip_temp_path, "wb") as f:
                        for chunk in r.iter_content(chunk_size=65536):
                            total_downloaded += len(chunk)
                            if total_downloaded > MAX_ZIP_SIZE_BYTES:
                                return False, f"Repository archive exceeds maximum size limit of {MAX_ZIP_SIZE_BYTES / (1024*1024):.1f} MB", []
                            f.write(chunk)
                    downloaded = True
                    break
                elif r.status_code == 404:
                    continue
                else:
                    download_error = f"GitHub returned status code {r.status_code}"
        except requests.exceptions.RequestException as e:
            download_error = f"Network request error: {str(e)}"

    if not downloaded:
        return False, download_error or f"Could not find public repository or branches (main/master) at https://github.com/{owner}/{repo}", []

    try:
        success, message, files = extract_safe_zip(zip_temp_path, target_dir)
        return success, message, files
    finally:
        if zip_temp_path.exists():
            try:
                zip_temp_path.unlink()
            except Exception:
                pass
