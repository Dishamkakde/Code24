import os
import shutil
import zipfile
from pathlib import Path
from typing import Tuple, List, Dict, Any
from app.config import (
    MAX_ZIP_SIZE_BYTES,
    MAX_FILE_COUNT,
    MAX_FILE_SIZE_BYTES,
    SUPPORTED_EXTENSIONS
)

import re

DANGEROUS_EXTENSIONS = {".exe", ".dll", ".so", ".bin", ".pyd", ".dylib", ".bat", ".cmd", ".vbs"}

SECRET_PATTERNS = [
    (re.compile(r'\b(AKIA[0-9A-Z]{16})\b'), "[REDACTED_AWS_KEY]"),
    (re.compile(r'\b(gh[pousr]_[A-Za-z0-9_]{30,255}|github_pat_[A-Za-z0-9_]{22,255})\b'), "[REDACTED_GITHUB_TOKEN]"),
    (re.compile(r'(?i)\bBearer\s+([A-Za-z0-9\-._~+/]{20,}=*)'), "Bearer [REDACTED_BEARER_TOKEN]"),
    (re.compile(r'-----BEGIN (?:[A-Z ]+)PRIVATE KEY-----[\s\S]+?-----END (?:[A-Z ]+)PRIVATE KEY-----'), "[REDACTED_PRIVATE_KEY]"),
    (re.compile(r'(?i)\b(api_key|apikey|secret|password|auth_token)\s*([=:])\s*([\'"][^\'"\s]{8,}[\'"])'), r'\1\2"[REDACTED_SECRET]"')
]

def redact_secrets(text: str) -> str:
    """Redacts API keys, credentials, and tokens from source snippets and logs."""
    if not text or not isinstance(text, str):
        return text
    sanitized = text
    for pattern, replacement in SECRET_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized

def cleanup_temp_dir(path: Path) -> None:
    """Safely cleans up temporary files or directories with error suppression."""
    try:
        if path and path.exists():
            if path.is_file():
                path.unlink(missing_ok=True)
            elif path.is_dir():
                shutil.rmtree(path, ignore_errors=True)
    except Exception:
        pass

def is_safe_path(base_dir: Path, path: Path) -> bool:
    try:
        resolved_base = base_dir.resolve()
        resolved_path = path.resolve()
        return os.path.commonpath([str(resolved_base), str(resolved_path)]) == str(resolved_base)
    except Exception:
        return False

def extract_safe_zip(zip_path: Path, target_dir: Path) -> Tuple[bool, str, List[Dict[str, Any]]]:
    """
    Safely extracts a ZIP archive into target_dir with strict security constraints:
    - Zip Slip / path traversal protection
    - Maximum file count limit
    - Maximum uncompressed file size limit
    - Exclusion of executable/binary payloads
    - Auto-unwraps single top-level directory (common in GitHub repo zips)
    """
    if not zip_path.exists():
        return False, "ZIP file does not exist", []

    file_size = zip_path.stat().st_size
    if file_size > MAX_ZIP_SIZE_BYTES:
        return False, f"ZIP archive exceeds maximum size limit of {MAX_ZIP_SIZE_BYTES / (1024*1024):.1f} MB", []

    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            infolist = zf.infolist()
            if len(infolist) > MAX_FILE_COUNT:
                return False, f"Archive contains too many files ({len(infolist)} > {MAX_FILE_COUNT})", []

            total_uncompressed_bytes = sum(info.file_size for info in infolist)
            if total_uncompressed_bytes > MAX_ZIP_SIZE_BYTES * 6:
                return False, "Archive uncompressed size is excessively large (potential zip bomb)", []

            target_dir.mkdir(parents=True, exist_ok=True)

            for member in infolist:
                # Disallow symlinks or special devices
                if member.is_dir():
                    continue

                # Path normalization and traversal check
                dest_path = target_dir / member.filename
                if not is_safe_path(target_dir, dest_path):
                    continue  # Silently skip malicious directory traversal paths

                # Skip suspicious extensions
                ext = dest_path.suffix.lower()
                if ext in DANGEROUS_EXTENSIONS:
                    continue

                if member.file_size > MAX_FILE_SIZE_BYTES:
                    continue

                # Ensure parent dirs exist
                dest_path.parent.mkdir(parents=True, exist_ok=True)

                # Extract file safely
                with zf.open(member) as source_file, open(dest_path, "wb") as target_file:
                    target_file.write(source_file.read())

        # If the archive contained a single root directory (e.g. repo-master/ or repo-main/), unwrap it
        children = [c for c in target_dir.iterdir()]
        if len(children) == 1 and children[0].is_dir():
            single_sub = children[0]
            temp_swap = target_dir.parent / f"{target_dir.name}_unwrap"
            if temp_swap.exists():
                shutil.rmtree(temp_swap)
            single_sub.rename(temp_swap)
            for item in temp_swap.iterdir():
                shutil.move(str(item), str(target_dir))
            try:
                temp_swap.rmdir()
            except Exception:
                pass

        # Build list of extracted files
        extracted_files: List[Dict[str, Any]] = []
        for root, _, files in os.walk(target_dir):
            if "node_modules" in root or ".git" in root or "__pycache__" in root:
                continue
            for f in files:
                f_path = Path(root) / f
                ext = f_path.suffix.lower()
                rel_path = str(f_path.relative_to(target_dir)).replace("\\", "/")
                lines = 0
                try:
                    if ext in SUPPORTED_EXTENSIONS or not ext:
                        with open(f_path, "r", encoding="utf-8", errors="ignore") as fp:
                            lines = sum(1 for _ in fp)
                except Exception:
                    pass

                extracted_files.append({
                    "path": rel_path,
                    "size": f_path.stat().st_size,
                    "lines": lines,
                    "language": ext.lstrip(".") or "txt"
                })

        return True, "Extracted successfully", extracted_files
    except zipfile.BadZipFile:
        return False, "Corrupted or invalid ZIP file format", []
    except Exception as e:
        return False, f"Error extracting ZIP: {str(e)}", []
