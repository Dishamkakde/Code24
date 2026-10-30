import difflib
import shutil
from pathlib import Path
from typing import Dict, Any, List, Tuple

def create_unified_diff(original_text: str, patched_text: str, filename: str = "app.py") -> str:
    original_lines = original_text.splitlines(keepends=True)
    patched_lines = patched_text.splitlines(keepends=True)
    diff = difflib.unified_diff(
        original_lines,
        patched_lines,
        fromfile=f"a/{filename}",
        tofile=f"b/{filename}"
    )
    return "".join(diff)

def build_side_by_side_diff(original_snippet: str, corrected_snippet: str) -> Dict[str, Any]:
    orig_lines = original_snippet.strip().splitlines()
    corr_lines = corrected_snippet.strip().splitlines()
    return {
        "original_lines": [{"line": i + 1, "text": line, "type": "removed"} for i, line in enumerate(orig_lines)],
        "corrected_lines": [{"line": i + 1, "text": line, "type": "added"} for i, line in enumerate(corr_lines)]
    }

def create_isolated_working_copy(original_project_dir: Path, working_dir: Path) -> Path:
    """Copies the project into an isolated sandbox to ensure original user code is untouched."""
    if working_dir.exists():
        shutil.rmtree(working_dir)
    shutil.copytree(original_project_dir, working_dir)
    return working_dir

from typing import Optional

def apply_patch_to_file(
    file_path: Path,
    old_code: str,
    new_code: str,
    line_number: Optional[int] = None
) -> Tuple[bool, str, str]:
    if not file_path.exists():
        return False, f"File {file_path.name} not found in working copy", ""
    
    content = file_path.read_text(encoding="utf-8", errors="ignore")
    
    # 1. Exact direct substring match
    if old_code and old_code in content:
        patched_content = content.replace(old_code, new_code, 1)
        diff = create_unified_diff(content, patched_content, file_path.name)
        file_path.write_text(patched_content, encoding="utf-8")
        return True, "Patch applied successfully to working copy", diff

    lines = content.splitlines(keepends=True)

    # 2. Line-targeted match if line_number is provided
    if line_number and 1 <= line_number <= len(lines):
        target_idx = line_number - 1
        orig_line = lines[target_idx]
        indent = len(orig_line) - len(orig_line.lstrip())
        indent_str = orig_line[:indent]
        
        # Format replacement with same leading indentation
        new_formatted = "".join(
            (indent_str + l.lstrip() if l.strip() else l) + ("\n" if not l.endswith("\n") else "")
            for l in new_code.splitlines()
        )
        lines[target_idx] = new_formatted
        patched_content = "".join(lines)
        diff = create_unified_diff(content, patched_content, file_path.name)
        file_path.write_text(patched_content, encoding="utf-8")
        return True, "Patch applied successfully to working copy (line-targeted)", diff

    # 3. Fuzzy match by stripped snippet
    if old_code:
        stripped_old = old_code.strip()
        for idx, l in enumerate(lines):
            if stripped_old in l or l.strip() == stripped_old:
                indent = len(l) - len(l.lstrip())
                indent_str = l[:indent]
                lines[idx] = indent_str + new_code.strip() + "\n"
                patched_content = "".join(lines)
                diff = create_unified_diff(content, patched_content, file_path.name)
                file_path.write_text(patched_content, encoding="utf-8")
                return True, "Patch applied successfully to working copy", diff

    return False, f"Target code snippet could not be safely anchored in {file_path.name}", ""
