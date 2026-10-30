from datetime import datetime
from typing import Dict, Any, Optional
from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse
from app.database import get_project_by_id, get_latest_scan_for_project, get_scan_by_id

router = APIRouter(prefix="/api/reports", tags=["reports"])

def build_report_data(project: Dict[str, Any], scan_res: Dict[str, Any]) -> Dict[str, Any]:
    summary = scan_res.get("summary") or {}
    findings = scan_res.get("findings") or []
    regressions = scan_res.get("regressions", {})
    env = scan_res.get("project_environment") or {}
    attack_meta = scan_res.get("attack_dataset_metadata") or {}

    return {
        "title": "DAMage CTRL Security Audit & Remediation Verification Report",
        "generated_at": datetime.now().strftime("%B %d, %Y - %H:%M:%S"),
        "scan_id": scan_res.get("id"),
        "project": {
            "id": project["id"],
            "name": project["name"],
            "source_type": project["source_type"],
            "languages": project.get("languages", []),
            "frameworks": project.get("frameworks", []),
            "file_count": project.get("file_count", 0),
            "line_count": project.get("line_count", 0),
        },
        "executive_summary": {
            "total_candidates": summary.get("candidates", len(findings)),
            "confirmed_exploitable": summary.get("confirmed", 0),
            "false_positives_filtered": summary.get("false_positives", 0),
            "fixes_verified": summary.get("fixed", 0),
            "regression_suite_pass_rate": f"{summary.get('regressions_passed', 1)}/{summary.get('regressions_total', 1)}",
            "safety_rating": summary.get("safety_rating", "Evaluated"),
            "safety_percentage": summary.get("safety_percentage", 100),
        },
        "environment": env,
        "attack_metadata": attack_meta,
        "findings": findings,
        "regressions": regressions,
        "disclaimer": (
            "DAMage CTRL analyzes source code and isolates security vulnerabilities using real scanner engines "
            "(Semgrep, Bandit, pip-audit, npm-audit). Confirmed remediations are proven against isolated test fixtures. "
            "However, automated security scanners cannot guarantee immunity against all unknown zero-day vulnerabilities."
        )
    }

@router.get("/scan/{scan_id}")
async def get_report_by_scan_id(scan_id: str):
    """Retrieves full audit report data for a specific scan ID from SQLite."""
    scan = get_scan_by_id(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan record not found")

    project = get_project_by_id(scan["project_id"])
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    return build_report_data(project, scan)

@router.get("/{project_id}")
async def get_report_data(project_id: str):
    """Retrieves the latest audit report data for a project from SQLite."""
    project = get_project_by_id(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    scan_res = get_latest_scan_for_project(project_id)
    if not scan_res:
        raise HTTPException(status_code=404, detail="No scan data found for this project")

    return build_report_data(project, scan_res)

@router.get("/{project_id}/html", response_class=HTMLResponse)
async def get_report_printable_html(project_id: str):
    """Generates an executive-ready printable HTML report with evidence-based classifications."""
    data = await get_report_data(project_id)
    p = data["project"]
    s = data["executive_summary"]
    findings = data["findings"]

    findings_html = ""
    for f in findings:
        status_badge = (
            '<span class="badge badge-danger">CONFIRMED EXPLOITABLE</span>'
            if f.get("status") == "confirmed"
            else '<span class="badge badge-success">FALSE ALARM (FILTERED)</span>'
        )
        verified_badge = (
            '<span class="badge badge-success">PATCH VERIFIED & PROVEN</span>'
            if f.get("fixed")
            else '<span class="badge badge-warning">NOT YET PATCHED</span>'
        )

        classif = f.get("classification") or {}
        cwe_obj = classif.get("cwe") or {}
        owasp_obj = classif.get("owasp") or {}
        attack_obj = classif.get("attack") or {}
        cvss_obj = classif.get("cvss") or {}

        cwe_text = cwe_obj.get("id") or f.get("cwe") or "CWE-20"
        owasp_text = f"OWASP {owasp_obj.get('code')}" if owasp_obj.get("code") else ""
        attack_text = f"ATT&CK {attack_obj.get('technique_id')}" if attack_obj.get("technique_id") else "ATT&CK: N/A"
        cvss_val = cvss_obj.get("score") if cvss_obj.get("score") is not None else f.get("cvss", 0.0)
        cvss_type = cvss_obj.get("source_type", "calculated").upper()

        diff_section = ""
        if f.get("diff"):
            diff_lines = ""
            for line in f["diff"].splitlines():
                cls = "diff-add" if line.startswith("+") and not line.startswith("+++") else "diff-del" if line.startswith("-") and not line.startswith("---") else "diff-hunk" if line.startswith("@@") else ""
                diff_lines += f'<div class="{cls}">{line}</div>'
            diff_section = f"""
            <div class="section-title">Defensive Patch Diff</div>
            <pre class="code-box">{diff_lines}</pre>
            """

        traceability = classif.get("traceability_statement") or f.get("patch_rationale") or ""

        findings_html += f"""
        <div class="finding-card">
            <div class="finding-header">
                <div>
                    <span class="finding-id">{f.get('id', 'FIND')}</span>
                    <strong>{f.get('title', 'Security Finding')}</strong>
                </div>
                <div>
                    {status_badge}
                    {verified_badge}
                </div>
            </div>
            <div class="meta-row">
                <span><strong>File:</strong> {f.get('file')}:{f.get('line')}</span>
                <span><strong>Scanner:</strong> {f.get('scanner_name', 'Semgrep')}</span>
                <span><strong>CWE:</strong> {cwe_text}</span>
                {f'<span><strong>OWASP:</strong> {owasp_text}</span>' if owasp_text else ''}
                <span><strong>{attack_text}</strong></span>
                <span><strong>CVSS:</strong> {cvss_val:.1f} [{cvss_type}]</span>
            </div>
            {f'<div class="section-title">Everyday Analogy (ELI12)</div><p class="analogy-box"><em>{f["eli12"]["analogy_title"]}:</em> {f["eli12"]["analogy_story"]}</p>' if f.get('eli12') else ''}
            <div class="section-title">Affected Code Snippet</div>
            <pre class="code-box">{f.get('snippet', '')}</pre>
            <div class="section-title">Evidence & Traceability</div>
            <p style="font-size: 13px; color: #334155;">{traceability}</p>
            {diff_section}
        </div>
        """

    html = f"""<!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <title>{data['title']} - {p['name']}</title>
        <style>
            @media print {{
                body {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
                .no-print {{ display: none; }}
                .page-break {{ page-break-after: always; }}
            }}
            body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #fff; color: #1e293b; margin: 0; padding: 40px; line-height: 1.5; }}
            .header {{ border-bottom: 2px solid #e2e8f0; padding-bottom: 20px; margin-bottom: 24px; display: flex; justify-content: space-between; align-items: center; }}
            .brand {{ font-size: 26px; font-weight: 800; color: #0f172a; }}
            .brand span {{ color: #2563eb; }}
            .stats-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin: 24px 0; }}
            .stat-box {{ background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 12px; padding: 16px; text-align: center; }}
            .stat-box .num {{ font-size: 28px; font-weight: 800; color: #0f172a; }}
            .stat-box .lbl {{ font-size: 13px; color: #64748b; text-transform: uppercase; font-weight: 600; margin-top: 4px; }}
            .finding-card {{ border: 1px solid #e2e8f0; border-radius: 12px; padding: 20px; margin-bottom: 24px; background: #fff; }}
            .finding-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }}
            .finding-id {{ background: #eff6ff; color: #2563eb; font-weight: 700; padding: 3px 8px; border-radius: 6px; margin-right: 8px; }}
            .badge {{ font-size: 12px; font-weight: 700; padding: 4px 10px; border-radius: 9999px; display: inline-block; margin-left: 6px; }}
            .badge-danger {{ background: #fef2f2; color: #ef4444; border: 1px solid #fecaca; }}
            .badge-success {{ background: #ecfdf5; color: #10b981; border: 1px solid #a7f3d0; }}
            .badge-warning {{ background: #fffbeb; color: #f59e0b; border: 1px solid #fde68a; }}
            .meta-row {{ display: flex; flex-wrap: wrap; gap: 16px; font-size: 13px; color: #475569; margin-bottom: 12px; padding-bottom: 8px; border-bottom: 1px dashed #e2e8f0; }}
            .section-title {{ font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em; font-weight: 700; color: #64748b; margin: 12px 0 4px; }}
            .analogy-box {{ background: #f0fdf4; border-left: 4px solid #10b981; padding: 12px 16px; border-radius: 0 8px 8px 0; margin: 6px 0 12px; font-size: 14px; color: #166534; }}
            .code-box {{ background: #0f172a; color: #f8fafc; padding: 12px; border-radius: 8px; font-family: monospace; font-size: 13px; overflow-x: auto; }}
            .diff-add {{ color: #4ade80; }}
            .diff-del {{ color: #f87171; }}
            .diff-hunk {{ color: #60a5fa; }}
            .disclaimer-box {{ background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; font-size: 13px; color: #64748b; margin-top: 40px; }}
            .btn-print {{ background: #0f172a; color: #fff; border: none; padding: 10px 20px; border-radius: 8px; font-weight: 700; cursor: pointer; }}
        </style>
    </head>
    <body>
        <div class="header">
            <div>
                <div class="brand">DAMage <span>CTRL</span></div>
                <div style="color: #64748b; font-size: 14px; margin-top: 4px;">Find the Flaw. Prove the Fix.</div>
            </div>
            <div class="no-print">
                <button class="btn-print" onclick="window.print()">Print / Save as PDF</button>
            </div>
        </div>

        <h2>Security Audit & Remediation Report</h2>
        <div style="font-size: 14px; color: #64748b;">
            Project: <strong>{p['name']}</strong> &bull; Generated: {data['generated_at']} &bull; Languages: {', '.join(p['languages'])}
        </div>

        <div class="stats-grid">
            <div class="stat-box">
                <div class="num">{s['total_candidates']}</div>
                <div class="lbl">Candidates Found</div>
            </div>
            <div class="stat-box">
                <div class="num" style="color: #ef4444;">{s['confirmed_exploitable']}</div>
                <div class="lbl">Confirmed Flaws</div>
            </div>
            <div class="stat-box">
                <div class="num" style="color: #10b981;">{s['false_positives_filtered']}</div>
                <div class="lbl">False Alarms Dismissed</div>
            </div>
            <div class="stat-box">
                <div class="num" style="color: #2563eb;">{s['fixes_verified']}</div>
                <div class="lbl">Fixes Verified & Proven</div>
            </div>
        </div>

        <h3>Detailed Findings & Evidence Traceability</h3>
        {findings_html}

        <div class="disclaimer-box">
            <strong>Important Notice:</strong> {data['disclaimer']}
        </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html)
