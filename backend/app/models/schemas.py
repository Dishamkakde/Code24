from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional

class FileItem(BaseModel):
    path: str
    size: int
    lines: int
    language: str

class ProjectInfo(BaseModel):
    id: str
    name: str
    source_type: str  # 'upload', 'github', 'demo'
    created_at: str
    file_count: int
    line_count: int
    languages: List[str]
    frameworks: List[str]
    files: Optional[List[FileItem]] = None
    status: str = "ready"

class ELI12Content(BaseModel):
    analogy_title: str
    analogy_story: str
    simple_explanation: str
    icon_name: str = "Shield"

class FiveSections(BaseModel):
    what: str
    why: str
    where: str
    how: str
    proof: str

class ScannerExecutionRecord(BaseModel):
    scanner_name: str
    scanner_version: Optional[str] = None
    status: str  # success, failed, timed_out, skipped_no_manifest, unsupported_language, missing_dependency
    exit_code: Optional[int] = None
    duration_seconds: float = 0.0
    command: List[str] = Field(default_factory=list)
    raw_stdout: Optional[str] = None
    raw_stderr: Optional[str] = None
    error_message: Optional[str] = None
    findings_count: int = 0

class ProjectEnvironment(BaseModel):
    languages: List[str] = Field(default_factory=list)
    frameworks: List[str] = Field(default_factory=list)
    manifests: List[str] = Field(default_factory=list)
    applicable_scanners: List[str] = Field(default_factory=list)
    total_files: int = 0
    total_lines: int = 0

class CVSSInfo(BaseModel):
    score: Optional[float] = None
    vector: Optional[str] = None
    version: str = "3.1"
    source_type: str = "calculated"  # sourced, calculated, none
    source_authority: Optional[str] = None
    rationale: Optional[str] = None

class CWEClassification(BaseModel):
    id: str
    name: str
    description: str
    source: str = "curated_mapping"  # scanner_reported, curated_mapping
    url: str

class OWASPClassification(BaseModel):
    code: str
    category: str
    year: int = 2021
    justification: str
    url: str

class AttackTechniqueMapping(BaseModel):
    technique_id: str
    subtechnique_id: Optional[str] = None
    technique_name: str
    tactics: List[str] = Field(default_factory=list)
    mapping_relationship: str  # enables_technique, direct_adversary_behavior
    defensible_reasoning: str
    confidence: str = "HIGH"
    stix_source: str = "MITRE ATT&CK Enterprise v15.1"
    url: str

class CVEClassification(BaseModel):
    cve_id: str
    package_name: str
    declared_version: str
    affected_range: Optional[str] = None
    advisory_source: str
    advisory_url: str
    summary: Optional[str] = None

class ScannerClassification(BaseModel):
    scanner_name: str
    scanner_rule_id: str
    scanner_reported_cwe: Optional[str] = None
    scanner_severity: Optional[str] = None
    scanner_confidence: Optional[str] = None
    scanner_message: str

class EvidenceBasedClassification(BaseModel):
    scanner_classification: ScannerClassification
    cwe: CWEClassification
    owasp: Optional[OWASPClassification] = None
    attack: Optional[AttackTechniqueMapping] = None
    cve: Optional[CVEClassification] = None
    cvss: CVSSInfo
    traceability_statement: str

class Finding(BaseModel):
    id: str
    rule: str
    cwe: str
    title: str
    technical_title: str
    severity: str  # Urgent, Important, Needs attention, Info
    severity_level: int  # 3=Urgent, 2=Important, 1=Needs attention, 0=Info
    status: str    # suspected_pattern, confirmed, false_positive
    cvss: float
    file: str
    function: str
    line: int
    end_line: int
    snippet: str
    eli12: ELI12Content
    five_sections: FiveSections
    diff: str
    patch_original: str
    patch_corrected: str
    patch_rationale: str
    patch_plain_english: str
    exploit_name: str
    exploit_before: Optional[bool] = None
    exploit_after: Optional[bool] = None
    rescan_clean: Optional[bool] = None
    fixed: bool = False
    verified_status: str = "unpatched" # unpatched, patch_suggested, fixed_verified, false_positive
    # Normalized Scanner Engine fields
    scanner_name: str = "semgrep"
    scanner_version: Optional[str] = None
    rule_identifier: Optional[str] = None
    confidence: Optional[str] = "MEDIUM" # HIGH, MEDIUM, LOW
    cwe_identifiers: List[str] = Field(default_factory=list)
    relevant_references: List[str] = Field(default_factory=list)
    source_evidence: Optional[str] = None
    why_matched: Optional[str] = None
    remediation_guidance: Optional[str] = None
    classification: Optional[EvidenceBasedClassification] = None

class ScanSummary(BaseModel):
    candidates: int
    confirmed: int
    false_positives: int
    fixed: int
    regressions_passed: int
    regressions_total: int
    safety_rating: str  # e.g., "Good start - 3 fixes ready", "All verified safe"
    safety_percentage: int

class ScanResult(BaseModel):
    id: str
    project_id: str
    scanned_at: str
    summary: ScanSummary
    findings: List[Finding]
    regressions: Dict[str, Dict[str, bool]]
    languages_detected: List[str]
    frameworks_detected: List[str]
    scanner_reports: List[ScannerExecutionRecord] = Field(default_factory=list)
    project_environment: Optional[ProjectEnvironment] = None
    attack_dataset_metadata: Optional[Dict[str, Any]] = None

class PatchApplyRequest(BaseModel):
    project_id: str
    finding_id: str
    confirm_isolated_copy: bool = True

class PatchApplyResponse(BaseModel):
    finding_id: str
    success: bool
    message: str
    diff: str
    applied_to_working_copy: bool
    status: str

class VerificationRequest(BaseModel):
    project_id: str
    finding_id: str

class VerificationResult(BaseModel):
    finding_id: str
    status: str  # fixed_verified, failed, unverified
    exploit_before: bool
    exploit_after: bool
    rescan_clean: bool
    regressions: Dict[str, bool]
    all_regressions_passed: bool
    proof_summary: str
    proof_steps: List[Dict[str, Any]]

class GitHubImportRequest(BaseModel):
    repo_url: str

class LearnConcept(BaseModel):
    id: str
    title: str
    cwe: str
    analogy_title: str
    analogy: str
    why_it_happens: str
    how_to_prevent: str
    simple_example_bad: str
    simple_example_good: str
    icon: str
