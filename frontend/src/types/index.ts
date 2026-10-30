export interface FileItem {
  path: string;
  size: number;
  lines: number;
  language: string;
}

export interface ProjectInfo {
  id: string;
  name: string;
  source_type: 'upload' | 'github' | 'demo';
  created_at: string;
  file_count: number;
  line_count: number;
  languages: string[];
  frameworks: string[];
  files?: FileItem[];
  status: string;
  latest_scan?: ScanResult;
}

export interface ELI12Content {
  analogy_title: string;
  analogy_story: string;
  simple_explanation: string;
  icon_name: string;
}

export interface FiveSections {
  what: string;
  why: string;
  where: string;
  how: string;
  proof: string;
}

export interface ScannerExecutionRecord {
  scanner_name: string;
  scanner_version?: string | null;
  status: string;
  exit_code?: number | null;
  duration_seconds: number;
  command: string[];
  raw_stdout?: string | null;
  raw_stderr?: string | null;
  error_message?: string | null;
  findings_count: number;
}

export interface ProjectEnvironment {
  languages: string[];
  frameworks: string[];
  manifests: string[];
  applicable_scanners: string[];
  total_files: number;
  total_lines: number;
}

export interface CVSSInfo {
  score?: number | null;
  vector?: string | null;
  version: string;
  source_type: 'sourced' | 'calculated' | 'none';
  source_authority?: string | null;
  rationale?: string | null;
}

export interface CWEClassification {
  id: string;
  name: string;
  description: string;
  source: string;
  url: string;
}

export interface OWASPClassification {
  code: string;
  category: string;
  year: number;
  justification: string;
  url: string;
}

export interface AttackTechniqueMapping {
  technique_id: string;
  subtechnique_id?: string | null;
  technique_name: string;
  tactics: string[];
  mapping_relationship: string;
  defensible_reasoning: string;
  confidence: string;
  stix_source: string;
  url: string;
}

export interface CVEClassification {
  cve_id: string;
  package_name: string;
  declared_version: string;
  affected_range?: string | null;
  advisory_source: string;
  advisory_url: string;
  summary?: string | null;
}

export interface ScannerClassification {
  scanner_name: string;
  scanner_rule_id: string;
  scanner_reported_cwe?: string | null;
  scanner_severity?: string | null;
  scanner_confidence?: string | null;
  scanner_message: string;
}

export interface EvidenceBasedClassification {
  scanner_classification: ScannerClassification;
  cwe: CWEClassification;
  owasp?: OWASPClassification | null;
  attack?: AttackTechniqueMapping | null;
  cve?: CVEClassification | null;
  cvss: CVSSInfo;
  traceability_statement: string;
}

export interface Finding {
  id: string;
  rule: string;
  cwe: string;
  title: string;
  technical_title: string;
  severity: 'Urgent' | 'Important' | 'Needs attention' | 'Info';
  severity_level: number;
  status: 'confirmed' | 'false_positive' | 'suspected_pattern';
  cvss: number;
  file: string;
  function: string;
  line: number;
  end_line: number;
  snippet: string;
  eli12: ELI12Content;
  five_sections: FiveSections;
  diff: string;
  patch_original: string;
  patch_corrected: string;
  patch_rationale: string;
  patch_plain_english: string;
  exploit_name: string;
  exploit_before?: boolean | null;
  exploit_after?: boolean | null;
  rescan_clean?: boolean | null;
  fixed: boolean;
  verified_status: 'unpatched' | 'patch_suggested' | 'fixed_verified' | 'false_positive';
  // Scanner Engine fields
  scanner_name?: string;
  scanner_version?: string | null;
  rule_identifier?: string | null;
  confidence?: string | null;
  cwe_identifiers?: string[];
  relevant_references?: string[];
  source_evidence?: string | null;
  why_matched?: string | null;
  remediation_guidance?: string | null;
  classification?: EvidenceBasedClassification;
}

export interface ScanSummary {
  candidates: number;
  confirmed: number;
  false_positives: number;
  fixed: number;
  regressions_passed: number;
  regressions_total: number;
  safety_rating: string;
  safety_percentage: number;
}

export interface ScanResult {
  id: string;
  project_id: string;
  scanned_at: string;
  summary: ScanSummary;
  findings: Finding[];
  regressions: {
    before: Record<string, boolean>;
    after: Record<string, boolean>;
  };
  languages_detected: string[];
  frameworks_detected: string[];
  scanner_reports?: ScannerExecutionRecord[];
  project_environment?: ProjectEnvironment;
  attack_dataset_metadata?: Record<string, any>;
}

export interface VerificationProofStep {
  step: string;
  label: string;
  result: string;
  passed: boolean;
  detail: string;
}

export interface VerificationResult {
  finding_id: string;
  status: 'fixed_verified' | 'failed' | 'unverified';
  exploit_before: boolean;
  exploit_after: boolean;
  rescan_clean: boolean;
  regressions: Record<string, boolean>;
  all_regressions_passed: boolean;
  proof_summary: string;
  proof_steps: VerificationProofStep[];
}

export interface LearnConcept {
  id: string;
  title: string;
  cwe: string;
  analogy_title: string;
  analogy: string;
  why_it_happens: string;
  how_to_prevent: string;
  simple_example_bad: string;
  simple_example_good: string;
  icon: string;
}
