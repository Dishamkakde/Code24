import type { ProjectInfo, ScanResult, VerificationResult, LearnConcept } from '../types';

const API_BASE = 'http://127.0.0.1:8000/api';

export async function loadDemoProject(): Promise<ProjectInfo> {
  const res = await fetch(`${API_BASE}/projects/load-demo`, { method: 'POST' });
  if (!res.ok) throw new Error((await res.json()).detail || 'Failed to load demo project');
  return res.json();
}

export async function uploadZipProject(file: File): Promise<ProjectInfo> {
  const formData = new FormData();
  formData.append('file', file);
  const res = await fetch(`${API_BASE}/projects/upload-zip`, {
    method: 'POST',
    body: formData,
  });
  if (!res.ok) throw new Error((await res.json()).detail || 'Failed to upload ZIP archive');
  return res.json();
}

export async function importGithubProject(repoUrl: string): Promise<ProjectInfo> {
  const res = await fetch(`${API_BASE}/projects/import-github`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ repo_url: repoUrl }),
  });
  if (!res.ok) throw new Error((await res.json()).detail || 'Failed to import GitHub repository');
  return res.json();
}

export async function scanWebsiteUrl(url: string): Promise<ProjectInfo> {
  const res = await fetch(`${API_BASE}/projects/scan-url`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url }),
  });
  if (!res.ok) throw new Error((await res.json()).detail || 'Failed to analyze website URL');
  return res.json();
}

export async function listProjects(): Promise<ProjectInfo[]> {
  const res = await fetch(`${API_BASE}/projects`);
  if (!res.ok) throw new Error('Failed to fetch projects history');
  return res.json();
}

export async function getProject(projectId: string): Promise<ProjectInfo> {
  const res = await fetch(`${API_BASE}/projects/${projectId}`);
  if (!res.ok) throw new Error('Failed to fetch project details');
  return res.json();
}

export async function startScan(projectId: string): Promise<{ id: string; scan_id: string; project_id: string; status: string; started_at: string; message: string }> {
  const res = await fetch(`${API_BASE}/scan/start/${projectId}`, { method: 'POST' });
  if (!res.ok) throw new Error((await res.json()).detail || 'Failed to start background scan');
  return res.json();
}

export async function getScanStatus(scanId: string): Promise<{
  scan_id: string;
  project_id: string;
  status: string;
  started_at?: string;
  completed_at?: string;
  error_message?: string;
  findings_count: number;
  safety_percentage: number;
  safety_rating: string;
}> {
  const res = await fetch(`${API_BASE}/scan/status/${scanId}`);
  if (!res.ok) throw new Error((await res.json()).detail || 'Failed to fetch scan status');
  return res.json();
}

export async function getScanFindings(scanId: string): Promise<any[]> {
  const res = await fetch(`${API_BASE}/scan/${scanId}/findings`);
  if (!res.ok) throw new Error((await res.json()).detail || 'Failed to fetch scan findings');
  return res.json();
}

export async function getProjectFindings(projectId: string): Promise<any[]> {
  const res = await fetch(`${API_BASE}/scan/project/${projectId}/findings`);
  if (!res.ok) throw new Error((await res.json()).detail || 'Failed to fetch project findings');
  return res.json();
}

export async function scanProject(projectId: string): Promise<ScanResult> {
  const res = await fetch(`${API_BASE}/scan/${projectId}?wait=true`, { method: 'POST' });
  if (!res.ok) throw new Error((await res.json()).detail || 'Failed to run security analysis');
  return res.json();
}

export async function applyPatch(projectId: string, findingId: string): Promise<{ success: boolean; message: string; diff: string }> {
  const res = await fetch(`${API_BASE}/patch/apply`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      project_id: projectId,
      finding_id: findingId,
      confirm_isolated_copy: true,
    }),
  });
  if (!res.ok) throw new Error((await res.json()).detail || 'Failed to apply defensive patch');
  return res.json();
}

export async function verifyPatch(projectId: string, findingId: string): Promise<VerificationResult> {
  const res = await fetch(`${API_BASE}/verify/${projectId}/${findingId}`, { method: 'POST' });
  if (!res.ok) throw new Error((await res.json()).detail || 'Failed to verify patch');
  return res.json();
}

export async function getLearnConcepts(): Promise<LearnConcept[]> {
  const res = await fetch(`${API_BASE}/learn`);
  if (!res.ok) throw new Error('Failed to load learning concepts');
  return res.json();
}

export async function updateProjectFrameworks(projectId: string, frameworks: string[]): Promise<ProjectInfo> {
  const res = await fetch(`${API_BASE}/projects/${projectId}/frameworks`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ frameworks }),
  });
  if (!res.ok) throw new Error('Failed to update frameworks');
  return res.json();
}

export function getPatchedZipDownloadUrl(projectId: string): string {
  return `${API_BASE}/projects/${projectId}/download-patched`;
}

export function getPrintableReportUrl(projectId: string): string {
  return `${API_BASE}/reports/${projectId}/html`;
}
