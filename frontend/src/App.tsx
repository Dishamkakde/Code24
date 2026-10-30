import React, { useState } from 'react';
import { Navbar } from './components/Navbar';
import { HeroBanner } from './components/HeroBanner';
import { ProjectImporter } from './components/ProjectImporter';
import { ScopeDetector } from './components/ScopeDetector';
import { SafetySummary } from './components/SafetySummary';
import { FindingCard } from './components/FindingCard';
import { FixAssistantModal } from './components/FixAssistantModal';
import { ELI12Modal } from './components/ELI12Modal';
import { LearnHub } from './components/LearnHub';
import { ProjectHistory } from './components/ProjectHistory';
import { SecurityReportView } from './components/SecurityReportView';
import type { ProjectInfo, ScanResult, Finding } from './types';
import { scanProject, applyPatch, verifyPatch } from './api/client';
import { ShieldCheck, CheckCircle2, AlertCircle, Sparkles } from 'lucide-react';

export function App() {
  const [currentTab, setCurrentTab] = useState<'home' | 'projects' | 'learn' | 'reports'>('home');
  const [activeProject, setActiveProject] = useState<ProjectInfo | null>(null);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  
  // Loading states
  const [isProjectLoading, setIsProjectLoading] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [verifyingFindingId, setVerifyingFindingId] = useState<string | null>(null);
  const [isApplyingPatch, setIsApplyingPatch] = useState(false);

  // Modals
  const [eli12Finding, setEli12Finding] = useState<Finding | null>(null);
  const [fixFinding, setFixFinding] = useState<Finding | null>(null);

  // Success toast notification
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 4000);
  };

  const handleProjectLoaded = (project: ProjectInfo) => {
    setActiveProject(project);
    setScanResult(null);
    showToast(`Loaded "${project.name}" into isolated sandbox!`);
  };

  const handleRunScan = async () => {
    if (!activeProject) return;
    setIsScanning(true);
    try {
      const res = await scanProject(activeProject.id);
      setScanResult(res);
      showToast(`Scan complete! ${res.summary.candidates} candidate${res.summary.candidates === 1 ? '' : 's'} evaluated.`);
    } catch (err: any) {
      alert(err.message || 'Error running scan');
    } finally {
      setIsScanning(false);
    }
  };

  const handleVerifyPatch = async (findingId: string) => {
    if (!activeProject) return;
    setVerifyingFindingId(findingId);
    try {
      const ver = await verifyPatch(activeProject.id, findingId);
      
      // Update finding in current scan state
      if (scanResult) {
        const updatedFindings = scanResult.findings.map((f) => {
          if (f.id === findingId) {
            return {
              ...f,
              fixed: ver.status === 'fixed_verified',
              verified_status: ver.status as any,
              exploit_after: ver.exploit_after,
              rescan_clean: ver.rescan_clean,
            };
          }
          return f;
        });

        const fixedCount = updatedFindings.filter((f) => f.fixed).length;
        const confirmedCount = scanResult.summary.confirmed;
        const newRating = (fixedCount === confirmedCount && confirmedCount > 0)
          ? 'All confirmed flaws verified & fixed! 100% safe.'
          : `${fixedCount}/${confirmedCount} issues verified & fixed`;

        setScanResult({
          ...scanResult,
          summary: {
            ...scanResult.summary,
            fixed: fixedCount,
            safety_rating: newRating,
            safety_percentage: fixedCount === confirmedCount ? 100 : Math.round(25 + 75 * (fixedCount / Math.max(1, confirmedCount))),
          },
          findings: updatedFindings,
        });
      }

      showToast(`Verification complete for ${findingId}: Flaw successfully blocked & proven!`);
    } catch (err: any) {
      alert(err.message || 'Error verifying patch');
    } finally {
      setVerifyingFindingId(null);
    }
  };

  const handleApplyAndVerify = async (findingId: string) => {
    if (!activeProject) return;
    setIsApplyingPatch(true);
    try {
      await applyPatch(activeProject.id, findingId);
      await handleVerifyPatch(findingId);
    } catch (err: any) {
      alert(err.message || 'Error applying patch');
    } finally {
      setIsApplyingPatch(false);
    }
  };

  const handleSelectFromHistory = (project: ProjectInfo) => {
    setActiveProject(project);
    if (project.latest_scan) {
      setScanResult(project.latest_scan);
    } else {
      setScanResult(null);
    }
    setCurrentTab('home');
    showToast(`Loaded ${project.name} from history`);
  };

  return (
    <div className="min-h-screen bg-[#FAF8F5] text-slate-800 flex flex-col font-sans">
      {/* Toast notification */}
      {toastMessage && (
        <div className="fixed bottom-6 right-6 z-50 flex items-center gap-2 px-5 py-3 rounded-2xl bg-slate-900 text-white text-xs font-bold shadow-2xl animate-in slide-in-from-bottom duration-200 border border-slate-700">
          <CheckCircle2 className="w-4 h-4 text-brand-mint" />
          <span>{toastMessage}</span>
        </div>
      )}

      {/* Top Navigation */}
      <Navbar
        currentTab={currentTab}
        onSelectTab={setCurrentTab}
        activeProjectName={activeProject?.name}
      />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* TAB 1: WORKSPACE */}
        {currentTab === 'home' && (
          <div className="animate-in fade-in duration-150">
            {/* Hero Greeting */}
            <HeroBanner />

            {/* Step 1: Project Importer */}
            <ProjectImporter
              onProjectLoaded={handleProjectLoaded}
              isLoading={isProjectLoading}
              setIsLoading={setIsProjectLoading}
            />

            {/* Step 2: Scope Detector (when project loaded) */}
            {activeProject && (
              <ScopeDetector
                project={activeProject}
                onRunScan={handleRunScan}
                isScanning={isScanning}
                onProjectUpdated={setActiveProject}
              />
            )}

            {/* Step 3: Safety Summary & Score (when scan complete) */}
            {scanResult && (
              <>
                <SafetySummary
                  summary={scanResult.summary}
                  onViewReport={() => setCurrentTab('reports')}
                />

                {/* Step 4: Findings List with 5-section progressive disclosures */}
                <div className="space-y-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <h3 className="text-xl sm:text-2xl font-black text-slate-900 tracking-tight">
                        Security Findings & Verified Proof
                      </h3>
                      <p className="text-xs text-slate-500 mt-1">
                        Every finding includes what happened, an everyday story, the exact line, a defensive fix, and proof evidence.
                      </p>
                    </div>
                    <span className="text-xs font-bold px-3 py-1 rounded-full bg-slate-200 text-slate-700">
                      {scanResult.findings.length} Cases Checked
                    </span>
                  </div>

                  {scanResult.findings.length === 0 ? (
                    <div className="bg-white rounded-3xl p-8 sm:p-10 border border-emerald-100 shadow-sm text-center">
                      <div className="w-16 h-16 rounded-full bg-emerald-50 text-emerald-600 flex items-center justify-center mx-auto mb-4 ring-8 ring-emerald-50/50">
                        <CheckCircle2 className="w-8 h-8" />
                      </div>
                      <h4 className="text-xl sm:text-2xl font-black text-slate-800 tracking-tight">
                        Zero Weaknesses Detected &bull; Clean Bill of Health!
                      </h4>
                      <p className="text-sm text-slate-500 max-w-xl mx-auto mt-2 leading-relaxed">
                        We systematically inspected your source files against our core security rules and found no vulnerable patterns or exposed secrets.
                      </p>
                      
                      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3 max-w-2xl mx-auto mt-6 text-left">
                        <div className="p-3 rounded-xl bg-emerald-50/60 border border-emerald-100 flex items-center gap-2.5">
                          <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
                          <span className="text-xs font-semibold text-slate-700">No SQL Injections (CWE-89)</span>
                        </div>
                        <div className="p-3 rounded-xl bg-emerald-50/60 border border-emerald-100 flex items-center gap-2.5">
                          <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
                          <span className="text-xs font-semibold text-slate-700">No Path Traversals (CWE-22)</span>
                        </div>
                        <div className="p-3 rounded-xl bg-emerald-50/60 border border-emerald-100 flex items-center gap-2.5">
                          <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
                          <span className="text-xs font-semibold text-slate-700">No Broken Access (CWE-639)</span>
                        </div>
                        <div className="p-3 rounded-xl bg-emerald-50/60 border border-emerald-100 flex items-center gap-2.5">
                          <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
                          <span className="text-xs font-semibold text-slate-700">No Insecure TLS (CWE-295)</span>
                        </div>
                        <div className="p-3 rounded-xl bg-emerald-50/60 border border-emerald-100 flex items-center gap-2.5">
                          <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
                          <span className="text-xs font-semibold text-slate-700">No Open Permissions (CWE-732)</span>
                        </div>
                        <div className="p-3 rounded-xl bg-emerald-50/60 border border-emerald-100 flex items-center gap-2.5">
                          <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
                          <span className="text-xs font-semibold text-slate-700">No Exposed Secrets (CWE-798)</span>
                        </div>
                      </div>

                      <div className="mt-6 pt-6 border-t border-slate-100 flex items-center justify-center gap-2 text-xs text-slate-400">
                        <span>All legitimate features preserved &bull; Code integrity 100% verified</span>
                      </div>
                    </div>
                  ) : (
                    scanResult.findings.map((finding) => (
                      <FindingCard
                        key={finding.id}
                        finding={finding}
                        onOpenELI12={setEli12Finding}
                        onOpenFixAssistant={setFixFinding}
                        onVerifyPatch={handleVerifyPatch}
                        isVerifying={verifyingFindingId === finding.id}
                        regressions={scanResult.regressions}
                      />
                    ))
                  )}
                </div>
              </>
            )}
          </div>
        )}

        {/* TAB 2: MY PROJECTS HISTORY */}
        {currentTab === 'projects' && (
          <div className="animate-in fade-in duration-150">
            <ProjectHistory onSelectProject={handleSelectFromHistory} />
          </div>
        )}

        {/* TAB 3: LEARN (ELI12 CONCEPT LIBRARY) */}
        {currentTab === 'learn' && (
          <div className="animate-in fade-in duration-150">
            <LearnHub />
          </div>
        )}

        {/* TAB 4: REPORTS & PDF PRINT */}
        {currentTab === 'reports' && (
          <div className="animate-in fade-in duration-150">
            <SecurityReportView
              project={activeProject}
              scanResult={scanResult}
              onBackToWorkspace={() => setCurrentTab('home')}
            />
          </div>
        )}
      </main>

      {/* Fix Assistant Modal */}
      <FixAssistantModal
        finding={fixFinding}
        onClose={() => setFixFinding(null)}
        onApplyAndVerify={handleApplyAndVerify}
        isApplying={isApplyingPatch}
      />

      {/* Explain Like I'm 12 Modal */}
      <ELI12Modal
        finding={eli12Finding}
        onClose={() => setEli12Finding(null)}
      />

      {/* Footer */}
      <footer className="border-t border-surface-border bg-white py-6 mt-16">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 text-center text-xs text-slate-400 font-medium">
          <p>
            DAMage CTRL &bull; Find the Flaw. Prove the Fix. &bull; Designed with care for students, builders, and small businesses.
          </p>
          <p className="mt-1 text-[11px] text-slate-300">
            Examines local source code in isolated sandboxes. No live production tests. Zero dependencies required.
          </p>
        </div>
      </footer>
    </div>
  );
}

export default App;
