import React, { useState } from 'react';
import { 
  ShieldAlert, ShieldCheck, AlertCircle, Sparkles, BookOpen, 
  Wrench, CheckCircle2, ChevronDown, ChevronUp, Code2, 
  HelpCircle, Eye, ArrowRight, Loader2, Database, Lock,
  ExternalLink, Tag, Shield, Info, Layers
} from 'lucide-react';
import type { Finding } from '../types';
import { BeforeAfterProof } from './BeforeAfterProof';

interface FindingCardProps {
  finding: Finding;
  onOpenELI12: (finding: Finding) => void;
  onOpenFixAssistant: (finding: Finding) => void;
  onVerifyPatch: (findingId: string) => Promise<void>;
  isVerifying: boolean;
  regressions?: {
    before: Record<string, boolean>;
    after: Record<string, boolean>;
  };
}

export const FindingCard: React.FC<FindingCardProps> = ({
  finding,
  onOpenELI12,
  onOpenFixAssistant,
  onVerifyPatch,
  isVerifying,
  regressions,
}) => {
  const [activeSection, setActiveSection] = useState<'what' | 'why' | 'where' | 'how' | 'proof'>('what');
  const [showTechnicalDetails, setShowTechnicalDetails] = useState(false);

  const getSeverityBadge = () => {
    switch (finding.severity) {
      case 'Urgent':
        return {
          bg: 'bg-red-50 text-red-700 border-red-200',
          dot: 'bg-red-500',
          label: 'Urgent Fix Recommended',
          desc: 'High risk: Attacker can directly bypass security without special privileges.'
        };
      case 'Important':
        return {
          bg: 'bg-amber-50 text-amber-700 border-amber-200',
          dot: 'bg-amber-500',
          label: 'Important (Needs Attention)',
          desc: 'Medium risk: Requires logged-in account or specific conditions to trigger.'
        };
      default:
        return {
          bg: 'bg-blue-50 text-blue-700 border-blue-200',
          dot: 'bg-blue-500',
          label: 'Needs Attention (Info)',
          desc: 'Low or filtered risk: Input is sanitized or blocked by surrounding code.'
        };
    }
  };

  const getStatusBadge = () => {
    if (finding.status === 'confirmed') {
      return (
        <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-black bg-red-100 text-red-700 border border-red-300">
          <span className="w-2 h-2 rounded-full bg-red-600 animate-pulse" />
          CONFIRMED EXPLOITABLE
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-black bg-emerald-100 text-emerald-800 border border-emerald-300">
        <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
        FALSE ALARM (FILTERED)
      </span>
    );
  };

  const severityInfo = getSeverityBadge();
  const isFixed = finding.fixed && finding.verified_status === 'fixed_verified';

  return (
    <div className={`rounded-3xl border transition-all p-6 sm:p-8 mb-6 ${
      isFixed 
        ? 'bg-white border-emerald-300 shadow-soft' 
        : finding.status === 'confirmed'
        ? 'bg-white border-red-200 shadow-card'
        : 'bg-white border-slate-200 shadow-soft'
    }`}>
      {/* Top Header: ID, Badges, Title */}
      <div className="flex flex-wrap items-center justify-between gap-3 pb-4 border-b border-slate-100">
        <div className="flex items-center gap-2">
          <span className="px-2.5 py-1 rounded-lg bg-slate-100 font-mono text-xs font-black text-slate-700 border border-slate-200">
            {finding.id}
          </span>
          {getStatusBadge()}
          <span className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold border ${severityInfo.bg}`}>
            <span className={`w-1.5 h-1.5 rounded-full ${severityInfo.dot}`} />
            {finding.severity}
          </span>
        </div>

        <div className="flex items-center gap-2">
          {/* Explain Like I'm 12 Button */}
          <button
            type="button"
            onClick={() => onOpenELI12(finding)}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-purple-50 text-purple-700 border border-purple-200 text-xs font-bold hover:bg-purple-100 transition-colors"
          >
            <Sparkles className="w-3.5 h-3.5 text-purple-600" />
            <span>Explain Like I'm 12</span>
          </button>

          {/* Fix Assistant Button */}
          {finding.status === 'confirmed' && (
            <button
              type="button"
              onClick={() => onOpenFixAssistant(finding)}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-brand-blue-light text-brand-blue border border-brand-blue-soft text-xs font-bold hover:bg-blue-100 transition-colors"
            >
              <Wrench className="w-3.5 h-3.5" />
              <span>Fix Assistant</span>
            </button>
          )}
        </div>
      </div>

      {/* Main Friendly Title & Evidence Badges */}
      <div className="my-4">
        <h3 className="text-xl sm:text-2xl font-black text-slate-900 tracking-tight">
          {finding.title}
        </h3>
        <p className="text-xs text-slate-500 font-medium mt-1">
          In file <span className="font-mono text-slate-700 font-semibold">{finding.file}:{finding.line}</span> inside <span className="font-mono text-slate-700 font-semibold">{finding.function}()</span>
        </p>

        {/* Evidence Classification Badges Row */}
        <div className="flex flex-wrap items-center gap-2 mt-3 pt-2">
          {/* CWE Badge */}
          {finding.classification?.cwe ? (
            <a
              href={finding.classification.cwe.url}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-800 font-mono text-xs font-bold transition-colors border border-slate-200"
              title={finding.classification.cwe.description}
            >
              <span>{finding.classification.cwe.id}</span>
              <ExternalLink className="w-3 h-3 text-slate-400" />
            </a>
          ) : (
            <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-slate-100 text-slate-700 font-mono text-xs font-bold border border-slate-200">
              {finding.cwe}
            </span>
          )}

          {/* OWASP Category Badge */}
          {finding.classification?.owasp && (
            <span 
              className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-indigo-50 text-indigo-700 font-semibold text-xs border border-indigo-200"
              title={finding.classification.owasp.justification}
            >
              <span>OWASP {finding.classification.owasp.code}</span>
            </span>
          )}

          {/* MITRE ATT&CK Badge */}
          {finding.classification?.attack ? (
            <a
              href={finding.classification.attack.url}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-rose-50 hover:bg-rose-100 text-rose-700 font-mono text-xs font-bold transition-colors border border-rose-200"
              title={`${finding.classification.attack.technique_name}: ${finding.classification.attack.defensible_reasoning}`}
            >
              <Shield className="w-3 h-3 text-rose-500" />
              <span>ATT&CK {finding.classification.attack.technique_id}</span>
              <ExternalLink className="w-2.5 h-2.5 text-rose-400" />
            </a>
          ) : (
            <span 
              className="inline-flex items-center gap-1 px-2 py-0.5 rounded-lg bg-slate-50 text-slate-400 font-mono text-[11px] border border-slate-200"
              title="Defensive omission or code hygiene flaw with no defensible MITRE ATT&CK adversary technique"
            >
              ATT&CK: N/A
            </span>
          )}

          {/* CVE Badge - Only displayed for dependency vulnerabilities */}
          {finding.classification?.cve && (
            <a
              href={finding.classification.cve.advisory_url}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-amber-50 hover:bg-amber-100 text-amber-800 font-mono text-xs font-bold transition-colors border border-amber-300"
              title={`Package: ${finding.classification.cve.package_name} (${finding.classification.cve.declared_version})`}
            >
              <span>{finding.classification.cve.cve_id}</span>
              <ExternalLink className="w-2.5 h-2.5 text-amber-600" />
            </a>
          )}

          {/* CVSS Badge with Sourced vs Calculated tag */}
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-100 text-slate-700 text-xs font-bold border border-slate-200">
            <span>CVSS {finding.classification?.cvss?.score?.toFixed(1) || finding.cvss.toFixed(1)}</span>
            <span className={`text-[10px] uppercase px-1 py-0.2 rounded font-extrabold ${
              finding.classification?.cvss?.source_type === 'sourced' 
                ? 'bg-blue-100 text-blue-700' 
                : 'bg-emerald-100 text-emerald-800'
            }`}>
              {finding.classification?.cvss?.source_type === 'sourced' ? 'Sourced' : 'Calculated'}
            </span>
          </span>
        </div>
      </div>

      {/* 5-Part Progressive Disclosure Tabs */}
      <div className="mt-5 border border-slate-200 rounded-2xl overflow-hidden bg-slate-50/50">
        <div className="flex border-b border-slate-200 bg-slate-100/70 overflow-x-auto text-xs font-bold">
          <button
            onClick={() => setActiveSection('what')}
            className={`px-4 py-2.5 transition-colors whitespace-nowrap ${
              activeSection === 'what' ? 'bg-white text-brand-blue border-b-2 border-brand-blue' : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            1. What did we find?
          </button>
          <button
            onClick={() => setActiveSection('why')}
            className={`px-4 py-2.5 transition-colors whitespace-nowrap ${
              activeSection === 'why' ? 'bg-white text-brand-blue border-b-2 border-brand-blue' : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            2. Why does it matter?
          </button>
          <button
            onClick={() => setActiveSection('where')}
            className={`px-4 py-2.5 transition-colors whitespace-nowrap ${
              activeSection === 'where' ? 'bg-white text-brand-blue border-b-2 border-brand-blue' : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            3. Where is the problem?
          </button>
          <button
            onClick={() => setActiveSection('how')}
            className={`px-4 py-2.5 transition-colors whitespace-nowrap ${
              activeSection === 'how' ? 'bg-white text-brand-blue border-b-2 border-brand-blue' : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            4. How can we fix it?
          </button>
          <button
            onClick={() => setActiveSection('proof')}
            className={`px-4 py-2.5 transition-colors whitespace-nowrap flex items-center gap-1.5 ${
              activeSection === 'proof' ? 'bg-white text-brand-mint border-b-2 border-brand-mint' : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            <span>5. Did the fix work?</span>
            {isFixed && <CheckCircle2 className="w-3.5 h-3.5 text-brand-mint" />}
          </button>
        </div>

        {/* Tab Content Display */}
        <div className="p-5 bg-white text-sm">
          {activeSection === 'what' && (
            <div className="space-y-3">
              <p className="text-slate-700 leading-relaxed">{finding.five_sections.what}</p>
              <div className="p-3.5 rounded-xl bg-purple-50/70 border border-purple-200 flex items-start gap-3">
                <Sparkles className="w-5 h-5 text-purple-600 flex-shrink-0 mt-0.5" />
                <div>
                  <div className="text-xs font-bold text-purple-900 uppercase">Everyday Story Analogy</div>
                  <div className="text-xs text-purple-800 mt-1 leading-relaxed">
                    <em>{finding.eli12.analogy_title}:</em> {finding.eli12.analogy_story}
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeSection === 'why' && (
            <div className="space-y-3">
              <p className="text-slate-700 leading-relaxed">{finding.five_sections.why}</p>
              <div className="p-3.5 rounded-xl bg-amber-50 border border-amber-200 text-xs text-amber-800 leading-relaxed">
                <strong>Why severity is {finding.severity}:</strong> {severityInfo.desc}
              </div>
            </div>
          )}

          {activeSection === 'where' && (
            <div className="space-y-3">
              <p className="text-slate-700 leading-relaxed">{finding.five_sections.where}</p>
              <div className="rounded-xl overflow-hidden border border-slate-200">
                <div className="bg-slate-800 px-4 py-2 text-xs text-slate-300 font-mono flex items-center justify-between">
                  <span>{finding.file} (Line {finding.line})</span>
                  <span className="text-[11px] text-red-400 font-bold">Vulnerable code</span>
                </div>
                <pre className="p-4 bg-slate-900 text-slate-100 font-mono text-xs overflow-x-auto leading-relaxed">
                  <code>{finding.snippet}</code>
                </pre>
              </div>
            </div>
          )}

          {activeSection === 'how' && (
            <div className="space-y-3">
              <p className="text-slate-700 leading-relaxed">{finding.five_sections.how}</p>
              <div className="p-3.5 rounded-xl bg-blue-50 border border-blue-200 text-xs text-blue-900 leading-relaxed">
                <div className="font-bold mb-1">Plain-English Defensive Fix:</div>
                {finding.patch_plain_english}
              </div>

              {finding.status === 'confirmed' && (
                <div className="pt-2">
                  <button
                    onClick={() => onOpenFixAssistant(finding)}
                    className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-brand-blue text-white text-xs font-bold hover:bg-blue-700 transition-colors shadow-sm"
                  >
                    <Wrench className="w-3.5 h-3.5" />
                    <span>Review Proposed Patch Diff</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              )}
            </div>
          )}

          {activeSection === 'proof' && (
            <div className="space-y-4">
              <p className="text-slate-700 leading-relaxed">{finding.five_sections.proof}</p>
              <BeforeAfterProof finding={finding} regressions={regressions} />
            </div>
          )}
        </div>
      </div>

      {/* Action Footer: Verify Patch Button & Expandable Technical Information */}
      <div className="mt-5 pt-4 border-t border-slate-100 flex flex-wrap items-center justify-between gap-4">
        {/* Verification trigger */}
        {finding.status === 'confirmed' && (
          <div>
            {!isFixed ? (
              <button
                type="button"
                disabled={isVerifying}
                onClick={() => onVerifyPatch(finding.id)}
                className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-brand-mint text-white font-bold text-xs shadow-soft hover:bg-emerald-600 active:scale-95 transition-all disabled:opacity-50"
              >
                {isVerifying ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    <span>Running Sandbox Verification...</span>
                  </>
                ) : (
                  <>
                    <ShieldCheck className="w-4 h-4" />
                    <span>Run Verification Proof Now</span>
                  </>
                )}
              </button>
            ) : (
              <div className="inline-flex items-center gap-2 text-xs font-bold text-emerald-700 bg-emerald-50 px-3 py-1.5 rounded-xl border border-emerald-200">
                <CheckCircle2 className="w-4 h-4 text-brand-mint" />
                <span>Fix Successfully Verified & Proven Safe</span>
              </div>
            )}
          </div>
        )}

        {/* Technical Details Toggle */}
        <button
          type="button"
          onClick={() => setShowTechnicalDetails(!showTechnicalDetails)}
          className="inline-flex items-center gap-1.5 text-xs font-bold text-slate-500 hover:text-slate-800 transition-colors ml-auto"
        >
          <Code2 className="w-3.5 h-3.5" />
          <span>{showTechnicalDetails ? 'Hide' : 'Show'} Expert / CWE Technical Details</span>
          {showTechnicalDetails ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
        </button>
      </div>

      {/* Comprehensive Evidence-Based Technical Information */}
      {showTechnicalDetails && (
        <div className="mt-5 p-5 rounded-2xl bg-slate-900 text-slate-200 text-xs space-y-4 shadow-inner border border-slate-800">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2">
              <Layers className="w-4 h-4 text-brand-blue" />
              <span className="font-bold text-sm text-white tracking-wide">
                Evidence-Based Security Classification & Traceability
              </span>
            </div>
            <span className="text-[11px] font-mono text-slate-400">
              MITRE ATT&CK&reg; Enterprise v15.1 &bull; CWE 4.14
            </span>
          </div>

          {/* Section 1: Scanner Raw Output vs Inferred Standards */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-3.5 rounded-xl bg-slate-800/70 border border-slate-700/60 space-y-2">
              <div className="flex items-center justify-between text-slate-400 uppercase text-[10px] font-bold tracking-wider">
                <span>Scanner Engine Signal (Direct Evidence)</span>
                <span className="font-mono text-slate-300">
                  {finding.classification?.scanner_classification?.scanner_name || finding.scanner_name || 'Analyzer'}
                </span>
              </div>
              <div className="space-y-1 font-mono text-[11px]">
                <div className="flex justify-between">
                  <span className="text-slate-400">Rule ID:</span>
                  <span className="text-slate-200 truncate max-w-[220px]">
                    {finding.classification?.scanner_classification?.scanner_rule_id || finding.rule}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Scanner Severity:</span>
                  <span className="text-amber-400">
                    {finding.classification?.scanner_classification?.scanner_severity || finding.severity}
                  </span>
                </div>
                {finding.classification?.scanner_classification?.scanner_confidence && (
                  <div className="flex justify-between">
                    <span className="text-slate-400">Confidence:</span>
                    <span className="text-slate-300">
                      {finding.classification.scanner_classification.scanner_confidence}
                    </span>
                  </div>
                )}
              </div>
            </div>

            {/* Section 2: CVSS 3.1 Provenance */}
            <div className="p-3.5 rounded-xl bg-slate-800/70 border border-slate-700/60 space-y-2">
              <div className="flex items-center justify-between text-slate-400 uppercase text-[10px] font-bold tracking-wider">
                <span>CVSS 3.1 Base Score Provenance</span>
                <span className={`px-1.5 py-0.5 rounded text-[10px] font-black ${
                  finding.classification?.cvss?.source_type === 'sourced'
                    ? 'bg-blue-900/60 text-blue-300 border border-blue-700/50'
                    : 'bg-emerald-900/60 text-emerald-300 border border-emerald-700/50'
                }`}>
                  {finding.classification?.cvss?.source_type === 'sourced' ? 'SOURCED ADVISORY' : 'CALCULATED EQUATION'}
                </span>
              </div>
              <div className="space-y-1 text-[11px]">
                <div className="flex justify-between font-mono">
                  <span className="text-slate-400">Base Score:</span>
                  <span className="text-white font-bold text-sm">
                    {finding.classification?.cvss?.score?.toFixed(1) || finding.cvss.toFixed(1)} / 10.0
                  </span>
                </div>
                {finding.classification?.cvss?.vector && (
                  <div className="text-[10px] font-mono text-slate-400 truncate" title={finding.classification.cvss.vector}>
                    Vector: {finding.classification.cvss.vector}
                  </div>
                )}
                <div className="text-[11px] text-slate-300 leading-snug">
                  {finding.classification?.cvss?.rationale || 'Derived using standard CVSS 3.1 base metric group calculation.'}
                </div>
              </div>
            </div>
          </div>

          {/* Section 3: CWE & OWASP Classifications */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* CWE */}
            <div className="p-3.5 rounded-xl bg-slate-800/70 border border-slate-700/60 space-y-1.5">
              <div className="text-slate-400 uppercase text-[10px] font-bold tracking-wider flex items-center justify-between">
                <span>CWE Software Weakness</span>
                <a
                  href={finding.classification?.cwe?.url || `https://cwe.mitre.org/data/definitions/${finding.cwe.replace('CWE-', '')}.html`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-brand-blue-soft hover:underline font-mono inline-flex items-center gap-1"
                >
                  <span>{finding.classification?.cwe?.id || finding.cwe}</span>
                  <ExternalLink className="w-2.5 h-2.5" />
                </a>
              </div>
              <div className="font-semibold text-slate-100 text-xs">
                {finding.classification?.cwe?.name || finding.technical_title}
              </div>
              <p className="text-slate-300 text-[11px] leading-relaxed">
                {finding.classification?.cwe?.description || 'Classifies underlying software flaw mechanism according to Common Weakness Enumeration.'}
              </p>
            </div>

            {/* OWASP */}
            <div className="p-3.5 rounded-xl bg-slate-800/70 border border-slate-700/60 space-y-1.5">
              <div className="text-slate-400 uppercase text-[10px] font-bold tracking-wider flex items-center justify-between">
                <span>OWASP Top 10 (2021) Category</span>
                <span className="font-mono text-indigo-300">
                  {finding.classification?.owasp?.code || 'A03:2021'}
                </span>
              </div>
              <div className="font-semibold text-slate-100 text-xs">
                {finding.classification?.owasp?.category || 'Injection'}
              </div>
              <p className="text-slate-300 text-[11px] leading-relaxed">
                {finding.classification?.owasp?.justification || 'Maps weakness mechanism to standard industry risk prioritization categories.'}
              </p>
            </div>
          </div>

          {/* Section 4: MITRE ATT&CK Enterprise Mapping & CVE Context */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* MITRE ATT&CK */}
            <div className="p-3.5 rounded-xl bg-slate-800/70 border border-slate-700/60 space-y-2">
              <div className="text-slate-400 uppercase text-[10px] font-bold tracking-wider flex items-center justify-between">
                <span>MITRE ATT&CK&reg; Association</span>
                {finding.classification?.attack ? (
                  <span className="text-rose-400 font-mono font-bold">
                    {finding.classification.attack.technique_id}
                  </span>
                ) : (
                  <span className="text-slate-400 font-mono text-[10px]">NO DEFENSIVE MAPPING</span>
                )}
              </div>

              {finding.classification?.attack ? (
                <div className="space-y-1.5">
                  <div className="text-xs font-semibold text-rose-200">
                    {finding.classification.attack.technique_name}
                  </div>
                  <div className="text-[10px] font-mono text-slate-400">
                    Tactics: {finding.classification.attack.tactics.join(', ')}
                  </div>
                  <p className="text-[11px] text-slate-300 leading-relaxed">
                    {finding.classification.attack.defensible_reasoning}
                  </p>
                  <div className="pt-1">
                    <a
                      href={finding.classification.attack.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-[11px] text-rose-300 hover:underline inline-flex items-center gap-1"
                    >
                      <span>View MITRE ATT&CK Technique Spec</span>
                      <ExternalLink className="w-2.5 h-2.5" />
                    </a>
                  </div>
                </div>
              ) : (
                <div className="text-[11px] text-slate-400 leading-relaxed">
                  <em>Negative Association:</em> This finding is a code-level defense omission (e.g. missing security header or insecure cookie flag), which does not correspond to an adversary ATT&CK technique.
                </div>
              )}
            </div>

            {/* CVE Context */}
            <div className="p-3.5 rounded-xl bg-slate-800/70 border border-slate-700/60 space-y-2">
              <div className="text-slate-400 uppercase text-[10px] font-bold tracking-wider flex items-center justify-between">
                <span>CVE & Supply-Chain Instance Status</span>
                <span className="font-mono text-slate-300 text-[10px]">
                  {finding.classification?.cve ? 'THIRD-PARTY ADVISORY' : 'FIRST-PARTY CODE'}
                </span>
              </div>

              {finding.classification?.cve ? (
                <div className="space-y-1.5">
                  <div className="text-xs font-mono font-bold text-amber-300">
                    {finding.classification.cve.cve_id}
                  </div>
                  <div className="text-[11px] text-slate-300">
                    Package: <span className="font-mono font-semibold text-white">{finding.classification.cve.package_name}</span> ({finding.classification.cve.declared_version})
                  </div>
                  {finding.classification.cve.affected_range && (
                    <div className="text-[10px] text-slate-400 font-mono">
                      Affected: {finding.classification.cve.affected_range}
                    </div>
                  )}
                  <div className="pt-1">
                    <a
                      href={finding.classification.cve.advisory_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-[11px] text-amber-300 hover:underline inline-flex items-center gap-1"
                    >
                      <span>View Advisory Source ({finding.classification.cve.advisory_source})</span>
                      <ExternalLink className="w-2.5 h-2.5" />
                    </a>
                  </div>
                </div>
              ) : (
                <div className="text-[11px] text-slate-400 leading-relaxed">
                  <em>First-Party Source Code:</em> No CVE identifier assigned. CVEs (Common Vulnerabilities and Exposures) are uniquely reserved for publicly cataloged software packages and libraries.
                </div>
              )}
            </div>
          </div>

          {/* Section 5: Traceability Statement */}
          <div className="p-3.5 rounded-xl bg-slate-800/40 border border-slate-700/40 text-[11px] text-slate-300 leading-relaxed">
            <span className="text-slate-400 uppercase text-[10px] font-bold block mb-1">
              Traceability & Defense Statement
            </span>
            <p>
              {finding.classification?.traceability_statement || finding.patch_rationale}
            </p>
          </div>
        </div>
      )}
    </div>
  );
};
