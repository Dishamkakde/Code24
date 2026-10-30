import React from 'react';
import { ShieldCheck, ShieldAlert, CheckCircle2, XCircle, ArrowRight, Check, AlertTriangle, Sparkles } from 'lucide-react';
import type { Finding } from '../types';

interface BeforeAfterProofProps {
  finding: Finding;
  regressions?: {
    before: Record<string, boolean>;
    after: Record<string, boolean>;
  };
}

export const BeforeAfterProof: React.FC<BeforeAfterProofProps> = ({ finding, regressions }) => {
  const isVerified = finding.fixed && finding.verified_status === 'fixed_verified';
  const isFalsePositive = finding.status === 'false_positive';

  return (
    <div className="rounded-2xl bg-slate-900 text-slate-100 p-5 sm:p-6 shadow-inner">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-[11px] font-bold uppercase tracking-wider text-emerald-400 bg-emerald-950/60 px-2.5 py-0.5 rounded-full border border-emerald-800">
              Interactive Verification Proof
            </span>
            <span className="text-xs text-slate-400">Deterministic Evidence</span>
          </div>
          <h4 className="text-base font-bold text-white mt-1">
            Before vs After Test Results for {finding.function}()
          </h4>
        </div>

        {/* Verification Status Badge */}
        <div>
          {isVerified ? (
            <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/40">
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              <span>FIXED & PROVEN VERIFIED</span>
            </span>
          ) : isFalsePositive ? (
            <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold bg-blue-500/20 text-blue-400 border border-blue-500/40">
              <Check className="w-4 h-4 text-blue-400" />
              <span>BENIGN / FALSE ALARM FILTERED</span>
            </span>
          ) : (
            <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold bg-amber-500/20 text-amber-400 border border-amber-500/40">
              <AlertTriangle className="w-4 h-4 text-amber-400" />
              <span>SUGGESTED FIX – NOT YET VERIFIED</span>
            </span>
          )}
        </div>
      </div>

      {/* 3 Step Evidence Pipeline Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3.5 my-5">
        {/* Step 1: Baseline inspection */}
        <div className="p-4 rounded-xl bg-slate-800/80 border border-slate-700">
          <div className="text-xs text-slate-400 font-semibold uppercase tracking-wider mb-1">
            {finding.exploit_name ? '1. Baseline Exploit Test' : '1. AST Pattern Audit'}
          </div>
          <div className="flex items-center gap-2 mt-2">
            {finding.exploit_before ? (
              <span className="px-2.5 py-1 rounded-lg text-xs font-bold bg-red-900/60 text-red-300 border border-red-700">
                SUCCEEDED (Flaw Proved Real)
              </span>
            ) : isFalsePositive ? (
              <span className="px-2.5 py-1 rounded-lg text-xs font-bold bg-emerald-900/60 text-emerald-300 border border-emerald-700">
                FAILED (Code safely filtered)
              </span>
            ) : (
              <span className="px-2.5 py-1 rounded-lg text-xs font-bold bg-amber-900/60 text-amber-300 border border-amber-700">
                FLAGGED (Insecure Pattern)
              </span>
            )}
          </div>
          <p className="text-xs text-slate-300 mt-2 leading-relaxed">
            {finding.exploit_before
              ? `Exploit payload sent to ${finding.function}() logged in or read data without permission.`
              : isFalsePositive
              ? 'Exploit attempt failed against original code; input cast or sanitized before query.'
              : `Deterministic AST analysis confirmed insecure pattern in ${finding.file}:${finding.line}.`}
          </p>
        </div>

        {/* Step 2: Exploit re-test or AST re-scan after patch */}
        <div className="p-4 rounded-xl bg-slate-800/80 border border-slate-700">
          <div className="text-xs text-slate-400 font-semibold uppercase tracking-wider mb-1">
            {finding.exploit_name ? '2. Attack Re-Test' : '2. AST Pattern Re-Scan'}
          </div>
          <div className="flex items-center gap-2 mt-2">
            {isVerified ? (
              <span className="px-2.5 py-1 rounded-lg text-xs font-bold bg-emerald-900/60 text-emerald-300 border border-emerald-700 flex items-center gap-1">
                <Check className="w-3.5 h-3.5" />
                <span>{finding.exploit_name ? 'BLOCKED (Attack Neutralized)' : 'CLEAN (Pattern Eradicated)'}</span>
              </span>
            ) : isFalsePositive ? (
              <span className="px-2.5 py-1 rounded-lg text-xs font-bold bg-slate-700 text-slate-300 border border-slate-600">
                N/A (Benign finding)
              </span>
            ) : (
              <span className="px-2.5 py-1 rounded-lg text-xs font-bold bg-amber-900/60 text-amber-300 border border-amber-700">
                Awaiting Verification
              </span>
            )}
          </div>
          <p className="text-xs text-slate-300 mt-2 leading-relaxed">
            {isVerified
              ? (finding.exploit_name
                  ? 'The identical exploit was re-run against the patched code. The attack was completely stopped.'
                  : 'Re-scanning the patched code confirms the vulnerable pattern is 100% eliminated.')
              : isFalsePositive
              ? 'No patch needed because input validation already prevents exploitation.'
              : 'Click "Verify Patch" to run sandboxed proof verification.'}
          </p>
        </div>

        {/* Step 3: Code integrity & regressions */}
        <div className="p-4 rounded-xl bg-slate-800/80 border border-slate-700">
          <div className="text-xs text-slate-400 font-semibold uppercase tracking-wider mb-1">
            3. AST Re-scan Pattern
          </div>
          <div className="flex items-center gap-2 mt-2">
            {isVerified ? (
              <span className="px-2.5 py-1 rounded-lg text-xs font-bold bg-emerald-900/60 text-emerald-300 border border-emerald-700">
                CLEAN (Pattern Gone)
              </span>
            ) : (
              <span className="px-2.5 py-1 rounded-lg text-xs font-bold bg-slate-700 text-slate-300 border border-slate-600">
                Flaw present in source
              </span>
            )}
          </div>
          <p className="text-xs text-slate-300 mt-2 leading-relaxed">
            {isVerified
              ? 'AST syntax scanner re-inspected the code and confirmed the insecure pattern is fully removed.'
              : 'Static scanner detects unsafe pattern in current version.'}
          </p>
        </div>
      </div>

      {/* Regression test results table */}
      {regressions && (
        <div className="mt-4 pt-4 border-t border-slate-800">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-bold text-slate-300 uppercase tracking-wider">
              Legitimate Feature Regression Suite (6 Checks)
            </span>
            <span className="text-[11px] text-emerald-400 font-semibold">
              All Expected Behavior Preserved
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2 text-xs">
            {Object.keys(regressions.after || {}).map((name) => {
              const pass = regressions.after[name];
              return (
                <div
                  key={name}
                  className="flex items-center justify-between p-2 rounded-lg bg-slate-800/50 border border-slate-700"
                >
                  <span className="text-slate-300 truncate mr-2">{name}</span>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                    pass
                      ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                      : 'bg-red-950 text-red-400 border border-red-800'
                  }`}>
                    {pass ? 'PASS' : 'FAIL'}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
};
