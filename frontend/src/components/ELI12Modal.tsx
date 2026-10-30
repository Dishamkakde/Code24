import React from 'react';
import { X, Sparkles, Lightbulb, BookOpen, ShieldCheck, HeartHandshake } from 'lucide-react';
import type { Finding } from '../types';

interface ELI12ModalProps {
  finding: Finding | null;
  onClose: () => void;
}

export const ELI12Modal: React.FC<ELI12ModalProps> = ({ finding, onClose }) => {
  if (!finding) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="bg-white rounded-3xl border border-purple-200 max-w-xl w-full shadow-2xl overflow-hidden flex flex-col">
        {/* Modal Header */}
        <div className="flex items-center justify-between p-6 bg-gradient-to-r from-purple-50 via-purple-100/50 to-pink-50 border-b border-purple-100">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-2xl bg-purple-600 text-white flex items-center justify-center shadow-sm">
              <Sparkles className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-black text-purple-950">Explain Like I'm 12</h3>
              <p className="text-xs text-purple-700 font-medium">Simple everyday analogies for cybersecurity</p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="w-8 h-8 rounded-full flex items-center justify-center text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 space-y-5 overflow-y-auto max-h-[75vh]">
          {/* Story Card */}
          <div className="p-5 rounded-2xl bg-gradient-to-b from-purple-50/60 to-white border border-purple-100 shadow-2xs">
            <div className="flex items-center gap-2 text-purple-700 font-bold text-xs uppercase tracking-wider mb-2">
              <Lightbulb className="w-4 h-4 text-purple-600" />
              <span>{finding.eli12.analogy_title}</span>
            </div>
            <p className="text-sm text-slate-700 leading-relaxed font-normal">
              {finding.eli12.analogy_story}
            </p>
          </div>

          {/* How this maps to your code */}
          <div className="p-4 rounded-2xl bg-blue-50/60 border border-blue-100">
            <div className="text-xs font-bold text-blue-900 uppercase tracking-wider mb-1 flex items-center gap-1.5">
              <ShieldCheck className="w-4 h-4 text-brand-blue" />
              <span>What is happening on your website?</span>
            </div>
            <p className="text-xs sm:text-sm text-blue-950 leading-relaxed">
              {finding.eli12.simple_explanation}
            </p>
          </div>

          {/* Simple Takeaway */}
          <div className="p-4 rounded-2xl bg-emerald-50/60 border border-emerald-100 flex items-start gap-3">
            <HeartHandshake className="w-5 h-5 text-emerald-600 flex-shrink-0 mt-0.5" />
            <div>
              <div className="text-xs font-bold text-emerald-900 uppercase tracking-wider">The Safe Rule</div>
              <p className="text-xs text-emerald-800 mt-1 leading-relaxed">
                Never trust input from strangers without validating it. Always tell the computer to treat user input as inert plain text, not as commands!
              </p>
            </div>
          </div>
        </div>

        {/* Modal Footer */}
        <div className="p-4 bg-slate-50 border-t border-slate-100 flex justify-end">
          <button
            onClick={onClose}
            className="px-5 py-2 rounded-xl bg-purple-600 text-white text-xs font-bold hover:bg-purple-700 transition-colors shadow-2xs"
          >
            Got It, Thanks!
          </button>
        </div>
      </div>
    </div>
  );
};
