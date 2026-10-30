import React, { useEffect, useState } from 'react';
import { BookOpen, Sparkles, Database, Lock, FolderX, Code2, Check, X, Lightbulb } from 'lucide-react';
import { getLearnConcepts } from '../api/client';
import type { LearnConcept } from '../types';

export const LearnHub: React.FC = () => {
  const [concepts, setConcepts] = useState<LearnConcept[]>([]);
  const [loading, setLoading] = useState(true);
  const [expandedId, setExpandedId] = useState<string | null>('sql-injection');

  useEffect(() => {
    getLearnConcepts()
      .then((data) => setConcepts(data))
      .catch(() => setConcepts([]))
      .finally(() => setLoading(false));
  }, []);

  const getIcon = (iconName: string) => {
    switch (iconName) {
      case 'Database': return <Database className="w-5 h-5 text-brand-blue" />;
      case 'Lock': return <Lock className="w-5 h-5 text-amber-500" />;
      case 'FolderAlert': return <FolderX className="w-5 h-5 text-red-500" />;
      default: return <Code2 className="w-5 h-5 text-purple-600" />;
    }
  };

  return (
    <div className="max-w-5xl mx-auto py-4">
      {/* Header */}
      <div className="text-center max-w-2xl mx-auto mb-10">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-purple-50 text-purple-700 text-xs font-bold uppercase tracking-wider mb-3 border border-purple-200">
          <Sparkles className="w-3.5 h-3.5 text-purple-600" />
          <span>Explain Like I'm 12 Security Library</span>
        </div>
        <h2 className="text-3xl font-extrabold text-slate-900 tracking-tight">
          How Web Flaws Work (Without the Jargon)
        </h2>
        <p className="text-sm text-slate-600 mt-2 leading-relaxed">
          Security concepts translated into relatable everyday analogies, understandable to kids, students, non-technical creators, and curious builders.
        </p>
      </div>

      {loading ? (
        <div className="text-center py-12 text-slate-400 text-sm">Loading security concepts...</div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {concepts.map((c) => {
            const isExpanded = expandedId === c.id;
            return (
              <div
                key={c.id}
                className="bg-white rounded-3xl border border-surface-border p-6 shadow-soft hover:shadow-card transition-shadow flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-center justify-between gap-3 mb-3">
                    <div className="w-10 h-10 rounded-2xl bg-slate-50 border border-slate-200 flex items-center justify-center">
                      {getIcon(c.icon)}
                    </div>
                    <span className="text-[11px] font-bold font-mono px-2 py-0.5 rounded-full bg-slate-100 text-slate-600 border border-slate-200">
                      {c.cwe}
                    </span>
                  </div>

                  <h3 className="text-lg font-bold text-slate-900">{c.title}</h3>

                  {/* Analogy box */}
                  <div className="mt-4 p-4 rounded-2xl bg-purple-50/70 border border-purple-100">
                    <div className="flex items-center gap-1.5 text-xs font-bold text-purple-900 uppercase tracking-wider mb-1">
                      <Lightbulb className="w-3.5 h-3.5 text-purple-600" />
                      <span>{c.analogy_title}</span>
                    </div>
                    <p className="text-xs text-purple-950 leading-relaxed">
                      {c.analogy}
                    </p>
                  </div>

                  {/* Why it happens */}
                  <div className="mt-4">
                    <h4 className="text-xs font-bold text-slate-700 uppercase tracking-wider mb-1">
                      Why does it happen?
                    </h4>
                    <p className="text-xs text-slate-600 leading-relaxed">
                      {c.why_it_happens}
                    </p>
                  </div>

                  {/* How to prevent */}
                  <div className="mt-3">
                    <h4 className="text-xs font-bold text-brand-mint uppercase tracking-wider mb-1">
                      How to fix it:
                    </h4>
                    <p className="text-xs text-slate-600 leading-relaxed">
                      {c.how_to_prevent}
                    </p>
                  </div>
                </div>

                {/* Code Comparison */}
                <div className="mt-5 pt-4 border-t border-slate-100">
                  <div className="grid grid-cols-1 gap-2 font-mono text-[11px]">
                    <div className="p-2.5 rounded-xl bg-red-50 text-red-900 border border-red-200 flex items-start gap-2">
                      <X className="w-3.5 h-3.5 text-red-600 mt-0.5 flex-shrink-0" />
                      <div className="overflow-x-auto">
                        <span className="text-[10px] uppercase font-bold text-red-600 block mb-0.5">Vulnerable Pattern:</span>
                        <code>{c.simple_example_bad}</code>
                      </div>
                    </div>
                    <div className="p-2.5 rounded-xl bg-emerald-50 text-emerald-900 border border-emerald-200 flex items-start gap-2">
                      <Check className="w-3.5 h-3.5 text-brand-mint mt-0.5 flex-shrink-0" />
                      <div className="overflow-x-auto">
                        <span className="text-[10px] uppercase font-bold text-emerald-700 block mb-0.5">Defensive Pattern:</span>
                        <code>{c.simple_example_good}</code>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
