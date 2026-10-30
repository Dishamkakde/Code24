import React, { useEffect, useState } from 'react';
import { FolderGit2, Calendar, FileCode2, ShieldAlert, CheckCircle2, ArrowRight, Loader2, Sparkles } from 'lucide-react';
import { listProjects } from '../api/client';
import type { ProjectInfo } from '../types';

interface ProjectHistoryProps {
  onSelectProject: (project: ProjectInfo) => void;
}

export const ProjectHistory: React.FC<ProjectHistoryProps> = ({ onSelectProject }) => {
  const [projects, setProjects] = useState<ProjectInfo[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    listProjects()
      .then((data) => setProjects(data))
      .catch(() => setProjects([]))
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="max-w-5xl mx-auto py-4">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-8 pb-4 border-b border-slate-200">
        <div>
          <h2 className="text-2xl font-black text-slate-900 tracking-tight">My Projects</h2>
          <p className="text-sm text-slate-500 mt-1">
            Locally saved projects and audit scan history in SQLite database.
          </p>
        </div>
      </div>

      {loading ? (
        <div className="text-center py-16 text-slate-400">
          <Loader2 className="w-6 h-6 animate-spin mx-auto mb-2 text-brand-blue" />
          <span>Loading project history...</span>
        </div>
      ) : projects.length === 0 ? (
        <div className="text-center py-16 bg-white rounded-3xl border border-slate-200 p-8 shadow-soft">
          <div className="w-12 h-12 rounded-2xl bg-slate-100 text-slate-400 flex items-center justify-center mx-auto mb-3">
            <FolderGit2 className="w-6 h-6" />
          </div>
          <h3 className="text-base font-bold text-slate-800">No projects analyzed yet</h3>
          <p className="text-xs text-slate-500 mt-1">
            Head to the Workspace to upload a project or run the interactive demonstration!
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {projects.map((p) => {
            const scan = p.latest_scan;
            const confirmed = scan ? scan.summary.confirmed : 0;
            const fixed = scan ? scan.summary.fixed : 0;
            const isAllFixed = fixed === confirmed && confirmed > 0;

            return (
              <div
                key={p.id}
                className="bg-white rounded-3xl border border-surface-border p-6 shadow-soft hover:shadow-card transition-all flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-center justify-between gap-2 mb-2">
                    <span className="text-xs font-mono font-bold text-slate-400 uppercase">
                      {p.source_type} &bull; {p.id}
                    </span>
                    {scan && (
                      <span className={`text-[11px] font-bold px-2.5 py-0.5 rounded-full ${
                        isAllFixed
                          ? 'bg-emerald-100 text-emerald-800'
                          : confirmed > 0
                          ? 'bg-red-100 text-red-800'
                          : 'bg-blue-100 text-blue-800'
                      }`}>
                        {isAllFixed ? 'All Verified Safe' : `${confirmed} Flaws Detected`}
                      </span>
                    )}
                  </div>

                  <h3 className="text-lg font-bold text-slate-900 truncate">{p.name}</h3>

                  <div className="flex items-center gap-4 text-xs text-slate-500 mt-3 font-medium">
                    <div className="flex items-center gap-1">
                      <FileCode2 className="w-3.5 h-3.5 text-slate-400" />
                      <span>{p.file_count} files ({p.line_count} lines)</span>
                    </div>
                    <div className="flex items-center gap-1">
                      <Calendar className="w-3.5 h-3.5 text-slate-400" />
                      <span>{new Date(p.created_at).toLocaleDateString()}</span>
                    </div>
                  </div>

                  {/* Languages badges */}
                  <div className="flex flex-wrap gap-1.5 mt-3">
                    {p.languages.map((l) => (
                      <span key={l} className="text-[10px] font-bold px-2 py-0.5 rounded-md bg-slate-100 text-slate-600">
                        {l}
                      </span>
                    ))}
                  </div>
                </div>

                <div className="mt-6 pt-4 border-t border-slate-100 flex items-center justify-between">
                  <div className="text-xs">
                    {scan ? (
                      <span className="text-slate-600">
                        Fixes: <strong className="text-slate-900">{fixed}/{confirmed} verified</strong>
                      </span>
                    ) : (
                      <span className="text-slate-400">Not scanned yet</span>
                    )}
                  </div>

                  <button
                    onClick={() => onSelectProject(p)}
                    className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-xl bg-slate-100 text-slate-800 text-xs font-bold hover:bg-brand-blue hover:text-white transition-colors"
                  >
                    <span>Inspect</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
