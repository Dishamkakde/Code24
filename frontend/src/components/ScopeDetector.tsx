import React, { useState } from 'react';
import { 
  FileCode2, Layers, Scan, Loader2, ChevronDown, ChevronUp, 
  ShieldCheck, Plus, X, Sparkles, Check
} from 'lucide-react';
import type { ProjectInfo } from '../types';
import { updateProjectFrameworks } from '../api/client';

interface ScopeDetectorProps {
  project: ProjectInfo;
  onRunScan: () => void;
  isScanning: boolean;
  onProjectUpdated?: (project: ProjectInfo) => void;
}

const POPULAR_FRAMEWORKS = [
  "FastAPI", "Flask", "Django", "Express.js", "React", "Next.js", 
  "Vue.js", "Nuxt", "Svelte / SvelteKit", "Tailwind CSS", "Bootstrap",
  "SQLite", "PostgreSQL", "MySQL", "MongoDB", "Prisma", "SQLAlchemy"
];

export const ScopeDetector: React.FC<ScopeDetectorProps> = ({
  project,
  onRunScan,
  isScanning,
  onProjectUpdated,
}) => {
  const [showFiles, setShowFiles] = useState(false);
  const [showAddFrameworkModal, setShowAddFrameworkModal] = useState(false);
  const [customFrameworkInput, setCustomFrameworkInput] = useState('');
  const [isUpdatingFw, setIsUpdatingFw] = useState(false);

  const handleToggleFramework = async (fwName: string) => {
    const currentFws = project.frameworks || [];
    let updatedFws: string[];
    if (currentFws.includes(fwName)) {
      updatedFws = currentFws.filter((f) => f !== fwName);
    } else {
      updatedFws = [...currentFws, fwName];
    }

    setIsUpdatingFw(true);
    try {
      const updatedProject = await updateProjectFrameworks(project.id, updatedFws);
      if (onProjectUpdated) {
        onProjectUpdated({
          ...project,
          frameworks: updatedProject.frameworks,
        });
      }
    } catch (err) {
      console.error(err);
    } finally {
      setIsUpdatingFw(false);
    }
  };

  const handleAddCustomFramework = async (e: React.FormEvent) => {
    e.preventDefault();
    const clean = customFrameworkInput.trim();
    if (!clean) return;

    if (!project.frameworks.includes(clean)) {
      await handleToggleFramework(clean);
    }
    setCustomFrameworkInput('');
  };

  return (
    <div className="bg-white rounded-3xl border border-surface-border p-6 sm:p-8 shadow-card mb-8">
      {/* Header Row */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 pb-6 border-b border-slate-100">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-xs font-bold uppercase tracking-wider text-brand-mint bg-brand-mint-light px-2.5 py-0.5 rounded-full border border-brand-mint-soft">
              Project Ready For Analysis
            </span>
            <span className="text-xs text-slate-400">&bull; ID: {project.id}</span>
          </div>
          <h2 className="text-2xl font-bold text-slate-900">{project.name}</h2>
          <p className="text-sm text-slate-500 mt-0.5">
            Isolated sandbox created at <span className="font-mono text-xs text-slate-600">{project.source_type}</span> scope.
          </p>
        </div>

        {/* Scan CTA button */}
        <button
          type="button"
          disabled={isScanning}
          onClick={onRunScan}
          className="inline-flex items-center justify-center gap-2.5 px-7 py-3.5 rounded-2xl bg-gradient-to-r from-brand-blue to-blue-600 text-white font-bold text-base shadow-soft hover:shadow-md hover:from-blue-700 hover:to-blue-800 active:scale-95 transition-all disabled:opacity-50 disabled:cursor-wait"
        >
          {isScanning ? (
            <>
              <Loader2 className="w-5 h-5 animate-spin" />
              <span>Scanning Source Code...</span>
            </>
          ) : (
            <>
              <Scan className="w-5 h-5" />
              <span>Start Security Scan</span>
            </>
          )}
        </button>
      </div>

      {/* Scope Highlights Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 my-6">
        {/* Languages Card */}
        <div className="p-4 rounded-2xl bg-[#FAF9F5] border border-cream-200">
          <div className="flex items-center gap-2 text-slate-500 text-xs font-semibold uppercase mb-1">
            <Layers className="w-3.5 h-3.5 text-brand-blue" />
            <span>Detected Languages</span>
          </div>
          <div className="flex flex-wrap gap-1.5 mt-2">
            {project.languages.length > 0 ? (
              project.languages.map((lang) => (
                <span
                  key={lang}
                  className="px-2.5 py-1 text-xs font-bold bg-white text-brand-blue border border-brand-blue-soft rounded-lg shadow-2xs"
                >
                  {lang}
                </span>
              ))
            ) : (
              <span className="text-xs text-slate-400">None detected</span>
            )}
          </div>
        </div>

        {/* Frameworks Card with Add Framework CTA */}
        <div className="p-4 rounded-2xl bg-[#FAF9F5] border border-cream-200">
          <div className="flex items-center justify-between text-slate-500 text-xs font-semibold uppercase mb-1">
            <div className="flex items-center gap-1.5">
              <ShieldCheck className="w-3.5 h-3.5 text-brand-mint" />
              <span>Frameworks & Libs</span>
            </div>
            <button
              onClick={() => setShowAddFrameworkModal(true)}
              className="text-[11px] font-bold text-brand-blue hover:text-blue-800 flex items-center gap-0.5"
            >
              <Plus className="w-3 h-3" />
              <span>Add</span>
            </button>
          </div>
          <div className="flex flex-wrap gap-1.5 mt-2">
            {project.frameworks.length > 0 ? (
              project.frameworks.map((fw) => (
                <span
                  key={fw}
                  className="inline-flex items-center gap-1 px-2.5 py-1 text-xs font-bold bg-white text-emerald-800 border border-brand-mint-soft rounded-lg shadow-2xs group"
                >
                  <span>{fw}</span>
                  <button
                    onClick={() => handleToggleFramework(fw)}
                    className="text-slate-300 hover:text-red-500 transition-colors"
                    title={`Remove ${fw}`}
                  >
                    <X className="w-3 h-3" />
                  </button>
                </span>
              ))
            ) : (
              <button
                onClick={() => setShowAddFrameworkModal(true)}
                className="text-xs text-slate-400 hover:text-brand-blue transition-colors flex items-center gap-1"
              >
                <span>+ Specify frameworks</span>
              </button>
            )}
          </div>
        </div>

        {/* Total Scannable Files */}
        <div className="p-4 rounded-2xl bg-[#FAF9F5] border border-cream-200">
          <div className="text-slate-500 text-xs font-semibold uppercase mb-1">Files in Scope</div>
          <div className="text-2xl font-black text-slate-900 mt-1">{project.file_count}</div>
          <div className="text-[11px] text-slate-400 mt-0.5">Scannable source code files</div>
        </div>

        {/* Total Lines of Code */}
        <div className="p-4 rounded-2xl bg-[#FAF9F5] border border-cream-200">
          <div className="text-slate-500 text-xs font-semibold uppercase mb-1">Total Lines</div>
          <div className="text-2xl font-black text-slate-900 mt-1">{project.line_count}</div>
          <div className="text-[11px] text-slate-400 mt-0.5">Lines of code inspected</div>
        </div>
      </div>

      {/* Expandable Files List */}
      {project.files && project.files.length > 0 && (
        <div className="pt-2">
          <button
            type="button"
            onClick={() => setShowFiles(!showFiles)}
            className="flex items-center gap-2 text-xs font-bold text-slate-600 hover:text-slate-900 transition-colors"
          >
            <span>{showFiles ? 'Hide' : 'View'} scanned file list ({project.files.length} files)</span>
            {showFiles ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
          </button>

          {showFiles && (
            <div className="mt-3 overflow-hidden rounded-2xl border border-slate-200 bg-slate-50">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-100 text-slate-500 font-semibold border-b border-slate-200">
                  <tr>
                    <th className="py-2.5 px-4">File Path</th>
                    <th className="py-2.5 px-4">Language</th>
                    <th className="py-2.5 px-4 text-right">Lines</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200">
                  {project.files.map((f) => (
                    <tr key={f.path} className="hover:bg-slate-100/60">
                      <td className="py-2 px-4 font-mono text-slate-700 flex items-center gap-2">
                        <FileCode2 className="w-3.5 h-3.5 text-slate-400" />
                        <span>{f.path}</span>
                      </td>
                      <td className="py-2 px-4 text-slate-500">{f.language}</td>
                      <td className="py-2 px-4 text-right font-mono text-slate-600">{f.lines}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Add / Manage Frameworks Modal */}
      {showAddFrameworkModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/50 backdrop-blur-xs animate-in fade-in">
          <div className="bg-white rounded-3xl border border-slate-200 p-6 max-w-lg w-full shadow-2xl">
            <div className="flex items-center justify-between pb-4 border-b border-slate-100 mb-4">
              <div className="flex items-center gap-2">
                <div className="w-8 h-8 rounded-xl bg-brand-mint-light text-brand-mint flex items-center justify-center font-bold">
                  <ShieldCheck className="w-4 h-4" />
                </div>
                <h3 className="text-base font-bold text-slate-900">Configure Frameworks</h3>
              </div>
              <button
                onClick={() => setShowAddFrameworkModal(false)}
                className="w-7 h-7 rounded-full flex items-center justify-center text-slate-400 hover:text-slate-700"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <p className="text-xs text-slate-600 mb-4">
              Select or type the web frameworks, libraries, and databases used by this project:
            </p>

            {/* Popular presets */}
            <div className="flex flex-wrap gap-2 mb-5 max-h-48 overflow-y-auto p-1">
              {POPULAR_FRAMEWORKS.map((fw) => {
                const isSelected = project.frameworks.includes(fw);
                return (
                  <button
                    key={fw}
                    type="button"
                    disabled={isUpdatingFw}
                    onClick={() => handleToggleFramework(fw)}
                    className={`px-3 py-1.5 rounded-xl text-xs font-bold transition-all flex items-center gap-1.5 ${
                      isSelected
                        ? 'bg-brand-mint text-white shadow-xs'
                        : 'bg-slate-100 text-slate-700 hover:bg-slate-200'
                    }`}
                  >
                    <span>{fw}</span>
                    {isSelected && <Check className="w-3.5 h-3.5" />}
                  </button>
                );
              })}
            </div>

            {/* Custom framework input */}
            <form onSubmit={handleAddCustomFramework} className="flex gap-2 pt-3 border-t border-slate-100">
              <input
                type="text"
                placeholder="Or type custom framework (e.g. Spring Boot, Laravel)"
                value={customFrameworkInput}
                onChange={(e) => setCustomFrameworkInput(e.target.value)}
                className="flex-1 px-3 py-2 rounded-xl border border-slate-300 text-xs outline-none focus:border-brand-blue"
              />
              <button
                type="submit"
                disabled={!customFrameworkInput.trim() || isUpdatingFw}
                className="px-4 py-2 rounded-xl bg-slate-900 text-white text-xs font-bold hover:bg-slate-800 disabled:opacity-40"
              >
                Add
              </button>
            </form>

            <div className="mt-5 flex justify-end">
              <button
                type="button"
                onClick={() => setShowAddFrameworkModal(false)}
                className="px-5 py-2 rounded-xl bg-brand-blue text-white text-xs font-bold hover:bg-blue-700"
              >
                Done
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
