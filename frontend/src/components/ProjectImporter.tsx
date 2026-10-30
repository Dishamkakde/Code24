import React, { useState } from 'react';
import { UploadCloud, GitBranch, PlayCircle, Loader2, FileArchive, ArrowRight, ShieldAlert, Globe } from 'lucide-react';
import { loadDemoProject, uploadZipProject, importGithubProject, scanWebsiteUrl } from '../api/client';
import type { ProjectInfo } from '../types';

interface ProjectImporterProps {
  onProjectLoaded: (project: ProjectInfo) => void;
  isLoading: boolean;
  setIsLoading: (loading: boolean) => void;
}

export const ProjectImporter: React.FC<ProjectImporterProps> = ({
  onProjectLoaded,
  isLoading,
  setIsLoading,
}) => {
  const [activeTab, setActiveTab] = useState<'demo' | 'zip' | 'github' | 'url'>('demo');
  const [githubUrl, setGithubUrl] = useState('');
  const [websiteUrl, setWebsiteUrl] = useState('');
  const [errorMsg, setErrorMsg] = useState('');
  const [dragOver, setDragOver] = useState(false);

  const handleUrlSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!websiteUrl.trim()) return;
    setErrorMsg('');
    setIsLoading(true);
    try {
      const proj = await scanWebsiteUrl(websiteUrl.trim());
      onProjectLoaded(proj);
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to inspect website URL');
    } finally {
      setIsLoading(false);
    }
  };

  const handleDemoClick = async () => {
    setErrorMsg('');
    setIsLoading(true);
    try {
      const proj = await loadDemoProject();
      onProjectLoaded(proj);
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to load demo project');
    } finally {
      setIsLoading(false);
    }
  };

  const handleFileUpload = async (file: File) => {
    if (!file.name.toLowerCase().endsWith('.zip')) {
      setErrorMsg('Please select a .zip archive file.');
      return;
    }
    setErrorMsg('');
    setIsLoading(true);
    try {
      const proj = await uploadZipProject(file);
      onProjectLoaded(proj);
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to process ZIP file');
    } finally {
      setIsLoading(false);
    }
  };

  const handleGithubSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!githubUrl.trim()) return;
    setErrorMsg('');
    setIsLoading(true);
    try {
      const proj = await importGithubProject(githubUrl.trim());
      onProjectLoaded(proj);
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to import GitHub repository');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="bg-white rounded-3xl border border-surface-border p-6 sm:p-8 shadow-card mb-8">
      <div className="text-center max-w-xl mx-auto mb-6">
        <h2 className="text-xl sm:text-2xl font-bold text-slate-900">
          Step 1: Choose Your Project
        </h2>
        <p className="text-sm text-slate-500 mt-1">
          Pick how you'd like to load source code into your isolated test sandbox.
        </p>
      </div>

      {/* Tabs selector */}
      <div className="flex p-1.5 bg-slate-100 rounded-2xl max-w-md mx-auto mb-6">
        <button
          type="button"
          onClick={() => { setActiveTab('demo'); setErrorMsg(''); }}
          className={`flex-1 flex items-center justify-center gap-2 py-2.5 rounded-xl text-xs sm:text-sm font-semibold transition-all ${
            activeTab === 'demo'
              ? 'bg-white text-brand-blue shadow-sm'
              : 'text-slate-600 hover:text-slate-900'
          }`}
        >
          <PlayCircle className="w-4 h-4 text-brand-mint" />
          <span>Interactive Demo</span>
        </button>

        <button
          type="button"
          onClick={() => { setActiveTab('zip'); setErrorMsg(''); }}
          className={`flex-1 flex items-center justify-center gap-2 py-2.5 rounded-xl text-xs sm:text-sm font-semibold transition-all ${
            activeTab === 'zip'
              ? 'bg-white text-brand-blue shadow-sm'
              : 'text-slate-600 hover:text-slate-900'
          }`}
        >
          <UploadCloud className="w-4 h-4 text-brand-blue" />
          <span>Upload ZIP</span>
        </button>

        <button
          type="button"
          onClick={() => { setActiveTab('github'); setErrorMsg(''); }}
          className={`flex-1 flex items-center justify-center gap-2 py-2.5 rounded-xl text-xs sm:text-sm font-semibold transition-all ${
            activeTab === 'github'
              ? 'bg-white text-brand-blue shadow-sm'
              : 'text-slate-600 hover:text-slate-900'
          }`}
        >
          <GitBranch className="w-4 h-4 text-slate-700" />
          <span>Public GitHub</span>
        </button>

        <button
          type="button"
          onClick={() => { setActiveTab('url'); setErrorMsg(''); }}
          className={`flex-1 flex items-center justify-center gap-2 py-2.5 rounded-xl text-xs sm:text-sm font-semibold transition-all ${
            activeTab === 'url'
              ? 'bg-white text-brand-blue shadow-sm'
              : 'text-slate-600 hover:text-slate-900'
          }`}
        >
          <Globe className="w-4 h-4 text-emerald-600" />
          <span>Website URL</span>
        </button>
      </div>

      {/* Error alert */}
      {errorMsg && (
        <div className="mb-6 max-w-md mx-auto flex items-start gap-3 p-3.5 rounded-2xl bg-red-50 border border-red-200 text-red-700 text-xs font-medium">
          <ShieldAlert className="w-4 h-4 flex-shrink-0 mt-0.5" />
          <span>{errorMsg}</span>
        </div>
      )}

      {/* Tab 1: Interactive Demo */}
      {activeTab === 'demo' && (
        <div className="max-w-xl mx-auto text-center p-6 rounded-2xl bg-[#F7FBF8] border border-brand-mint-soft">
          <div className="w-14 h-14 rounded-2xl bg-brand-mint-light text-brand-mint flex items-center justify-center mx-auto mb-4 border border-brand-mint-soft shadow-sm">
            <PlayCircle className="w-7 h-7 stroke-[2.2]" />
          </div>
          <h3 className="text-lg font-bold text-slate-900">
            Deliberately Vulnerable Notes & Attachments App
          </h3>
          <p className="text-sm text-slate-600 mt-2 leading-relaxed">
            Ready to explore right away! This built-in demonstration contains 4 real planted cases: 
            <strong className="text-slate-800"> SQL injection</strong>, 
            <strong className="text-slate-800"> broken access control (IDOR)</strong>, 
            <strong className="text-slate-800"> path traversal</strong>, and 
            <strong className="text-slate-800"> an integer-cast filter</strong> that proves our false-positive detector.
          </p>

          <button
            type="button"
            disabled={isLoading}
            onClick={handleDemoClick}
            className="mt-6 inline-flex items-center gap-2.5 px-6 py-3 rounded-2xl bg-brand-mint text-white font-bold text-sm shadow-soft hover:bg-emerald-600 active:scale-95 transition-all disabled:opacity-50 disabled:cursor-wait"
          >
            {isLoading ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                <span>Loading Demo App...</span>
              </>
            ) : (
              <>
                <span>Load Demonstration Project</span>
                <ArrowRight className="w-4 h-4" />
              </>
            )}
          </button>
        </div>
      )}

      {/* Tab 2: Upload ZIP */}
      {activeTab === 'zip' && (
        <div className="max-w-xl mx-auto">
          <div
            onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
            onDragLeave={() => setDragOver(false)}
            onDrop={(e) => {
              e.preventDefault();
              setDragOver(false);
              if (e.dataTransfer.files && e.dataTransfer.files[0]) {
                handleFileUpload(e.dataTransfer.files[0]);
              }
            }}
            className={`border-2 border-dashed rounded-2xl p-8 text-center transition-all ${
              dragOver
                ? 'border-brand-blue bg-brand-blue-light'
                : 'border-slate-300 hover:border-slate-400 bg-slate-50/50'
            }`}
          >
            <div className="w-12 h-12 rounded-2xl bg-brand-blue-light text-brand-blue flex items-center justify-center mx-auto mb-3">
              <UploadCloud className="w-6 h-6" />
            </div>
            <h4 className="text-base font-bold text-slate-800">
              Drag and drop your project ZIP here
            </h4>
            <p className="text-xs text-slate-500 mt-1 mb-4">
              Maximum 25 MB &bull; Zip-slip protected &bull; Extracted into an isolated sandbox
            </p>

            <label className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-brand-blue text-white font-semibold text-xs cursor-pointer hover:bg-blue-700 transition-colors shadow-sm">
              <FileArchive className="w-4 h-4" />
              <span>Browse ZIP File</span>
              <input
                type="file"
                accept=".zip"
                className="hidden"
                disabled={isLoading}
                onChange={(e) => {
                  if (e.target.files && e.target.files[0]) {
                    handleFileUpload(e.target.files[0]);
                  }
                }}
              />
            </label>
          </div>
        </div>
      )}

      {/* Tab 3: GitHub Import */}
      {activeTab === 'github' && (
        <form onSubmit={handleGithubSubmit} className="max-w-xl mx-auto">
          <div className="p-6 rounded-2xl bg-slate-50 border border-slate-200">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-10 h-10 rounded-xl bg-slate-900 text-white flex items-center justify-center">
                <GitBranch className="w-5 h-5" />
              </div>
              <div>
                <h4 className="text-sm font-bold text-slate-900">Import Public Repository</h4>
                <p className="text-xs text-slate-500">Only public repositories with source code are supported.</p>
              </div>
            </div>

            <div className="flex flex-col sm:flex-row gap-2">
              <input
                type="url"
                required
                placeholder="https://github.com/owner/repository"
                value={githubUrl}
                onChange={(e) => setGithubUrl(e.target.value)}
                className="flex-1 px-4 py-2.5 rounded-xl border border-slate-300 text-sm focus:border-brand-blue focus:ring-1 focus:ring-brand-blue outline-none"
              />
              <button
                type="submit"
                disabled={isLoading}
                className="inline-flex items-center justify-center gap-2 px-5 py-2.5 rounded-xl bg-slate-900 text-white font-semibold text-sm hover:bg-slate-800 transition-colors disabled:opacity-50"
              >
                {isLoading ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    <span>Importing...</span>
                  </>
                ) : (
                  <span>Import & Inspect</span>
                )}
              </button>
            </div>
            <p className="text-[11px] text-slate-400 mt-2">
              Downloads the latest public archive snapshot. No code execution occurs during import.
            </p>
          </div>
        </form>
      )}

      {/* Tab 4: Live Website URL */}
      {activeTab === 'url' && (
        <form onSubmit={handleUrlSubmit} className="max-w-xl mx-auto">
          <div className="p-6 rounded-2xl bg-emerald-50/50 border border-emerald-200">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-10 h-10 rounded-xl bg-emerald-700 text-white flex items-center justify-center">
                <Globe className="w-5 h-5" />
              </div>
              <div>
                <h4 className="text-sm font-bold text-slate-900">Inspect Live Website URL</h4>
                <p className="text-xs text-slate-500">Non-invasive live HTTP header, SSL/TLS, and defense shield audit.</p>
              </div>
            </div>

            <div className="flex flex-col sm:flex-row gap-2">
              <input
                type="text"
                required
                placeholder="https://example.com"
                value={websiteUrl}
                onChange={(e) => setWebsiteUrl(e.target.value)}
                className="flex-1 px-4 py-2.5 rounded-xl border border-slate-300 text-sm focus:border-brand-mint focus:ring-1 focus:ring-brand-mint outline-none bg-white"
              />
              <button
                type="submit"
                disabled={isLoading}
                className="inline-flex items-center justify-center gap-2 px-5 py-2.5 rounded-xl bg-emerald-700 text-white font-semibold text-sm hover:bg-emerald-800 transition-colors disabled:opacity-50"
              >
                {isLoading ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    <span>Auditing...</span>
                  </>
                ) : (
                  <span>Audit Website</span>
                )}
              </button>
            </div>
            <p className="text-[11px] text-slate-400 mt-2">
              Performs safe HTTP security header checks (CSP, HSTS, X-Frame-Options) and SSL/TLS validation. No penetration attack payloads sent.
            </p>
          </div>
        </form>
      )}
    </div>
  );
};
