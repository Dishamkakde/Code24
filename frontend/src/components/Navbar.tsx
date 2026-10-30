import React from 'react';
import { ShieldCheck, BookOpen, FolderGit2, FileText, Sparkles, Home } from 'lucide-react';

interface NavbarProps {
  currentTab: 'home' | 'projects' | 'learn' | 'reports';
  onSelectTab: (tab: 'home' | 'projects' | 'learn' | 'reports') => void;
  activeProjectName?: string;
}

export const Navbar: React.FC<NavbarProps> = ({ currentTab, onSelectTab, activeProjectName }) => {
  return (
    <header className="sticky top-0 z-40 bg-surface/90 backdrop-blur-md border-b border-surface-border">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-18">
          {/* Brand Identity */}
          <div 
            onClick={() => onSelectTab('home')}
            className="flex items-center gap-3 cursor-pointer group"
          >
            <div className="w-11 h-11 rounded-2xl bg-gradient-to-tr from-brand-blue to-brand-mint flex items-center justify-center text-white shadow-soft group-hover:scale-105 transition-transform">
              <ShieldCheck className="w-6 h-6 stroke-[2.2]" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xl font-bold tracking-tight text-slate-900">
                  DAM<span className="text-brand-blue">age</span> <span className="text-brand-mint">CTRL</span>
                </span>
                <span className="text-[11px] font-semibold bg-brand-mint-light text-brand-mint px-2 py-0.5 rounded-full border border-brand-mint-soft">
                  Friendly Security
                </span>
              </div>
              <p className="text-xs text-slate-500 font-medium">Find the Flaw. Prove the Fix.</p>
            </div>
          </div>

          {/* Navigation Links */}
          <nav className="flex items-center gap-1 sm:gap-2">
            <button
              onClick={() => onSelectTab('home')}
              className={`flex items-center gap-2 px-3.5 py-2 rounded-xl text-sm font-semibold transition-colors ${
                currentTab === 'home'
                  ? 'bg-brand-blue text-white shadow-soft'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
              }`}
            >
              <Home className="w-4 h-4" />
              <span>Workspace</span>
            </button>

            <button
              onClick={() => onSelectTab('projects')}
              className={`flex items-center gap-2 px-3.5 py-2 rounded-xl text-sm font-semibold transition-colors ${
                currentTab === 'projects'
                  ? 'bg-brand-blue text-white shadow-soft'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
              }`}
            >
              <FolderGit2 className="w-4 h-4" />
              <span>My Projects</span>
            </button>

            <button
              onClick={() => onSelectTab('learn')}
              className={`flex items-center gap-2 px-3.5 py-2 rounded-xl text-sm font-semibold transition-colors ${
                currentTab === 'learn'
                  ? 'bg-brand-blue text-white shadow-soft'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
              }`}
            >
              <BookOpen className="w-4 h-4" />
              <span>Learn (ELI12)</span>
            </button>

            <button
              onClick={() => onSelectTab('reports')}
              className={`flex items-center gap-2 px-3.5 py-2 rounded-xl text-sm font-semibold transition-colors ${
                currentTab === 'reports'
                  ? 'bg-brand-blue text-white shadow-soft'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
              }`}
            >
              <FileText className="w-4 h-4" />
              <span>Reports</span>
            </button>
          </nav>

          {/* Active project pill / Safe badge */}
          <div className="hidden md:flex items-center gap-2">
            {activeProjectName ? (
              <div className="flex items-center gap-2 bg-amber-50 border border-amber-200 text-amber-800 text-xs px-3 py-1.5 rounded-full font-medium">
                <Sparkles className="w-3.5 h-3.5 text-amber-600" />
                <span className="truncate max-w-[150px]">{activeProjectName}</span>
              </div>
            ) : (
              <div className="flex items-center gap-1.5 text-xs text-slate-500 bg-slate-100 px-3 py-1.5 rounded-full font-medium">
                <div className="w-2 h-2 rounded-full bg-brand-mint animate-pulse" />
                <span>Isolated Sandbox Ready</span>
              </div>
            )}
          </div>
        </div>
      </div>
    </header>
  );
};
