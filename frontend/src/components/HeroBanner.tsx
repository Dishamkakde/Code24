import React from 'react';
import { Shield, Sparkles, CheckCircle, Lock, EyeOff } from 'lucide-react';

export const HeroBanner: React.FC = () => {
  return (
    <div className="relative overflow-hidden rounded-3xl bg-gradient-to-b from-white to-[#F9FAF8] border border-surface-border p-8 sm:p-10 shadow-soft mb-8">
      {/* Soft decorative glow */}
      <div className="absolute top-0 right-0 -mt-10 -mr-10 w-72 h-72 bg-brand-mint-light rounded-full blur-3xl opacity-60 pointer-events-none" />
      <div className="absolute bottom-0 left-10 -mb-10 w-72 h-72 bg-brand-blue-light rounded-full blur-3xl opacity-60 pointer-events-none" />

      <div className="relative z-10 max-w-3xl">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-brand-mint-light border border-brand-mint-soft text-brand-mint text-xs font-bold tracking-wide uppercase mb-4">
          <Sparkles className="w-3.5 h-3.5" />
          <span>Security Made Simple For Everyone</span>
        </div>

        <h1 className="text-3xl sm:text-4xl lg:text-5xl font-extrabold text-slate-900 tracking-tight leading-tight">
          Let's make your website safer!
        </h1>

        <p className="mt-4 text-base sm:text-lg text-slate-600 leading-relaxed font-normal">
          Cybersecurity shouldn't require a degree. <strong className="font-semibold text-slate-900">DAMage CTRL</strong> scans your website's source code, translates security risks into friendly everyday stories, suggests minimal defensive code fixes, and <span className="underline decoration-brand-mint decoration-2 underline-offset-4 font-semibold text-slate-800">actually tests the fix</span> to prove it works before you touch your original files.
        </p>

        {/* Safety guarantees & privacy notice */}
        <div className="mt-6 pt-6 border-t border-slate-100 flex flex-wrap items-center gap-y-3 gap-x-6 text-xs text-slate-500 font-medium">
          <div className="flex items-center gap-1.5 text-slate-700">
            <CheckCircle className="w-4 h-4 text-brand-mint flex-shrink-0" />
            <span>Examines local source code (not live websites)</span>
          </div>
          <div className="flex items-center gap-1.5 text-slate-700">
            <EyeOff className="w-4 h-4 text-brand-blue flex-shrink-0" />
            <span>Never asks for passwords or API keys</span>
          </div>
          <div className="flex items-center gap-1.5 text-slate-700">
            <Lock className="w-4 h-4 text-amber-500 flex-shrink-0" />
            <span>Original files are never silently modified</span>
          </div>
        </div>
      </div>
    </div>
  );
};
