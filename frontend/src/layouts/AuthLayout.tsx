import React from 'react';
import { Outlet, Navigate } from 'react-router-dom';
import { useAuth } from '@/features/auth/AuthContext';
import { Sparkles, CheckCircle2, ShieldAlert } from 'lucide-react';

export const AuthLayout: React.FC = () => {
  const { isAuthenticated, isLoading } = useAuth();

  if (!isLoading && isAuthenticated) {
    return <Navigate to="/dashboard" replace />;
  }

  return (
    <div className="min-h-screen bg-slate-900 flex">
      {/* Left side: Branding & Hero pitch */}
      <div className="hidden lg:flex lg:w-1/2 flex-col justify-between p-12 bg-gradient-to-br from-brand-950 via-slate-900 to-indigo-950 text-white border-r border-slate-800">
        <div>
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-2xl bg-gradient-to-tr from-brand-500 to-indigo-500 flex items-center justify-center text-white shadow-lg shadow-brand-500/30">
              <Sparkles size={22} />
            </div>
            <span className="font-extrabold text-2xl tracking-tight">JobFlow AI</span>
          </div>
          <div className="mt-20 max-w-lg">
            <h1 className="text-4xl font-extrabold tracking-tight leading-tight">
              Land your dream job with zero hallucinations.
            </h1>
            <p className="mt-4 text-slate-400 text-base leading-relaxed">
              Match your verified resume against thousands of opportunities. Generate ATS-optimized
              tailored resumes and cover letters with strict human-in-the-loop audit authorization.
            </p>
          </div>
        </div>

        <div className="space-y-4 max-w-md">
          <div className="flex items-start gap-3">
            <CheckCircle2 size={18} className="text-emerald-400 mt-1 shrink-0" />
            <p className="text-sm text-slate-300">
              <strong className="text-white">Zero Fabrication Guarantee:</strong> Every claim, skill, and bullet is grounded strictly in your verified background.
            </p>
          </div>
          <div className="flex items-start gap-3">
            <ShieldAlert size={18} className="text-indigo-400 mt-1 shrink-0" />
            <p className="text-sm text-slate-300">
              <strong className="text-white">Strict Human Control:</strong> Applications are never submitted automatically. You review, approve, and confirm every portal submission.
            </p>
          </div>
        </div>

        <div className="text-xs text-slate-500">
          Universal AI Job Application Assistant &middot; Architecture v2.1.1
        </div>
      </div>

      {/* Right side: Auth form */}
      <div className="w-full lg:w-1/2 flex items-center justify-center p-6 sm:p-12 bg-white">
        <div className="w-full max-w-md">
          <Outlet />
        </div>
      </div>
    </div>
  );
};
