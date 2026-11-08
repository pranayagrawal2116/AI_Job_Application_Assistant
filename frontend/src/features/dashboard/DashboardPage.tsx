import React, { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '@/features/auth/AuthContext';
import { api } from '@/lib/api';
import { DashboardSummary, ApplicationItem } from '@/types';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { getStatusBadgeColor } from '@/lib/utils';
import {
  Sparkles,
  ArrowRight,
  Briefcase,
  UploadCloud,
  FileCheck2,
  Clock,
  Send,
  Calendar,
  Building2,
  Compass,
} from 'lucide-react';

export const DashboardPage: React.FC = () => {
  const { user } = useAuth();
  const navigate = useNavigate();

  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [recentApps, setRecentApps] = useState<ApplicationItem[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [sum, apps] = await Promise.all([
          api.getDashboardSummary(),
          api.getApplications(),
        ]);
        setSummary(sum);
        setRecentApps(apps.slice(0, 5));
      } catch (e) {
        console.error('Failed to load dashboard data:', e);
      } finally {
        setIsLoading(false);
      }
    };
    fetchData();
  }, []);

  if (isLoading) {
    return (
      <div className="py-20 flex justify-center">
        <LoadingSpinner size={32} />
      </div>
    );
  }

  const completeness = summary?.profile_completeness || 0;

  return (
    <div className="space-y-8 animate-fade-in">
      {/* 1. Header greeting & profile completeness */}
      <div className="bg-gradient-to-r from-brand-900 via-indigo-900 to-slate-900 rounded-3xl p-6 sm:p-8 text-white relative overflow-hidden shadow-xl shadow-brand-950/10">
        <div className="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-6">
          <div className="max-w-xl">
            <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-white/10 text-white/90 text-xs font-semibold backdrop-blur-md mb-3 border border-white/10">
              <Sparkles size={13} className="text-brand-300" />
              <span>Candidate Command Center{summary?.category_label ? ` · ${summary.category_label}` : ''}</span>
            </span>
            <h1 className="text-2xl sm:text-3xl font-extrabold tracking-tight">
              Good day, {user?.full_name || 'Candidate'}
            </h1>
            <p className="mt-1.5 text-sm text-slate-300 leading-relaxed">
              You have <strong className="text-white">{summary?.eligible_matches_count ?? summary?.eligible_opportunities ?? 0}</strong> verified
              eligible opportunities ({summary?.total_catalog_jobs ?? summary?.total_opportunities ?? 0} active in catalogue).
            </p>
          </div>

          {/* Profile completeness card */}
          <div className="bg-white/10 backdrop-blur-md rounded-2xl p-4 border border-white/10 flex items-center gap-4 shrink-0">
            <div className="relative w-14 h-14 flex items-center justify-center">
              <svg className="w-14 h-14 -rotate-90">
                <circle
                  cx="28"
                  cy="28"
                  r="22"
                  className="stroke-white/20"
                  strokeWidth="5"
                  fill="transparent"
                />
                <circle
                  cx="28"
                  cy="28"
                  r="22"
                  className="stroke-brand-400 transition-all duration-1000 ease-out"
                  strokeWidth="5"
                  strokeDasharray="138.2"
                  strokeDashoffset={138.2 - (138.2 * completeness) / 100}
                  strokeLinecap="round"
                  fill="transparent"
                />
              </svg>
              <span className="absolute text-xs font-bold text-white">{completeness}%</span>
            </div>
            <div>
              <p className="text-xs font-bold text-white">Profile Readiness</p>
              <p className="text-[11px] text-slate-300 mt-0.5">
                {completeness >= 80
                  ? 'Application Ready'
                  : summary?.missing_sections && summary.missing_sections.length > 0
                  ? `Pending: ${summary.missing_sections[0]}`
                  : 'Needs more details'}
              </p>
              <Link
                to="/profile"
                className="text-[11px] font-semibold text-brand-300 hover:text-white underline mt-1 block"
              >
                Complete profile &rarr;
              </Link>
            </div>
          </div>
        </div>
      </div>

      {/* 2. Recommended Next Action Banner */}
      {summary?.recommended_action && (
        <div className="bg-white rounded-2xl p-5 border border-slate-200/80 shadow-sm flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-start gap-3.5">
            <div className="w-10 h-10 rounded-xl bg-amber-50 text-amber-600 border border-amber-200/60 flex items-center justify-center shrink-0">
              <Sparkles size={20} />
            </div>
            <div>
              <span className="text-[10px] font-bold uppercase tracking-wider text-amber-700 bg-amber-50 px-2 py-0.5 rounded-full border border-amber-200">
                Recommended Next Step
              </span>
              <h3 className="text-sm font-bold text-slate-900 mt-1">
                {summary.recommended_action.title}
              </h3>
              <p className="text-xs text-slate-500 mt-0.5">
                {summary.recommended_action.description}
              </p>
            </div>
          </div>
          <button
            onClick={() => navigate(summary.recommended_action.cta_url)}
            className="px-5 py-2.5 rounded-xl bg-brand-600 hover:bg-brand-700 text-white font-semibold text-xs shadow-md shadow-brand-500/20 flex items-center gap-1.5 self-start sm:self-center shrink-0 transition-all"
          >
            <span>{summary.recommended_action.cta_label}</span>
            <ArrowRight size={14} />
          </button>
        </div>
      )}

      {/* 3. Pipeline Metric Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4">
        {[
          { label: 'Saved', count: summary?.saved_count || 0, icon: Compass, color: 'text-slate-600 bg-slate-100' },
          { label: 'Preparing', count: summary?.preparing_count || 0, icon: Clock, color: 'text-blue-600 bg-blue-50' },
          { label: 'Review Ready', count: summary?.review_count || 0, icon: FileCheck2, color: 'text-purple-600 bg-purple-50' },
          { label: 'Submitted', count: summary?.submitted_count || 0, icon: Send, color: 'text-emerald-600 bg-emerald-50' },
          { label: 'Interviews', count: summary?.interview_count || 0, icon: Calendar, color: 'text-amber-600 bg-amber-50' },
        ].map((metric) => {
          const Icon = metric.icon;
          return (
            <div
              key={metric.label}
              className="bg-white rounded-2xl p-5 border border-slate-200/80 shadow-sm flex flex-col justify-between"
            >
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-slate-500">{metric.label}</span>
                <div className={`p-2 rounded-xl ${metric.color}`}>
                  <Icon size={16} />
                </div>
              </div>
              <div className="mt-4">
                <span className="text-2xl font-extrabold text-slate-900">{metric.count}</span>
              </div>
            </div>
          );
        })}
      </div>

      {/* 4. Active Applications & Quick Actions */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left: Recent applications table (2 cols) */}
        <div className="lg:col-span-2 bg-white rounded-3xl p-6 border border-slate-200/80 shadow-sm space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-base font-bold text-slate-900">Active Applications</h3>
              <p className="text-xs text-slate-500">Track and prepare your recent job applications</p>
            </div>
            <Link
              to="/applications"
              className="text-xs font-semibold text-brand-600 hover:text-brand-700 flex items-center gap-1"
            >
              <span>View all</span>
              <ArrowRight size={14} />
            </Link>
          </div>

          {recentApps.length === 0 ? (
            <div className="py-12 text-center text-slate-400">
              <Briefcase size={36} className="mx-auto mb-2 text-slate-300" />
              <p className="text-sm font-medium text-slate-600">No applications yet</p>
              <p className="text-xs text-slate-400 mt-1">
                Explore catalog opportunities or add a job to get started.
              </p>
              <Link
                to="/jobs"
                className="mt-4 inline-flex items-center gap-1.5 px-4 py-2 rounded-xl bg-brand-50 text-brand-700 font-semibold text-xs border border-brand-200 hover:bg-brand-100 transition-colors"
              >
                <span>Find Jobs</span>
                <ArrowRight size={13} />
              </Link>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-slate-100 text-slate-400 font-medium">
                    <th className="pb-3 font-semibold">Company & Role</th>
                    <th className="pb-3 font-semibold">Status</th>
                    <th className="pb-3 font-semibold">Location</th>
                    <th className="pb-3 text-right font-semibold">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {recentApps.map((app) => (
                    <tr key={app.id} className="hover:bg-slate-50/60 transition-colors">
                      <td className="py-3.5 pr-3">
                        <div className="font-bold text-slate-900">{app.job_title}</div>
                        <div className="text-slate-500 flex items-center gap-1 mt-0.5">
                          <Building2 size={12} className="text-slate-400" />
                          <span>{app.company_name}</span>
                        </div>
                      </td>
                      <td className="py-3.5 pr-3">
                        <span
                          className={`inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-semibold border ${getStatusBadgeColor(
                            app.status
                          )}`}
                        >
                          {app.status}
                        </span>
                      </td>
                      <td className="py-3.5 pr-3 text-slate-500">{app.location || 'Remote'}</td>
                      <td className="py-3.5 text-right">
                        <Link
                          to={`/applications/${app.id}/prepare`}
                          className="px-3 py-1.5 rounded-lg bg-brand-50 hover:bg-brand-100 text-brand-700 font-semibold text-xs border border-brand-200 transition-colors"
                        >
                          Prepare
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Right: Quick Actions & Tips (1 col) */}
        <div className="space-y-4">
          <div className="bg-white rounded-3xl p-6 border border-slate-200/80 shadow-sm space-y-4">
            <h3 className="text-base font-bold text-slate-900">Quick Actions</h3>
            <div className="space-y-2.5">
              <Link
                to="/jobs"
                className="w-full flex items-center justify-between p-3.5 rounded-2xl bg-slate-50 hover:bg-brand-50/60 border border-slate-100 hover:border-brand-200 transition-all group"
              >
                <div className="flex items-center gap-3">
                  <div className="w-8 h-8 rounded-xl bg-blue-100 text-blue-700 flex items-center justify-center">
                    <Compass size={16} />
                  </div>
                  <div className="text-left">
                    <p className="text-xs font-bold text-slate-800">Find Jobs</p>
                    <p className="text-[11px] text-slate-400">
                      Explore {summary?.total_catalog_jobs || 50}+ opportunities
                    </p>
                  </div>
                </div>
                <ArrowRight size={14} className="text-slate-400 group-hover:text-brand-600" />
              </Link>

              <Link
                to="/profile?tab=resumes"
                className="w-full flex items-center justify-between p-3.5 rounded-2xl bg-slate-50 hover:bg-brand-50/60 border border-slate-100 hover:border-brand-200 transition-all group"
              >
                <div className="flex items-center gap-3">
                  <div className="w-8 h-8 rounded-xl bg-purple-100 text-purple-700 flex items-center justify-center">
                    <UploadCloud size={16} />
                  </div>
                  <div className="text-left">
                    <p className="text-xs font-bold text-slate-800">Upload Resume</p>
                    <p className="text-[11px] text-slate-400">PDF or DOCX parsing</p>
                  </div>
                </div>
                <ArrowRight size={14} className="text-slate-400 group-hover:text-brand-600" />
              </Link>

              <Link
                to="/applications"
                className="w-full flex items-center justify-between p-3.5 rounded-2xl bg-slate-50 hover:bg-brand-50/60 border border-slate-100 hover:border-brand-200 transition-all group"
              >
                <div className="flex items-center gap-3">
                  <div className="w-8 h-8 rounded-xl bg-emerald-100 text-emerald-700 flex items-center justify-center">
                    <Send size={16} />
                  </div>
                  <div className="text-left">
                    <p className="text-xs font-bold text-slate-800">Track Applications</p>
                    <p className="text-[11px] text-slate-400">Kanban & timeline tracker</p>
                  </div>
                </div>
                <ArrowRight size={14} className="text-slate-400 group-hover:text-brand-600" />
              </Link>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
