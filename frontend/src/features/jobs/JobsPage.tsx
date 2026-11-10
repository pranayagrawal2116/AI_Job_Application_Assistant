import React, { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '@/lib/api';
import { DiscoveryStatus, InferredRole, JobItem, JobMatchExplanation } from '@/types';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { Badge } from '@/components/common/Badge';
import { Modal } from '@/components/common/Modal';
import { FileDropzone } from '@/components/common/FileDropzone';
import { formatScore, getScoreColor } from '@/lib/utils';
import { JobCardSkeletonGrid } from './JobCardSkeleton';
import {
  Search,
  Bookmark,
  BookmarkCheck,
  Building2,
  MapPin,
  Banknote,
  Clock,
  CheckCircle2,
  XCircle,
  Plus,
  ExternalLink,
  Filter,
  FileText,
  Link as LinkIcon,
  Upload,
  Sparkles,
  Compass,
  RefreshCw,
  X,
  Info,
  Check,
  AlertTriangle,
} from 'lucide-react';

type FeedState =
  | 'initial_loading'
  | 'no_resume_uploaded'
  | 'discovering'
  | 'ready_with_jobs'
  | 'empty_no_matches'
  | 'partial_discovery'
  | 'discovery_failed';

export const JobsPage: React.FC = () => {
  const navigate = useNavigate();

  const [activeTab, setActiveTab] = useState<'all' | 'saved' | 'add'>('all');
  const [jobs, setJobs] = useState<JobItem[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [feedState, setFeedState] = useState<FeedState>('initial_loading');
  const [discoveryError, setDiscoveryError] = useState<string | null>(null);
  const initialWorkflowStartedRef = useRef(false);

  // Discovery engine state & suggested career paths
  const [discoveryStatus, setDiscoveryStatus] = useState<DiscoveryStatus | null>(null);
  const [suggestedRoles, setSuggestedRoles] = useState<InferredRole[]>([]);
  const [selectedRoleFilter, setSelectedRoleFilter] = useState<string | null>(null);
  const [isTriggeringDiscovery, setIsTriggeringDiscovery] = useState(false);
  const [discoveryNotification, setDiscoveryNotification] = useState<string | null>(null);

  // Filters
  const [searchTerm, setSearchTerm] = useState('');
  const [arrangement, setArrangement] = useState('');
  const [platform, setPlatform] = useState('');
  const [onlyEligible, setOnlyEligible] = useState(false);
  const [minScore, setMinScore] = useState<number>(0);

  // Selected job for detail / match explanation modal
  const [selectedJob, setSelectedJob] = useState<JobItem | null>(null);
  const [matchExplanation, setMatchExplanation] = useState<JobMatchExplanation | null>(null);
  const [isLoadingExplanation, setIsLoadingExplanation] = useState(false);

  // Add Job Manually modal/tab state
  const [manualMode, setManualMode] = useState<'text' | 'file' | 'url'>('text');
  const [pastedText, setPastedText] = useState('');
  const [hintCompany, setHintCompany] = useState('');
  const [hintTitle, setHintTitle] = useState('');
  const [jobUrlInput, setJobUrlInput] = useState('');
  const [jdFile, setJdFile] = useState<File | null>(null);
  const [isSubmittingJd, setIsSubmittingJd] = useState(false);
  const [jdError, setJdError] = useState<string | null>(null);
  const [jdSuccess, setJdSuccess] = useState<string | null>(null);

  const loadJobsInternal = async () => {
    setIsLoading(true);
    try {
      const data = await api.getJobs({
        search: (selectedRoleFilter || searchTerm) || undefined,
        arrangement: arrangement || undefined,
        platform: platform || undefined,
        only_eligible: onlyEligible || undefined,
        min_score: minScore > 0 ? minScore : undefined,
        saved_only: activeTab === 'saved',
        recommended_only: !searchTerm && activeTab !== 'saved',
      });
      setJobs(data);
      if (data.length > 0) {
        setFeedState((prev) => (prev === 'partial_discovery' ? 'partial_discovery' : 'ready_with_jobs'));
      } else {
        setFeedState('empty_no_matches');
      }
    } catch (e) {
      console.error('Failed to fetch jobs:', e);
      setFeedState('empty_no_matches');
    } finally {
      setIsLoading(false);
    }
  };

  const pollDiscoveryRun = (runId: number) => {
    setIsTriggeringDiscovery(true);
    const pollInterval = 2000;

    const checkStatus = async () => {
      try {
        const run = await api.getDiscoveryRun(runId);
        if (!run) {
          setIsTriggeringDiscovery(false);
          await loadJobsInternal();
          return;
        }

        if (run.status === 'COMPLETED') {
          setIsTriggeringDiscovery(false);
          const found = run.total_discovered ?? run.jobs_found ?? ((run.new_jobs_saved ?? 0) + (run.duplicates_skipped ?? 0));
          const saved = run.new_jobs_saved ?? run.jobs_saved ?? 0;
          const skipped = run.duplicates_skipped ?? 0;
          setDiscoveryNotification(
            `Discovery completed! Found ${found} opportunities (${saved} new saved, ${skipped} duplicates skipped).`
          );
          await loadDiscoveryMeta();
          await loadJobsInternal();
          return;
        }

        if (run.status === 'PARTIAL') {
          setIsTriggeringDiscovery(false);
          setFeedState('partial_discovery');
          const found = run.total_discovered ?? run.jobs_found ?? ((run.new_jobs_saved ?? 0) + (run.duplicates_skipped ?? 0));
          const saved = run.new_jobs_saved ?? run.jobs_saved ?? 0;
          const skipped = run.duplicates_skipped ?? 0;
          setDiscoveryNotification(
            `Discovery finished with partial results (${saved} saved of ${found} found, ${skipped} duplicates skipped). Some external sources were restricted.`
          );
          await loadDiscoveryMeta();
          await loadJobsInternal();
          return;
        }

        if (run.status === 'FAILED') {
          setIsTriggeringDiscovery(false);
          setFeedState('discovery_failed');
          const err = run.error_message || 'Discovery failed. Please try again.';
          setDiscoveryError(err);
          setDiscoveryNotification(`Discovery error: ${err}`);
          await loadDiscoveryMeta();
          return;
        }

        // Run still in progress, continue polling
        setTimeout(checkStatus, pollInterval);
      } catch (err: any) {
        console.warn('Error polling discovery run:', err);
        setTimeout(checkStatus, 3000);
      }
    };

    setTimeout(checkStatus, pollInterval);
  };

  const loadDiscoveryMeta = async () => {
    try {
      const statusRes = await api.getDiscoveryStatus();
      setDiscoveryStatus(statusRes);
      if (statusRes.suggested_roles && statusRes.suggested_roles.length > 0) {
        setSuggestedRoles(statusRes.suggested_roles);
      }
      return statusRes;
    } catch (e) {
      return null;
    }
  };

  const initPageWorkflow = async () => {
    setFeedState('initial_loading');
    setIsLoading(true);
    try {
      const statusRes = await loadDiscoveryMeta();
      if (!statusRes) {
        await loadJobsInternal();
        return;
      }

      if (statusRes.has_primary_resume === false) {
        setFeedState('no_resume_uploaded');
        setIsLoading(false);
        return;
      }

      if (statusRes.active_run && (statusRes.active_run.status === 'PENDING' || statusRes.active_run.status === 'RUNNING')) {
        setFeedState('discovering');
        setIsTriggeringDiscovery(true);
        setDiscoveryNotification('Resuming active background discovery run...');
        pollDiscoveryRun(statusRes.active_run.id);
        return;
      }

      if (statusRes.completed_for_current_resume) {
        if (
          statusRes.latest_run?.status === 'PARTIAL' ||
          (statusRes.latest_run?.restricted_count && statusRes.latest_run.restricted_count > 0)
        ) {
          setFeedState('partial_discovery');
        }
        await loadJobsInternal();
        return;
      }

      if (statusRes.latest_run?.status === 'FAILED') {
        const msg = statusRes.latest_run.error_message || 'A previous discovery run failed.';
        setDiscoveryError(msg);
        setFeedState('discovery_failed');
        setIsLoading(false);
        return;
      }

      // First visit for this resume: automatically trigger discovery
      setFeedState('discovering');
      setIsTriggeringDiscovery(true);
      setDiscoveryNotification('Initiating personalized job discovery based on your resume...');
      try {
        const res = await api.triggerDiscovery();
        if (res.run_id) {
          pollDiscoveryRun(res.run_id);
        } else {
          await loadJobsInternal();
        }
      } catch (triggerErr: any) {
        console.error('Auto discovery trigger error:', triggerErr);
        setDiscoveryError(triggerErr.message || 'Discovery could not be started.');
        setFeedState('discovery_failed');
        setIsTriggeringDiscovery(false);
        setIsLoading(false);
      }
    } catch (e) {
      console.error('Initial page workflow failure:', e);
      await loadJobsInternal();
    }
  };

  useEffect(() => {
    if (initialWorkflowStartedRef.current) return;
    initialWorkflowStartedRef.current = true;
    initPageWorkflow();
  }, []);

  useEffect(() => {
    if (activeTab === 'add') return;
    if (
      feedState !== 'initial_loading' &&
      feedState !== 'no_resume_uploaded' &&
      feedState !== 'discovering'
    ) {
      loadJobsInternal();
    }
  }, [activeTab, arrangement, platform, onlyEligible, minScore, selectedRoleFilter]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setSelectedRoleFilter(null);
    loadJobsInternal();
  };

  const handleToggleShortlist = async (jobId: number) => {
    try {
      const res = await api.toggleShortlist(jobId);
      setJobs((prev) =>
        prev.map((j) => (j.id === jobId ? { ...j, is_shortlisted: res.is_shortlisted } : j))
      );
      if (selectedJob && selectedJob.id === jobId) {
        setSelectedJob({ ...selectedJob, is_shortlisted: res.is_shortlisted });
      }
    } catch (err) {
      console.error('Error toggling bookmark:', err);
    }
  };

  const handleStartApplication = async (job: JobItem) => {
    try {
      const app = await api.createApplication({
        company_name: job.company_name,
        job_title: job.job_title,
        job_id: job.id,
      });
      navigate(`/applications/${app.id}/prepare`);
    } catch (err: any) {
      console.error('Failed to start application:', err);
    }
  };

  const handleOpenExplanation = async (job: JobItem) => {
    setSelectedJob(job);
    setIsLoadingExplanation(true);
    setMatchExplanation(null);
    try {
      const exp = await api.getJobMatchExplanation(job.id);
      setMatchExplanation(exp);
    } catch (err) {
      console.warn('Could not load detailed explanation:', err);
    } finally {
      setIsLoadingExplanation(false);
    }
  };

  const handleTriggerDiscovery = async () => {
    setIsTriggeringDiscovery(true);
    setDiscoveryError(null);
    if (jobs.length === 0) {
      setFeedState('discovering');
    }
    setDiscoveryNotification('Initiating job discovery across supported platforms...');
    try {
      const res = await api.triggerDiscovery();
      const runId = res.run_id || res.id;
      if (runId) {
        setDiscoveryNotification(res.message || 'Discovery running in background...');
        pollDiscoveryRun(runId);
      } else {
        setDiscoveryNotification(res.message || 'Discovery started.');
        await loadDiscoveryMeta();
        setTimeout(() => {
          loadJobsInternal();
          setIsTriggeringDiscovery(false);
        }, 1500);
      }
    } catch (err: any) {
      setDiscoveryError(err.message || 'Failed to trigger discovery.');
      setDiscoveryNotification(err.message || 'Failed to trigger discovery.');
      if (jobs.length === 0) {
        setFeedState('discovery_failed');
      }
      setIsTriggeringDiscovery(false);
    }
  };

  const handleManualIngest = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmittingJd(true);
    setJdError(null);
    setJdSuccess(null);

    try {
      let res: any;
      if (manualMode === 'text') {
        res = await api.ingestJobText({
          raw_text: pastedText,
          hint_company: hintCompany,
          hint_title: hintTitle,
        });
      } else if (manualMode === 'file') {
        if (!jdFile) throw new Error('Please select a file.');
        res = await api.ingestJobFile(jdFile, hintTitle, hintCompany);
      } else if (manualMode === 'url') {
        res = await api.ingestJobUrl(jobUrlInput);
      }

      setJdSuccess('Job parsed successfully! Creating application workspace...');
      setTimeout(async () => {
        const app = await api.createApplication({
          company_name: res.company_name || hintCompany || 'Company',
          job_title: res.job_title || hintTitle || 'Target Role',
          job_description_id: res.id,
        });
        navigate(`/applications/${app.id}/prepare`);
      }, 1000);
    } catch (err: any) {
      setJdError(err.message || 'Failed to ingest job.');
      setIsSubmittingJd(false);
    }
  };

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-extrabold text-slate-900 tracking-tight">
            Find Opportunities
          </h1>
          <p className="text-xs text-slate-500 mt-1">
            Personalized job matches scored dynamically against your verified qualifications.
          </p>
        </div>

        {/* Tab Switcher */}
        <div className="flex items-center gap-1.5 p-1 rounded-2xl bg-slate-200/60 self-start sm:self-center">
          <button
            onClick={() => {
              setActiveTab('all');
              setSelectedRoleFilter(null);
            }}
            className={`px-4 py-1.5 rounded-xl text-xs font-bold transition-all ${
              activeTab === 'all'
                ? 'bg-white text-slate-900 shadow-sm'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            Explore Jobs
          </button>
          <button
            onClick={() => setActiveTab('saved')}
            className={`px-4 py-1.5 rounded-xl text-xs font-bold transition-all ${
              activeTab === 'saved'
                ? 'bg-white text-slate-900 shadow-sm'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            Saved Opportunities
          </button>
          <button
            onClick={() => setActiveTab('add')}
            className={`px-4 py-1.5 rounded-xl text-xs font-bold flex items-center gap-1.5 transition-all ${
              activeTab === 'add'
                ? 'bg-white text-slate-900 shadow-sm'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            <Plus size={14} />
            <span>Add Job Manually</span>
          </button>
        </div>
      </div>

      {/* DISCOVERY STATUS BANNER */}
      {activeTab !== 'add' && (
        <div className="p-4 rounded-2xl bg-white border border-slate-200/80 shadow-2xs flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className={`w-8 h-8 rounded-xl flex items-center justify-center shrink-0 ${
              discoveryStatus?.is_running || isTriggeringDiscovery
                ? 'bg-amber-100 text-amber-700 animate-pulse'
                : 'bg-brand-50 text-brand-600'
            }`}>
              <Sparkles size={16} />
            </div>
            <div>
              <p className="text-xs font-bold text-slate-900">
                {discoveryStatus?.is_running || isTriggeringDiscovery
                  ? 'Discovery Scraper Running'
                  : 'Automated Discovery Engine'}
              </p>
              <p className="text-[11px] text-slate-500">
                {discoveryStatus?.is_running || isTriggeringDiscovery
                  ? 'Scanning LinkedIn, Internshala, Indeed & Careers feeds for your verified roles...'
                  : `Personalized ranking active · ${jobs.length} relevant opportunities available.`}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 self-start sm:self-center">
            {discoveryNotification && (
              <span className="text-[11px] font-semibold text-brand-700 bg-brand-50 px-2.5 py-1 rounded-lg border border-brand-100">
                {discoveryNotification}
              </span>
            )}
            <button
              type="button"
              onClick={handleTriggerDiscovery}
              disabled={isTriggeringDiscovery || Boolean(discoveryStatus?.is_running)}
              className="px-3.5 py-1.5 rounded-xl bg-slate-900 hover:bg-slate-800 text-white font-semibold text-xs flex items-center gap-1.5 shadow-2xs transition-all disabled:opacity-50"
            >
              {isTriggeringDiscovery || discoveryStatus?.is_running ? (
                <LoadingSpinner size={12} className="text-white" />
              ) : (
                <RefreshCw size={12} />
              )}
              <span>{isTriggeringDiscovery ? 'Searching...' : 'Refresh Matches'}</span>
            </button>
          </div>
        </div>
      )}

      {/* SUGGESTED CAREER PATHS CHIPS */}
      {activeTab !== 'add' && suggestedRoles.length > 0 && (
        <div className="space-y-1.5">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-1.5 text-xs font-bold text-slate-700">
              <Compass size={14} className="text-brand-600" />
              <span>Suggested Career Paths:</span>
            </div>
            {selectedRoleFilter && (
              <button
                type="button"
                onClick={() => setSelectedRoleFilter(null)}
                className="text-[11px] text-brand-600 hover:text-brand-700 font-semibold flex items-center gap-1"
              >
                <span>Clear role filter</span>
                <X size={12} />
              </button>
            )}
          </div>

          <div className="flex flex-wrap gap-2">
            {suggestedRoles.map((role, idx) => {
              const isSelected = selectedRoleFilter === role.role_title;
              return (
                <button
                  key={idx}
                  type="button"
                  onClick={() => {
                    setSelectedRoleFilter(isSelected ? null : role.role_title);
                  }}
                  className={`px-3 py-1.5 rounded-xl text-xs font-semibold flex items-center gap-1.5 transition-all ${
                    isSelected
                      ? 'bg-brand-600 text-white shadow-2xs'
                      : 'bg-white border border-slate-200/80 text-slate-700 hover:bg-slate-50'
                  }`}
                >
                  <span>{role.role_title}</span>
                  <span
                    className={`px-1.5 py-0.2 rounded-md text-[9px] font-bold ${
                      isSelected ? 'bg-brand-700 text-brand-100' : 'bg-slate-100 text-slate-600'
                    }`}
                  >
                    {Math.round(role.confidence * 100)}%
                  </span>
                  {isSelected && <X size={12} className="ml-0.5" />}
                </button>
              );
            })}
          </div>
        </div>
      )}

      {/* TAB CONTENT: ADD JOB MANUALLY */}
      {activeTab === 'add' ? (
        <div className="max-w-3xl mx-auto bg-white rounded-3xl p-6 sm:p-8 border border-slate-200/80 shadow-sm space-y-6">
          <div>
            <h2 className="text-lg font-bold text-slate-900">Add Custom Job Description</h2>
            <p className="text-xs text-slate-500 mt-0.5">
              Paste job text, upload a document, or ingest an employer URL to evaluate your match and prepare an application.
            </p>
          </div>

          {/* Sub-mode selector */}
          <div className="grid grid-cols-3 gap-3">
            {[
              { id: 'text', label: 'Paste Job Text', icon: FileText },
              { id: 'file', label: 'Upload JD File', icon: Upload },
              { id: 'url', label: 'Ingest URL', icon: LinkIcon },
            ].map((m) => {
              const Icon = m.icon;
              return (
                <button
                  key={m.id}
                  onClick={() => setManualMode(m.id as any)}
                  className={`p-3.5 rounded-2xl border flex flex-col items-center gap-2 text-xs font-bold transition-all ${
                    manualMode === m.id
                      ? 'border-brand-500 bg-brand-50/50 text-brand-700 shadow-sm'
                      : 'border-slate-200 hover:bg-slate-50 text-slate-600'
                  }`}
                >
                  <Icon size={18} />
                  <span>{m.label}</span>
                </button>
              );
            })}
          </div>

          {jdError && (
            <div className="p-4 rounded-xl bg-rose-50 border border-rose-200 text-rose-700 text-xs flex items-center gap-2">
              <XCircle size={16} />
              <span>{jdError}</span>
            </div>
          )}

          {jdSuccess && (
            <div className="p-4 rounded-xl bg-emerald-50 border border-emerald-200 text-emerald-700 text-xs flex items-center gap-2">
              <CheckCircle2 size={16} />
              <span>{jdSuccess}</span>
            </div>
          )}

          <form onSubmit={handleManualIngest} className="space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1">
                  Company Name (Optional)
                </label>
                <input
                  type="text"
                  value={hintCompany}
                  onChange={(e) => setHintCompany(e.target.value)}
                  placeholder="e.g. Google, Stripe"
                  className="w-full px-3.5 py-2.5 rounded-xl border border-slate-200 text-xs focus:ring-2 focus:ring-brand-500 focus:outline-none"
                />
              </div>
              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1">
                  Job Title (Optional)
                </label>
                <input
                  type="text"
                  value={hintTitle}
                  onChange={(e) => setHintTitle(e.target.value)}
                  placeholder="e.g. AI Engineer, Product Manager"
                  className="w-full px-3.5 py-2.5 rounded-xl border border-slate-200 text-xs focus:ring-2 focus:ring-brand-500 focus:outline-none"
                />
              </div>
            </div>

            {manualMode === 'text' && (
              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1">
                  Job Description Text *
                </label>
                <textarea
                  required
                  rows={8}
                  value={pastedText}
                  onChange={(e) => setPastedText(e.target.value)}
                  placeholder="Paste the full job posting, requirements, and responsibilities here..."
                  className="w-full p-3.5 rounded-xl border border-slate-200 text-xs focus:ring-2 focus:ring-brand-500 focus:outline-none"
                />
              </div>
            )}

            {manualMode === 'file' && (
              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1">
                  Upload PDF or DOCX Job Posting *
                </label>
                <FileDropzone
                  id="jd-file-upload"
                  onFileSelect={(file) => setJdFile(file)}
                  selectedFile={jdFile}
                  onClearFile={() => setJdFile(null)}
                  title="Click to select or drop job description"
                  subtitle="PDF or DOCX documents up to 10 MB"
                />
              </div>
            )}

            {manualMode === 'url' && (
              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1">
                  Public Job Posting URL *
                </label>
                <input
                  type="url"
                  required
                  value={jobUrlInput}
                  onChange={(e) => setJobUrlInput(e.target.value)}
                  placeholder="https://jobs.lever.co/company/job-id..."
                  className="w-full px-3.5 py-2.5 rounded-xl border border-slate-200 text-xs focus:ring-2 focus:ring-brand-500 focus:outline-none"
                />
                <p className="text-[11px] text-slate-400 mt-1">
                  Protected against SSRF and private intranet access. Anti-bot walls will trigger a graceful paste fallback.
                </p>
              </div>
            )}

            <button
              type="submit"
              disabled={isSubmittingJd}
              className="w-full py-3 rounded-xl bg-brand-600 hover:bg-brand-700 text-white font-semibold text-xs shadow-md shadow-brand-500/20 flex items-center justify-center gap-2 transition-all disabled:opacity-50"
            >
              {isSubmittingJd ? (
                <>
                  <LoadingSpinner size={16} className="text-white" />
                  <span>Processing Job Description...</span>
                </>
              ) : (
                <span>Analyze Job & Start Application</span>
              )}
            </button>
          </form>
        </div>
      ) : (
        <>
          {/* Search & Filter Bar */}
          <div className="bg-white rounded-2xl p-4 border border-slate-200/80 shadow-sm space-y-3">
            <form onSubmit={handleSearchSubmit} className="flex gap-2">
              <div className="relative flex-1">
                <Search size={18} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400" />
                <input
                  type="text"
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  placeholder="Search by role title, company, or keywords..."
                  className="w-full pl-10 pr-4 py-2.5 rounded-xl border border-slate-200 text-xs focus:ring-2 focus:ring-brand-500 focus:outline-none"
                />
              </div>
              <button
                type="submit"
                className="px-5 py-2.5 rounded-xl bg-brand-600 hover:bg-brand-700 text-white font-semibold text-xs transition-colors shrink-0"
              >
                Search
              </button>
            </form>

            {/* Filter pills */}
            <div className="flex flex-wrap items-center gap-2 pt-2 border-t border-slate-100 text-xs">
              <div className="flex items-center gap-1.5 text-slate-400 font-semibold mr-1">
                <Filter size={14} />
                <span>Filters:</span>
              </div>

              {/* Work Arrangement */}
              <select
                value={arrangement}
                onChange={(e) => setArrangement(e.target.value)}
                className="px-3 py-1.5 rounded-xl border border-slate-200 bg-white text-slate-700 text-xs focus:outline-none"
              >
                <option value="">All Arrangements</option>
                <option value="Remote">Remote</option>
                <option value="Hybrid">Hybrid</option>
                <option value="Onsite">Onsite</option>
              </select>

              {/* Platform */}
              <select
                value={platform}
                onChange={(e) => setPlatform(e.target.value)}
                className="px-3 py-1.5 rounded-xl border border-slate-200 bg-white text-slate-700 text-xs focus:outline-none"
              >
                <option value="">All Platforms</option>
                <option value="LinkedIn">LinkedIn</option>
                <option value="Indeed">Indeed</option>
                <option value="Internshala">Internshala</option>
                <option value="Naukri">Naukri</option>
                <option value="Company Careers">Company Careers</option>
              </select>

              {/* Only Eligible */}
              <button
                type="button"
                onClick={() => setOnlyEligible(!onlyEligible)}
                className={`px-3 py-1.5 rounded-xl border text-xs font-semibold transition-all ${
                  onlyEligible
                    ? 'bg-emerald-50 text-emerald-700 border-emerald-300'
                    : 'bg-white text-slate-600 border-slate-200 hover:bg-slate-50'
                }`}
              >
                {onlyEligible ? '✓ Eligible Only' : 'Show Eligible Only'}
              </button>

              {/* Min Score Slider */}
              <div className="flex items-center gap-2 ml-auto text-slate-500">
                <span>Min Match:</span>
                <input
                  type="range"
                  min="0"
                  max="90"
                  step="10"
                  value={minScore}
                  onChange={(e) => setMinScore(Number(e.target.value))}
                  className="w-20 accent-brand-600 cursor-pointer"
                />
                <span className="font-bold text-slate-800">{minScore}%</span>
              </div>
            </div>
          </div>

          {/* Partial Discovery Notice Banner */}
          {feedState === 'partial_discovery' && (
            <div
              data-testid="partial-discovery-banner"
              className="mb-5 p-4 rounded-2xl bg-amber-50/80 border border-amber-200 text-amber-900 flex items-start gap-3"
            >
              <Info size={18} className="text-amber-600 shrink-0 mt-0.5" />
              <div className="text-xs">
                <span className="font-bold block mb-0.5">Partial Discovery Notice</span>
                <span>
                  Some external job platforms were temporarily restricted or rate-limited. Displaying
                  verified opportunities from accessible sources.
                </span>
              </div>
            </div>
          )}

          {/* Job Cards Grid / Skeletons / Empty States */}
          {(feedState === 'initial_loading' || (feedState === 'discovering' && jobs.length === 0) || (isLoading && jobs.length === 0)) ? (
            <JobCardSkeletonGrid count={6} />
          ) : feedState === 'no_resume_uploaded' ? (
            <div
              data-testid="no-resume-state"
              className="py-16 px-6 text-center bg-white rounded-3xl border border-slate-200/80 shadow-xs max-w-xl mx-auto my-6"
            >
              <div className="w-14 h-14 mx-auto mb-4 bg-brand-50 rounded-2xl flex items-center justify-center text-brand-600 border border-brand-100">
                <Upload size={28} />
              </div>
              <h3 className="text-lg font-bold text-slate-900 mb-2">
                Upload your resume to discover opportunities
              </h3>
              <p className="text-xs text-slate-500 mb-6 leading-relaxed">
                JobFlow AI matches jobs specifically to your verified education, work experience,
                and domain qualifications. Upload your primary resume in your profile to start discovery.
              </p>
              <button
                type="button"
                data-testid="go-to-profile-btn"
                onClick={() => navigate('/profile')}
                className="px-5 py-2.5 rounded-xl bg-brand-600 hover:bg-brand-700 text-white font-semibold text-xs shadow-md shadow-brand-500/20 transition-all inline-flex items-center gap-2 cursor-pointer"
              >
                <Sparkles size={14} />
                <span>Go to My Profile</span>
              </button>
            </div>
          ) : feedState === 'discovery_failed' && jobs.length === 0 ? (
            <div
              data-testid="discovery-failed-state"
              className="py-12 px-6 text-center bg-white rounded-3xl border border-rose-200 shadow-xs max-w-xl mx-auto my-6"
            >
              <div className="w-12 h-12 mx-auto mb-3 bg-rose-50 rounded-2xl flex items-center justify-center text-rose-600 border border-rose-100">
                <AlertTriangle size={24} />
              </div>
              <h3 className="text-base font-bold text-slate-900 mb-1">Discovery Encountered an Issue</h3>
              <p className="text-xs text-rose-700 mb-4">
                {discoveryError || 'Unable to complete opportunity search at this time.'}
              </p>
              <button
                type="button"
                data-testid="retry-discovery-btn"
                onClick={handleTriggerDiscovery}
                className="px-4 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 text-white font-semibold text-xs shadow-xs transition-all inline-flex items-center gap-1.5 cursor-pointer"
              >
                <RefreshCw size={13} />
                <span>Retry Discovery</span>
              </button>
            </div>
          ) : jobs.length === 0 ? (
            <div
              data-testid="empty-jobs-state"
              className="py-16 text-center text-slate-400 bg-white rounded-3xl border border-slate-200"
            >
              <Building2 size={36} className="mx-auto mb-2 text-slate-300" />
              <p className="text-sm font-bold text-slate-700">No opportunities found</p>
              <p className="text-xs text-slate-400 mt-1">
                {searchTerm
                  ? 'Try loosening your filters or search keywords.'
                  : 'Discovery completed with no direct matches. Try adjusting target roles or refreshing.'}
              </p>
              <button
                type="button"
                onClick={handleTriggerDiscovery}
                className="mt-4 px-4 py-2 rounded-xl bg-slate-100 hover:bg-slate-200 text-slate-700 font-semibold text-xs transition-colors inline-flex items-center gap-1.5 cursor-pointer"
              >
                <RefreshCw size={12} />
                <span>Refresh Search</span>
              </button>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
              {jobs.map((job) => (
                <div
                  key={job.id}
                  className="bg-white rounded-3xl p-5 border border-slate-200/80 shadow-sm hover:shadow-md transition-all flex flex-col justify-between"
                >
                  <div>
                    {/* Card Top: Match Score & Bookmark */}
                    <div className="flex items-center justify-between gap-2 mb-3">
                      <div className="flex items-center gap-2">
                        {job.match_score != null ? (
                          <span
                            className={`px-2.5 py-1 rounded-full text-xs font-extrabold border ${getScoreColor(
                              job.match_score
                            )}`}
                          >
                            {formatScore(job.match_score)} Match
                          </span>
                        ) : (
                          <span className="px-2.5 py-1 rounded-full text-xs font-semibold border border-slate-200 bg-slate-50 text-slate-500">
                            Score Pending
                          </span>
                        )}
                        {job.is_eligible === true ? (
                          <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-emerald-700 bg-emerald-50 px-2 py-0.5 rounded-full border border-emerald-200">
                            <CheckCircle2 size={12} />
                            Eligible
                          </span>
                        ) : job.is_eligible === false ? (
                          <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-rose-700 bg-rose-50 px-2 py-0.5 rounded-full border border-rose-200">
                            <XCircle size={12} />
                            Ineligible
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-amber-700 bg-amber-50 px-2 py-0.5 rounded-full border border-amber-200">
                            Pending Evaluation
                          </span>
                        )}
                        {job.source === 'search' && (
                          <span className="inline-flex items-center text-[10px] font-medium text-slate-500 bg-slate-100 px-2 py-0.5 rounded-full border border-slate-200">
                            Search
                          </span>
                        )}
                      </div>

                      <button
                        onClick={() => handleToggleShortlist(job.id)}
                        className={`p-2 rounded-xl transition-colors ${
                          job.is_shortlisted
                            ? 'text-brand-600 bg-brand-50'
                            : 'text-slate-400 hover:text-slate-600 hover:bg-slate-50'
                        }`}
                      >
                        {job.is_shortlisted ? <BookmarkCheck size={18} /> : <Bookmark size={18} />}
                      </button>
                    </div>

                    {/* Job Details */}
                    <div>
                      <h3 className="font-bold text-base text-slate-900 line-clamp-1">
                        {job.job_title}
                      </h3>
                      <p className="text-xs font-semibold text-slate-600 mt-0.5 flex items-center gap-1">
                        <Building2 size={13} className="text-slate-400" />
                        <span>{job.company_name}</span>
                      </p>
                    </div>

                    {/* Metadata chips */}
                    <div className="mt-3 flex flex-wrap gap-2 text-[11px] text-slate-500">
                      <span className="flex items-center gap-1 bg-slate-50 px-2 py-0.5 rounded-md border border-slate-100">
                        <MapPin size={11} className="text-slate-400" />
                        {job.location}
                      </span>
                      <span className="flex items-center gap-1 bg-slate-50 px-2 py-0.5 rounded-md border border-slate-100">
                        <Clock size={11} className="text-slate-400" />
                        {job.work_arrangement}
                      </span>
                      {job.stipend && job.stipend !== 'Not Disclosed' && (
                        <span className="flex items-center gap-1 bg-slate-50 px-2 py-0.5 rounded-md border border-slate-100">
                          <Banknote size={11} className="text-slate-400" />
                          {job.stipend}
                        </span>
                      )}
                    </div>

                    {/* Candidate-specific Matching Skills Pills */}
                    {job.matching_skills && job.matching_skills.length > 0 && (
                      <div className="mt-3">
                        <span className="text-[10px] font-bold text-emerald-800 uppercase tracking-wider block mb-1">
                          Matching Qualifications:
                        </span>
                        <div className="flex flex-wrap gap-1">
                          {job.matching_skills.slice(0, 4).map((skill, idx) => (
                            <span
                              key={idx}
                              className="text-[10px] font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200/80 px-2 py-0.5 rounded-md flex items-center gap-1"
                            >
                              <Check size={10} />
                              <span>{skill}</span>
                            </span>
                          ))}
                          {job.matching_skills.length > 4 && (
                            <span className="text-[10px] text-emerald-600 self-center">
                              +{job.matching_skills.length - 4} more
                            </span>
                          )}
                        </div>
                      </div>
                    )}

                    {/* Candidate-specific Missing Skills Pills */}
                    {job.missing_skills && job.missing_skills.length > 0 && (
                      <div className="mt-2">
                        <span className="text-[10px] font-bold text-amber-800 uppercase tracking-wider block mb-1">
                          Missing Skills:
                        </span>
                        <div className="flex flex-wrap gap-1">
                          {job.missing_skills.slice(0, 3).map((skill, idx) => (
                            <span
                              key={idx}
                              className="text-[10px] font-medium bg-amber-50 text-amber-700 border border-amber-200/80 px-2 py-0.5 rounded-md"
                            >
                              ! {skill}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Card Bottom CTA */}
                  <div className="mt-5 pt-3 border-t border-slate-100 flex items-center gap-2">
                    <button
                      onClick={() => handleOpenExplanation(job)}
                      className="flex-1 py-2 rounded-xl bg-slate-100 hover:bg-slate-200 text-slate-700 font-semibold text-xs transition-colors flex items-center justify-center gap-1"
                    >
                      <Info size={13} />
                      <span>Match Breakdown</span>
                    </button>
                    <button
                      onClick={() => handleStartApplication(job)}
                      className="flex-1 py-2 rounded-xl bg-brand-600 hover:bg-brand-700 text-white font-semibold text-xs shadow-sm shadow-brand-500/20 transition-colors"
                    >
                      Prepare Application
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </>
      )}

      {/* JOB MATCH EXPLANATION & DETAIL MODAL */}
      {selectedJob && (
        <Modal
          isOpen={!!selectedJob}
          onClose={() => {
            setSelectedJob(null);
            setMatchExplanation(null);
          }}
          title={selectedJob.job_title}
          description={`${selectedJob.company_name} • ${selectedJob.location} (${selectedJob.work_arrangement})`}
          maxWidth="2xl"
        >
          <div className="space-y-5 text-xs text-slate-700">
            {/* Score header */}
            <div className="p-4 rounded-2xl bg-slate-50 border border-slate-200 flex items-center justify-between">
              <div>
                <span className="text-xs font-bold text-slate-900">Personalized Match Score</span>
                <p className="text-[11px] text-slate-500">
                  Computed by Universal Matching Engine against your verified credentials.
                </p>
              </div>
              <div className="flex items-center gap-2">
                {selectedJob.match_score != null ? (
                  <span
                    className={`px-3 py-1 rounded-full text-xs font-extrabold border ${getScoreColor(
                      selectedJob.match_score
                    )}`}
                  >
                    {formatScore(selectedJob.match_score)} {selectedJob.match_classification ? `(${selectedJob.match_classification})` : ''}
                  </span>
                ) : (
                  <span className="px-3 py-1 rounded-full text-xs font-semibold border border-slate-200 bg-slate-50 text-slate-500">
                    Score Pending
                  </span>
                )}
                {selectedJob.is_eligible === true ? (
                  <Badge variant="success">Eligible</Badge>
                ) : selectedJob.is_eligible === false ? (
                  <Badge variant="danger">Ineligible</Badge>
                ) : (
                  <Badge variant="warning">Pending Evaluation</Badge>
                )}
              </div>
            </div>

            {/* Explanation details */}
            {isLoadingExplanation ? (
              <div className="py-8 flex justify-center">
                <LoadingSpinner size={24} />
              </div>
            ) : matchExplanation ? (
              <div className="space-y-4">
                {matchExplanation.is_evaluated === false && (
                  <div className="p-4 rounded-2xl bg-amber-50 border border-amber-200 text-amber-900">
                    <p className="font-semibold">Match evaluation has not been performed yet.</p>
                    <p className="text-[11px] text-amber-700 mt-1">
                      Upload or select a primary resume to evaluate alignment against this job posting, or start application preparation to tailor your materials.
                    </p>
                  </div>
                )}
                {/* 100-pt Dimension Breakdown */}
                {matchExplanation.score_breakdown && Object.keys(matchExplanation.score_breakdown).length > 0 && (
                  <div className="p-4 rounded-2xl bg-white border border-slate-200/80 space-y-3">
                    <h4 className="font-bold text-slate-900 text-xs">100-Point Scoring Dimensions</h4>
                    <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                      {Object.entries(matchExplanation.score_breakdown).map(([dim, data]: [string, any], i) => (
                        <div key={i} className="p-2.5 rounded-xl bg-slate-50 border border-slate-100">
                          <p className="text-[10px] text-slate-400 capitalize">{dim.replace('_', ' ')}</p>
                          <p className="text-xs font-bold text-slate-800 mt-0.5">
                            {typeof data === 'object' && data !== null
                              ? `${data.score || 0} / ${data.weight || 0} pts`
                              : `${data} pts`}
                          </p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Matching Skills */}
                {matchExplanation.matching_skills && matchExplanation.matching_skills.length > 0 && (
                  <div>
                    <h4 className="font-bold text-emerald-800 text-xs mb-1.5 flex items-center gap-1.5">
                      <CheckCircle2 size={13} className="text-emerald-600" />
                      <span>Verified Matching Skills ({matchExplanation.matching_skills.length})</span>
                    </h4>
                    <div className="flex flex-wrap gap-1.5">
                      {matchExplanation.matching_skills.map((s, idx) => (
                        <span
                          key={idx}
                          className="bg-emerald-50 text-emerald-800 border border-emerald-200 px-2.5 py-1 rounded-lg text-xs font-semibold"
                        >
                          ✓ {s}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Missing Skills */}
                {matchExplanation.missing_skills && matchExplanation.missing_skills.length > 0 && (
                  <div>
                    <h4 className="font-bold text-amber-800 text-xs mb-1.5 flex items-center gap-1.5">
                      <AlertTriangle size={13} className="text-amber-600" />
                      <span>Missing Skills or Desired Qualifications ({matchExplanation.missing_skills.length})</span>
                    </h4>
                    <div className="flex flex-wrap gap-1.5">
                      {matchExplanation.missing_skills.map((s, idx) => (
                        <span
                          key={idx}
                          className="bg-amber-50 text-amber-800 border border-amber-200 px-2.5 py-1 rounded-lg text-xs font-medium"
                        >
                          ! {s}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Explanation text */}
                {matchExplanation.explanation && (
                  <div>
                    <h4 className="font-bold text-slate-900 text-xs mb-1">Evaluation Summary</h4>
                    <p className="p-3 rounded-xl bg-slate-50 text-slate-600 leading-relaxed text-xs">
                      {matchExplanation.explanation}
                    </p>
                  </div>
                )}

                {/* Disqualification reasons */}
                {matchExplanation.disqualification_reasons && matchExplanation.disqualification_reasons.length > 0 && (
                  <div className="p-3 rounded-xl bg-rose-50 border border-rose-200 text-rose-700 text-xs">
                    <p className="font-bold mb-1">Disqualification Factors:</p>
                    <ul className="list-disc pl-4 space-y-0.5">
                      {matchExplanation.disqualification_reasons.map((r, i) => (
                        <li key={i}>{r}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            ) : null}

            {/* Description */}
            <div>
              <h4 className="font-bold text-slate-900 mb-1">Job Description & Requirements</h4>
              <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-100 leading-relaxed whitespace-pre-wrap max-h-48 overflow-y-auto">
                {selectedJob.job_description || 'No detailed description provided.'}
              </div>
            </div>

            {/* Actions */}
            <div className="pt-4 border-t border-slate-100 flex items-center justify-between gap-3">
              {selectedJob.job_url ? (
                <a
                  href={selectedJob.job_url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="px-4 py-2.5 rounded-xl border border-slate-200 text-slate-700 hover:bg-slate-50 text-xs font-semibold flex items-center gap-1.5 transition-colors"
                >
                  <span>Official Job Posting</span>
                  <ExternalLink size={13} />
                </a>
              ) : <div />}

              <div className="flex items-center gap-2">
                <button
                  onClick={() => handleToggleShortlist(selectedJob.id)}
                  className="px-4 py-2.5 rounded-xl border border-slate-200 hover:bg-slate-50 text-xs font-semibold transition-colors"
                >
                  {selectedJob.is_shortlisted ? 'Remove Bookmark' : 'Bookmark Job'}
                </button>
                <button
                  onClick={() => {
                    setSelectedJob(null);
                    handleStartApplication(selectedJob);
                  }}
                  className="px-5 py-2.5 rounded-xl bg-brand-600 hover:bg-brand-700 text-white font-semibold text-xs shadow-md shadow-brand-500/20 transition-all"
                >
                  Prepare Application
                </button>
              </div>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
};
