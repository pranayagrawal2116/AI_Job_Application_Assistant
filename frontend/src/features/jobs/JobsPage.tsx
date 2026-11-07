import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '@/lib/api';
import { JobItem } from '@/types';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { Badge } from '@/components/common/Badge';
import { Modal } from '@/components/common/Modal';
import { FileDropzone } from '@/components/common/FileDropzone';
import { formatScore, getScoreColor } from '@/lib/utils';
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
} from 'lucide-react';

export const JobsPage: React.FC = () => {
  const navigate = useNavigate();

  const [activeTab, setActiveTab] = useState<'all' | 'saved' | 'add'>('all');
  const [jobs, setJobs] = useState<JobItem[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  // Filters
  const [searchTerm, setSearchTerm] = useState('');
  const [arrangement, setArrangement] = useState('');
  const [platform, setPlatform] = useState('');
  const [onlyEligible, setOnlyEligible] = useState(false);
  const [minScore, setMinScore] = useState<number>(0);

  // Selected job for detail modal
  const [selectedJob, setSelectedJob] = useState<JobItem | null>(null);
  const [candidateResumes, setCandidateResumes] = useState<any[]>([]);
  const [evaluatingResumeId, setEvaluatingResumeId] = useState<number | null>(null);
  const [evaluatingProfile, setEvaluatingProfile] = useState<string>('student_intern');
  const [isEvaluating, setIsEvaluating] = useState<boolean>(false);
  const [matchEvaluation, setMatchEvaluation] = useState<any | null>(null);
  const [evalError, setEvalError] = useState<string | null>(null);

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

  const fetchJobs = async () => {
    setIsLoading(true);
    try {
      const data = await api.getJobs({
        search: searchTerm || undefined,
        arrangement: arrangement || undefined,
        platform: platform || undefined,
        only_eligible: onlyEligible || undefined,
        min_score: minScore > 0 ? minScore : undefined,
        saved_only: activeTab === 'saved',
      });
      setJobs(data);
    } catch (e) {
      console.error('Failed to fetch jobs:', e);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    if (activeTab !== 'add') {
      fetchJobs();
    }
  }, [activeTab, arrangement, platform, onlyEligible, minScore]);

  useEffect(() => {
    api.getResumes().then((res) => {
      setCandidateResumes(res);
      if (res && res.length > 0) {
        setEvaluatingResumeId(res[0].id);
      }
    }).catch(() => {});
  }, []);

  const handleRunEvaluation = async () => {
    if (!selectedJob || !evaluatingResumeId) return;
    setIsEvaluating(true);
    setEvalError(null);
    try {
      const res = await api.evaluateMatch({
        resume_id: evaluatingResumeId,
        job_id: selectedJob.id,
        scoring_profile: evaluatingProfile,
      });
      setMatchEvaluation(res);
    } catch (err: any) {
      setEvalError(err.message || 'Match evaluation failed.');
    } finally {
      setIsEvaluating(false);
    }
  };

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    fetchJobs();
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
        // Create application for this new job description
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
            Discover verified jobs scored by relevance to your profile.
          </p>
        </div>

        {/* Tab Switcher */}
        <div className="flex items-center gap-1.5 p-1 rounded-2xl bg-slate-200/60 self-start sm:self-center">
          <button
            onClick={() => setActiveTab('all')}
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

          {/* Job Cards Grid */}
          {isLoading ? (
            <div className="py-20 flex justify-center">
              <LoadingSpinner size={32} />
            </div>
          ) : jobs.length === 0 ? (
            <div className="py-16 text-center text-slate-400 bg-white rounded-3xl border border-slate-200">
              <Building2 size={36} className="mx-auto mb-2 text-slate-300" />
              <p className="text-sm font-bold text-slate-700">No opportunities found</p>
              <p className="text-xs text-slate-400 mt-1">
                Try loosening your filters or adding a job manually.
              </p>
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
                        <span
                          className={`px-2.5 py-1 rounded-full text-xs font-extrabold border ${getScoreColor(
                            job.match_score
                          )}`}
                        >
                          {formatScore(job.match_score)} Match
                        </span>
                        {job.is_eligible ? (
                          <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-emerald-700 bg-emerald-50 px-2 py-0.5 rounded-full border border-emerald-200">
                            <CheckCircle2 size={12} />
                            Eligible
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-rose-700 bg-rose-50 px-2 py-0.5 rounded-full border border-rose-200">
                            <XCircle size={12} />
                            Ineligible
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

                    {/* Skills pills */}
                    {job.required_skills && job.required_skills.length > 0 && (
                      <div className="mt-4 flex flex-wrap gap-1.5">
                        {job.required_skills.slice(0, 4).map((skill, idx) => (
                          <span
                            key={idx}
                            className="text-[10px] font-medium bg-slate-100 text-slate-700 px-2 py-0.5 rounded-md"
                          >
                            {skill}
                          </span>
                        ))}
                        {job.required_skills.length > 4 && (
                          <span className="text-[10px] text-slate-400 py-0.5 px-1">
                            +{job.required_skills.length - 4} more
                          </span>
                        )}
                      </div>
                    )}
                  </div>

                  {/* Card Bottom CTA */}
                  <div className="mt-6 pt-3 border-t border-slate-100 flex items-center gap-2">
                    <button
                      onClick={() => setSelectedJob(job)}
                      className="flex-1 py-2 rounded-xl bg-slate-100 hover:bg-slate-200 text-slate-700 font-semibold text-xs transition-colors"
                    >
                      View Details
                    </button>
                    <button
                      onClick={() => handleStartApplication(job)}
                      className="flex-1 py-2 rounded-xl bg-brand-600 hover:bg-brand-700 text-white font-semibold text-xs shadow-sm shadow-brand-500/20 transition-colors"
                    >
                      Start Application
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </>
      )}

      {/* JOB DETAIL MODAL */}
      {selectedJob && (
        <Modal
          isOpen={!!selectedJob}
          onClose={() => setSelectedJob(null)}
          title={selectedJob.job_title}
          description={`${selectedJob.company_name} • ${selectedJob.location} (${selectedJob.work_arrangement})`}
          maxWidth="2xl"
        >
          <div className="space-y-5 text-xs text-slate-700">
            {/* Match evaluation banner */}
            <div className="p-4 rounded-2xl bg-slate-50 border border-slate-200 flex items-center justify-between">
              <div>
                <span className="text-xs font-bold text-slate-900">Universal Match Score</span>
                <p className="text-[11px] text-slate-500">
                  Scored across domain relevance, technical skills, and candidate profile
                </p>
              </div>
              <div className="flex items-center gap-2">
                <span
                  className={`px-3 py-1 rounded-full text-xs font-extrabold border ${getScoreColor(
                    selectedJob.match_score
                  )}`}
                >
                  {formatScore(selectedJob.match_score)}
                </span>
                {selectedJob.is_eligible ? (
                  <Badge variant="success">Eligible</Badge>
                ) : (
                  <Badge variant="danger">Ineligible</Badge>
                )}
              </div>
            </div>

            {/* Description */}
            <div>
              <h4 className="font-bold text-slate-900 mb-1">Job Description & Overview</h4>
              <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-100 leading-relaxed whitespace-pre-wrap max-h-60 overflow-y-auto">
                {selectedJob.job_description || 'No detailed description provided.'}
              </div>
            </div>

            {/* Required Skills */}
            {selectedJob.required_skills && selectedJob.required_skills.length > 0 && (
              <div>
                <h4 className="font-bold text-slate-900 mb-1.5">Required Skills</h4>
                <div className="flex flex-wrap gap-1.5">
                  {selectedJob.required_skills.map((skill, idx) => (
                    <span
                      key={idx}
                      className="bg-brand-50 text-brand-700 border border-brand-200 px-2.5 py-1 rounded-lg text-xs font-medium"
                    >
                      {skill}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Interactive Match Evaluation Section */}
            <div className="p-4 rounded-2xl border border-brand-100 bg-brand-50/40 space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Sparkles size={16} className="text-brand-600" />
                  <h4 className="font-bold text-slate-900 text-xs">Evaluate Match Against My Resume</h4>
                </div>
                {candidateResumes.length === 0 && (
                  <span className="text-[10px] text-amber-700 bg-amber-50 border border-amber-200 px-2 py-0.5 rounded-full">
                    Upload resume in Profile first
                  </span>
                )}
              </div>

              {candidateResumes.length > 0 && (
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  <div>
                    <label className="block text-[11px] font-semibold text-slate-600 mb-1">Select Resume</label>
                    <select
                      value={evaluatingResumeId || ''}
                      onChange={(e) => setEvaluatingResumeId(Number(e.target.value))}
                      className="w-full px-2.5 py-1.5 rounded-xl border border-slate-200 bg-white text-xs"
                    >
                      {candidateResumes.map((r) => (
                        <option key={r.id} value={r.id}>
                          {r.original_filename} ({r.label || 'General'})
                        </option>
                      ))}
                    </select>
                  </div>
                  <div>
                    <label className="block text-[11px] font-semibold text-slate-600 mb-1">Scoring Profile</label>
                    <select
                      value={evaluatingProfile}
                      onChange={(e) => setEvaluatingProfile(e.target.value)}
                      className="w-full px-2.5 py-1.5 rounded-xl border border-slate-200 bg-white text-xs"
                    >
                      <option value="student_intern">Student / Intern (Heavy Academics & Projects)</option>
                      <option value="mid_career">Mid-Career (Experience & Domain)</option>
                      <option value="executive">Executive / Leadership</option>
                      <option value="career_changer">Career Changer (Transferable Skills)</option>
                    </select>
                  </div>
                </div>
              )}

              {candidateResumes.length > 0 && (
                <button
                  onClick={handleRunEvaluation}
                  disabled={isEvaluating || !evaluatingResumeId}
                  className="w-full py-2 rounded-xl bg-brand-600 hover:bg-brand-700 text-white font-semibold text-xs flex items-center justify-center gap-1.5 transition-colors disabled:opacity-50"
                >
                  {isEvaluating ? <LoadingSpinner size={13} /> : <Sparkles size={14} />}
                  <span>{isEvaluating ? 'Evaluating Multi-Dimensional Match...' : 'Run Personalized Match Analysis'}</span>
                </button>
              )}

              {evalError && (
                <div className="p-2.5 rounded-xl bg-rose-50 border border-rose-200 text-rose-700 text-[11px]">
                  {evalError}
                </div>
              )}

              {matchEvaluation && (
                <div className="p-3.5 rounded-xl bg-white border border-brand-200 space-y-2.5">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-slate-800 text-xs">Analysis Result:</span>
                    <div className="flex items-center gap-2">
                      <span className={`px-2.5 py-0.5 rounded-full text-xs font-extrabold border ${getScoreColor(matchEvaluation.match_score)}`}>
                        {formatScore(matchEvaluation.match_score)} ({matchEvaluation.match_classification})
                      </span>
                      <Badge variant={matchEvaluation.eligibility_status === 'ELIGIBLE' ? 'success' : 'danger'}>
                        {matchEvaluation.eligibility_status}
                      </Badge>
                    </div>
                  </div>

                  {matchEvaluation.matching_skills && matchEvaluation.matching_skills.length > 0 && (
                    <div>
                      <span className="text-[11px] font-semibold text-emerald-700 block mb-1">
                        Matching Skills ({matchEvaluation.matching_skills.length}):
                      </span>
                      <div className="flex flex-wrap gap-1">
                        {matchEvaluation.matching_skills.map((s: string, i: number) => (
                          <span key={i} className="px-2 py-0.5 bg-emerald-50 text-emerald-700 border border-emerald-200 rounded-md text-[10px] font-medium">
                            ✓ {s}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {matchEvaluation.missing_skills && matchEvaluation.missing_skills.length > 0 && (
                    <div>
                      <span className="text-[11px] font-semibold text-amber-700 block mb-1">
                        Skill Gaps ({matchEvaluation.missing_skills.length}):
                      </span>
                      <div className="flex flex-wrap gap-1">
                        {matchEvaluation.missing_skills.map((s: string, i: number) => (
                          <span key={i} className="px-2 py-0.5 bg-amber-50 text-amber-700 border border-amber-200 rounded-md text-[10px] font-medium">
                            ✗ {s}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
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
