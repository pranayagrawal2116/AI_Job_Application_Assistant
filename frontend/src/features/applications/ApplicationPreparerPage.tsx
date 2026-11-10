import React, { useState, useEffect } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { api } from '@/lib/api';
import { ApplicationItem } from '@/types';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { getStatusBadgeColor } from '@/lib/utils';
import {
  FileText,
  Sparkles,
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  ArrowRight,
  ArrowLeft,
  Download,
  ExternalLink,
  Edit3,
  Lock,
  Send,
} from 'lucide-react';

export const ApplicationPreparerPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const appId = Number(id);

  const [app, setApp] = useState<ApplicationItem | null>(null);
  const [currentStep, setCurrentStep] = useState(1);
  const [isLoading, setIsLoading] = useState(true);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Resume Selection State
  const [resumes, setResumes] = useState<any[]>([]);
  const [selectedResumeId, setSelectedResumeId] = useState<number | null>(null);
  const [customInstructions, setCustomInstructions] = useState('');

  // Preparation Data States
  const [tailoredResume, setTailoredResume] = useState<any>(null);
  const [isTailoringResume, setIsTailoringResume] = useState(false);
  const [isRecoveringScan, setIsRecoveringScan] = useState(false);

  const [coverLetterText, setCoverLetterText] = useState('');
  const [coverLetterTone, setCoverLetterTone] = useState('Professional & Direct');
  const [coverLetterClaims, setCoverLetterClaims] = useState<any[]>([]);
  const [isGeneratingCoverLetter, setIsGeneratingCoverLetter] = useState(false);

  const [screeningQs, setScreeningQs] = useState<Array<{ q: string; a: string; needsInput: boolean }>>([]);
  const [isGeneratingScreening, setIsGeneratingScreening] = useState(false);

  // Approval Gate State
  const [packetInfo, setPacketInfo] = useState<any>(null);
  const [candidateConfirmedApproval, setCandidateConfirmedApproval] = useState(false);
  const [approverName, setApproverName] = useState('');
  const [isAuthorizing, setIsAuthorizing] = useState(false);
  const [isApproved, setIsApproved] = useState(false);
  const [isPreparingPacket, setIsPreparingPacket] = useState(false);
  const [downloadingDoc, setDownloadingDoc] = useState<string | null>(null);

  // Manual Submission Confirmation State
  const [candidateConfirmedSubmission, setCandidateConfirmedSubmission] = useState(false);
  const [submissionChannel, setSubmissionChannel] = useState('COMPANY_PORTAL');
  const [confirmationRef, setConfirmationRef] = useState('');
  const [candidateNotes, setCandidateNotes] = useState('');
  const [isSubmittingConfirm, setIsSubmittingConfirm] = useState(false);
  const [isSubmitted, setIsSubmitted] = useState(false);

  useEffect(() => {
    const loadAppData = async () => {
      setIsLoading(true);
      try {
        const [application, userResumes, prepState] = await Promise.all([
          api.getApplication(appId),
          api.getResumes().catch(() => []),
          api.getPreparationState(appId).catch(() => null),
        ]);

        setApp(application);
        setResumes(userResumes || []);

        // Resolve selected resume
        let resolvedResId: number | null = null;
        if (prepState?.selected_resume_id) {
          resolvedResId = prepState.selected_resume_id;
        } else if (application?.resume_id) {
          resolvedResId = application.resume_id;
        } else if (userResumes && userResumes.length > 0) {
          const primary = userResumes.find((r: any) => r.is_primary);
          resolvedResId = primary ? primary.id : (userResumes.length === 1 ? userResumes[0].id : null);
        }
        setSelectedResumeId(resolvedResId);

        // Restore preparation artifacts if present
        if (prepState?.tailored_resume) {
          setTailoredResume(prepState.tailored_resume);
        }
        if (prepState?.cover_letter) {
          setCoverLetterText(prepState.cover_letter.letter_text || '');
          setCoverLetterClaims(prepState.cover_letter.provenance_claims || []);
        }
        if (prepState?.screening_qa && prepState.screening_qa.length > 0) {
          setScreeningQs(prepState.screening_qa);
        }
        if (prepState?.has_packet && prepState.packet) {
          setPacketInfo(prepState.packet);
        }
        if (prepState?.is_approved) {
          setIsApproved(true);
        }
        if (prepState?.is_submitted) {
          setIsSubmitted(true);
        }

        // Check if application is already submitted or approved
        if (['SUBMITTED', 'Applied', 'In Progress', 'IN_PROGRESS'].includes(application.status)) {
          setIsSubmitted(true);
          setIsApproved(true);
        } else if (['APPROVED', 'Approved'].includes(application.status)) {
          setIsApproved(true);
        }

        // Active packet check fallback
        if (!prepState?.packet) {
          const packetRes = await api.getLatestPacket(appId).catch(() => null);
          if (packetRes?.has_packet) {
            setPacketInfo(packetRes.packet);
          }
        }
      } catch (err: any) {
        setErrorMsg(err.message || 'Failed to load application workspace.');
      } finally {
        setIsLoading(false);
      }
    };
    if (appId) loadAppData();
  }, [appId]);

  const handleTailorResume = async () => {
    if (resumes.length === 0) {
      setErrorMsg('No resumes available. Please upload a resume in My Profile first.');
      return;
    }
    if (!selectedResumeId && resumes.length > 1) {
      setErrorMsg('Please select a resume to use for tailoring.');
      return;
    }
    setIsTailoringResume(true);
    setErrorMsg(null);
    try {
      const res = await api.tailorResume(appId, {
        resume_id: selectedResumeId || undefined,
        custom_instructions: customInstructions || undefined,
      });
      setTailoredResume(res.tailored_resume);
      setSuccessMsg('Tailored resume synthesized and saved!');
    } catch (err: any) {
      setErrorMsg(err.message || 'Resume tailoring failed.');
    } finally {
      setIsTailoringResume(false);
    }
  };

  const handleRecoverScan = async () => {
    setIsRecoveringScan(true);
    setErrorMsg(null);
    try {
      const res = await api.recoverResumeScan(appId);
      setSuccessMsg(res.message || 'Security scan verified and updated with active key. You can now generate your tailored resume.');
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to re-verify security scan.');
    } finally {
      setIsRecoveringScan(false);
    }
  };

  const handleGenerateCoverLetter = async () => {
    setIsGeneratingCoverLetter(true);
    setErrorMsg(null);
    try {
      const res = await api.generateCoverLetter(appId, {
        tone: coverLetterTone,
        resume_id: selectedResumeId || undefined,
      });
      const cl = res.cover_letter;
      setCoverLetterText(cl.letter_text || '');
      setCoverLetterClaims(cl.provenance_claims || []);
      setSuccessMsg('Tailored cover letter drafted and saved!');
    } catch (err: any) {
      setErrorMsg(err.message || 'Cover letter generation failed.');
    } finally {
      setIsGeneratingCoverLetter(false);
    }
  };

  const handleGenerateScreening = async () => {
    setIsGeneratingScreening(true);
    setErrorMsg(null);
    try {
      const res = await api.answerScreeningQuestions(appId, {
        resume_id: selectedResumeId || undefined,
      });
      setScreeningQs(res.screening_qa || []);
      setSuccessMsg('Screening answers drafted from verified credentials!');
    } catch (err: any) {
      setErrorMsg(err.message || 'Screening QA generation failed.');
    } finally {
      setIsGeneratingScreening(false);
    }
  };

  const handleAuthorizePacket = async () => {
    if (!candidateConfirmedApproval) {
      setErrorMsg('Please confirm that you have inspected and verified all application documents.');
      return;
    }
    setIsAuthorizing(true);
    setErrorMsg(null);

    try {
      // 1. Issue HMAC single-use action ticket
      const ticketRes = await api.issueApprovalTicket(appId);
      // 2. Consume ticket to authorize packet
      await api.approvePacket(appId, {
        approver_name: approverName || 'Candidate',
        action_ticket: ticketRes.ticket,
        candidate_confirmed: true,
      });

      setIsApproved(true);
      setSuccessMsg('Application packet cryptographically sealed and approved!');
      setCurrentStep(7);
    } catch (err: any) {
      setErrorMsg(err.message || 'Packet authorization failed.');
    } finally {
      setIsAuthorizing(false);
    }
  };

  const handleConfirmManualSubmission = async () => {
    if (!candidateConfirmedSubmission) {
      setErrorMsg('Please confirm that you manually submitted the application on the employer portal.');
      return;
    }
    setIsSubmittingConfirm(true);
    setErrorMsg(null);

    try {
      // 1. Issue submission ticket
      const ticketRes = await api.issueSubmissionTicket(appId);
      // 2. Confirm manual submission
      await api.confirmSubmission(appId, {
        submission_ticket: ticketRes.ticket,
        candidate_confirmed: true,
        submission_channel: submissionChannel,
        confirmation_reference: confirmationRef || `MANUAL-${Date.now()}`,
        candidate_notes: candidateNotes,
      });

      setIsSubmitted(true);
      setSuccessMsg('Manual submission successfully recorded! Application is now In Progress.');
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to record submission.');
    } finally {
      setIsSubmittingConfirm(false);
    }
  };

  const handlePreparePacket = async () => {
    setIsPreparingPacket(true);
    setErrorMsg(null);
    try {
      const res = await api.prepareApplicationPacket(appId);
      setSuccessMsg('Application packet generated and sealed for review!');
      if (res?.packet) {
        setPacketInfo(res.packet);
      }
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to prepare packet.');
    } finally {
      setIsPreparingPacket(false);
    }
  };

  const handleDownloadDoc = async (docType: string, docFormat: string) => {
    setDownloadingDoc(`${docType}_${docFormat}`);
    setErrorMsg(null);
    try {
      const blob = await api.downloadDocument(appId, docType, docFormat);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      const cleanCompany = (app?.company_name || 'Application').replace(/[^a-zA-Z0-9_-]/g, '_');
      a.download = `${cleanCompany}_${docType}.${docFormat}`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (err: any) {
      setErrorMsg(err.message || `Download failed for ${docType} (${docFormat}).`);
    } finally {
      setDownloadingDoc(null);
    }
  };

  if (isLoading) {
    return (
      <div className="py-20 flex justify-center">
        <LoadingSpinner size={32} />
      </div>
    );
  }

  if (!app) {
    return (
      <div className="py-16 text-center text-slate-500">
        <p>Application #{appId} not found.</p>
        <Link to="/applications" className="text-brand-600 underline mt-2 inline-block">
          Return to Applications
        </Link>
      </div>
    );
  }

  const steps = [
    { num: 1, label: 'Job Alignment' },
    { num: 2, label: 'Tailor Resume' },
    { num: 3, label: 'Cover Letter' },
    { num: 4, label: 'Screening QA' },
    { num: 5, label: 'Preview & Export' },
    { num: 6, label: 'Human Approval Gate' },
    { num: 7, label: 'Portal Submission' },
  ];

  return (
    <div className="space-y-6 animate-fade-in max-w-5xl mx-auto">
      {/* Top Breadcrumb & Status */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-200">
        <div className="flex items-center gap-3">
          <button
            onClick={() => navigate('/applications')}
            className="p-2 rounded-xl text-slate-400 hover:text-slate-600 hover:bg-slate-100 transition-colors"
          >
            <ArrowLeft size={18} />
          </button>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-xl font-extrabold text-slate-900 tracking-tight">
                {app.job_title}
              </h1>
              <span
                className={`px-2.5 py-0.5 rounded-full text-xs font-semibold border ${getStatusBadgeColor(
                  app.status
                )}`}
              >
                {app.status}
              </span>
            </div>
            <p className="text-xs text-slate-500 flex items-center gap-2 mt-0.5">
              <span>{app.company_name}</span>
              {app.location && <span>&middot; {app.location}</span>}
              <span>&middot; Workspace #{app.id}</span>
            </p>
          </div>
        </div>

        {app.external_application_url && (
          <a
            href={app.external_application_url}
            target="_blank"
            rel="noopener noreferrer"
            className="px-4 py-2 rounded-xl border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 text-xs font-semibold flex items-center gap-1.5 transition-colors shadow-2xs self-start sm:self-center"
          >
            <span>Employer Job Portal</span>
            <ExternalLink size={13} />
          </a>
        )}
      </div>

      {errorMsg && (
        <div className="p-4 rounded-xl bg-rose-50 border border-rose-200 text-rose-700 text-xs flex items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <AlertTriangle size={16} className="shrink-0" />
            <span>{errorMsg}</span>
          </div>
          {errorMsg.includes('signing key is unavailable') && (
            <button
              onClick={handleRecoverScan}
              disabled={isRecoveringScan}
              className="px-3 py-1.5 bg-rose-600 hover:bg-rose-700 disabled:opacity-50 text-white font-medium rounded-lg text-xs transition-colors shrink-0 shadow-sm"
            >
              {isRecoveringScan ? 'Re-verifying...' : 'Re-verify Security Scan'}
            </button>
          )}
        </div>
      )}

      {successMsg && (
        <div className="p-4 rounded-xl bg-emerald-50 border border-emerald-200 text-emerald-700 text-xs flex items-center gap-2">
          <CheckCircle2 size={16} />
          <span>{successMsg}</span>
        </div>
      )}

      {/* 7-STEP PROGRESS BAR */}
      <div className="bg-white rounded-2xl p-4 border border-slate-200/80 shadow-sm overflow-x-auto">
        <div className="flex items-center justify-between min-w-[700px]">
          {steps.map((s, idx) => {
            const isCompleted =
              currentStep > s.num ||
              (s.num === 2 && !!tailoredResume) ||
              (s.num === 3 && !!coverLetterText) ||
              (s.num === 4 && screeningQs.length > 0) ||
              (s.num === 5 && !!packetInfo) ||
              (s.num === 6 && isApproved) ||
              (s.num === 7 && isSubmitted);
            const isCurrent = currentStep === s.num;
            const canNavigate =
              s.num === 1 ||
              s.num === 2 ||
              (s.num === 3 && !!tailoredResume) ||
              (s.num === 4 && !!coverLetterText) ||
              (s.num === 5 && screeningQs.length > 0) ||
              (s.num === 6 && !!packetInfo) ||
              (s.num === 7 && isApproved);

            return (
              <React.Fragment key={s.num}>
                <button
                  onClick={() => {
                    if (canNavigate) setCurrentStep(s.num);
                  }}
                  disabled={!canNavigate}
                  className="flex items-center gap-2 text-xs font-bold transition-all focus:outline-none disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  <div
                    className={`w-7 h-7 rounded-full flex items-center justify-center text-xs transition-all ${
                      isCompleted
                        ? 'bg-emerald-500 text-white'
                        : isCurrent
                        ? 'bg-brand-600 text-white ring-4 ring-brand-100'
                        : 'bg-slate-100 text-slate-500'
                    }`}
                  >
                    {isCompleted ? <CheckCircle2 size={15} /> : s.num}
                  </div>
                  <span className={isCurrent ? 'text-brand-700 font-extrabold' : 'text-slate-600'}>
                    {s.label}
                  </span>
                </button>
                {idx < steps.length - 1 && (
                  <div
                    className={`flex-1 h-0.5 mx-3 transition-colors ${
                      currentStep > s.num ? 'bg-emerald-400' : 'bg-slate-200'
                    }`}
                  />
                )}
              </React.Fragment>
            );
          })}
        </div>
      </div>

      {/* ================= STEP 1: JOB ALIGNMENT & GAP ANALYSIS ================= */}
      {currentStep === 1 && (
        <div className="bg-white rounded-3xl p-6 sm:p-8 border border-slate-200/80 shadow-sm space-y-6">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-bold text-slate-900">Step 1: Alignment Review & Gap Analysis</h2>
              <p className="text-xs text-slate-500 mt-0.5">
                Inspect how your verified profile matches this specific employer's job requirements.
              </p>
            </div>
            <button
              onClick={() => setCurrentStep(2)}
              className="px-5 py-2.5 rounded-xl bg-brand-600 hover:bg-brand-700 text-white font-semibold text-xs shadow-md shadow-brand-500/20 flex items-center gap-1.5 transition-all"
            >
              <span>Next: Tailor Resume</span>
              <ArrowRight size={14} />
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
            <div className="p-5 rounded-2xl bg-emerald-50/60 border border-emerald-200/80 space-y-3">
              <div className="flex items-center gap-2 text-emerald-800 font-bold text-xs">
                <CheckCircle2 size={16} />
                <span>Verified Matching Strengths</span>
              </div>
              <p className="text-xs text-slate-600 leading-relaxed">
                Your technical skills, education, and past responsibilities demonstrate direct domain alignment.
                All matching bullet points will be highlighted in the tailored resume.
              </p>
            </div>

            <div className="p-5 rounded-2xl bg-blue-50/60 border border-blue-200/80 space-y-3">
              <div className="flex items-center gap-2 text-blue-800 font-bold text-xs">
                <Sparkles size={16} />
                <span>Zero Hallucination Guarantee</span>
              </div>
              <p className="text-xs text-slate-600 leading-relaxed">
                JobFlow will never fabricate dates, skills, or achievements. Any missing statutory
                certifications or requirements will remain flagged as pending candidate input.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* ================= STEP 2: TAILOR RESUME ================= */}
      {currentStep === 2 && (
        <div className="bg-white rounded-3xl p-6 sm:p-8 border border-slate-200/80 shadow-sm space-y-6">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-bold text-slate-900">Step 2: Role-Specific Tailored Resume</h2>
              <p className="text-xs text-slate-500 mt-0.5">
                Reorders and scores bullet points to match the target job description.
              </p>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={handleTailorResume}
                disabled={isTailoringResume || resumes.length === 0}
                className="px-4 py-2 rounded-xl border border-brand-200 bg-brand-50 hover:bg-brand-100 text-brand-700 font-semibold text-xs flex items-center gap-1.5 transition-colors disabled:opacity-50"
              >
                <Sparkles size={14} />
                <span>{isTailoringResume ? 'Synthesizing...' : 'Regenerate Tailored Bullets'}</span>
              </button>
              <button
                onClick={() => setCurrentStep(3)}
                disabled={!tailoredResume}
                className="px-5 py-2 rounded-xl bg-brand-600 hover:bg-brand-700 text-white font-semibold text-xs shadow-md shadow-brand-500/20 flex items-center gap-1.5 transition-all disabled:opacity-40 disabled:cursor-not-allowed"
              >
                <span>Next: Cover Letter</span>
                <ArrowRight size={14} />
              </button>
            </div>
          </div>

          {/* Resume Selection Box */}
          <div className="p-4 rounded-2xl bg-slate-50 border border-slate-200/80 space-y-3">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div>
                <label className="text-xs font-bold text-slate-800 block">Source Resume</label>
                <p className="text-[11px] text-slate-500">
                  Select which verified resume version to base your tailoring on.
                </p>
              </div>
              {resumes.length === 0 ? (
                <Link
                  to="/profile?tab=resumes"
                  className="px-3.5 py-1.5 rounded-xl bg-brand-600 hover:bg-brand-700 text-white text-xs font-semibold inline-flex items-center gap-1.5 self-start"
                >
                  <span>Upload Resume</span>
                  <ExternalLink size={12} />
                </Link>
              ) : (
                <select
                  value={selectedResumeId || ''}
                  onChange={(e) => setSelectedResumeId(Number(e.target.value))}
                  className="px-3 py-1.5 rounded-xl border border-slate-200 text-xs bg-white text-slate-800 font-medium focus:ring-2 focus:ring-brand-500 focus:outline-none"
                >
                  {resumes.map((r) => (
                    <option key={r.id} value={r.id}>
                      {r.original_filename || `Resume #${r.id}`} {r.is_primary ? '(Primary)' : ''}
                    </option>
                  ))}
                </select>
              )}
            </div>

            {resumes.length === 0 && (
              <div className="p-3 rounded-xl bg-amber-50 border border-amber-200 text-amber-800 text-xs flex items-center gap-2">
                <AlertTriangle size={15} className="shrink-0 text-amber-600" />
                <span>
                  No resumes found in your profile. Please upload a resume in{' '}
                  <Link to="/profile" className="font-bold underline">
                    My Profile
                  </Link>{' '}
                  before generating tailored applications.
                </span>
              </div>
            )}

            <div>
              <label className="text-xs font-semibold text-slate-700 block mb-1">
                Custom Tailoring Instructions (Optional)
              </label>
              <input
                type="text"
                placeholder="e.g. Highlight Python, machine learning workflows, and data pipelines..."
                value={customInstructions}
                onChange={(e) => setCustomInstructions(e.target.value)}
                className="w-full px-3.5 py-2 rounded-xl border border-slate-200 text-xs bg-white focus:outline-none focus:ring-2 focus:ring-brand-500 text-slate-700"
              />
            </div>
          </div>

          {!tailoredResume ? (
            <div className="text-center py-12 border-2 border-dashed border-slate-200 rounded-2xl">
              <FileText size={36} className="mx-auto text-brand-500 mb-3" />
              <p className="text-sm font-bold text-slate-800">Ready to tailor your resume</p>
              <p className="text-xs text-slate-400 mt-1 max-w-sm mx-auto">
                Generate optimized bullet points scored by relevance against the target role requirements.
              </p>
              <button
                onClick={handleTailorResume}
                disabled={isTailoringResume || resumes.length === 0}
                className="mt-4 px-6 py-2.5 rounded-xl bg-brand-600 hover:bg-brand-700 text-white font-semibold text-xs shadow-md shadow-brand-500/20 inline-flex items-center gap-1.5 transition-all disabled:opacity-50"
              >
                <Sparkles size={14} />
                <span>{isTailoringResume ? 'Synthesizing...' : 'Generate Tailored Resume'}</span>
              </button>
            </div>
          ) : (
            <div className="space-y-4">
              <div className="p-4 rounded-2xl bg-slate-50 border border-slate-200 space-y-2">
                <div className="flex items-center justify-between">
                  <h4 className="text-xs font-bold text-slate-900">
                    Professional Summary & Target Focus
                  </h4>
                  <span className="text-[10px] font-semibold text-emerald-700 bg-emerald-50 px-2 py-0.5 rounded-full border border-emerald-200">
                    Verified Grounding
                  </span>
                </div>
                <p className="text-xs text-slate-700 leading-relaxed">
                  {tailoredResume.professional_summary ||
                    'Candidate profile aligned with target engineering requirements.'}
                </p>
              </div>

              {tailoredResume.matching_skills && tailoredResume.matching_skills.length > 0 && (
                <div className="p-4 rounded-2xl bg-slate-50 border border-slate-200 space-y-2">
                  <h4 className="text-xs font-bold text-slate-900">Aligned Technical Skills</h4>
                  <div className="flex flex-wrap gap-1.5">
                    {tailoredResume.matching_skills.map((skill: string, sIdx: number) => (
                      <span
                        key={sIdx}
                        className="px-2.5 py-0.5 rounded-lg text-[11px] font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200"
                      >
                        {skill}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {tailoredResume.experience_entries && (
                <div className="space-y-3">
                  <h4 className="text-xs font-bold text-slate-900">Tailored Experience Bullets</h4>
                  {tailoredResume.experience_entries.map((exp: any, eIdx: number) => (
                    <div key={eIdx} className="p-4 rounded-2xl border border-slate-200 space-y-2 bg-white">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-bold text-slate-800">
                          {exp.job_title} at {exp.employer}
                        </span>
                        <span className="text-[11px] text-slate-400">{exp.duration}</span>
                      </div>
                      <div className="space-y-1.5 pt-1">
                        {exp.bullets?.map((b: any, bIdx: number) => (
                          <div
                            key={bIdx}
                            className="flex items-start gap-2 text-xs text-slate-600 bg-slate-50 p-2.5 rounded-xl border border-slate-100"
                          >
                            <span className="text-brand-600 font-bold">&bull;</span>
                            <span className="flex-1">{b.bullet_text || b}</span>
                            {b.relevance_score && (
                              <span className="text-[10px] font-semibold text-slate-400">
                                {Math.round(b.relevance_score * 100)}%
                              </span>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* ================= STEP 3: COVER LETTER ================= */}
      {currentStep === 3 && (
        <div className="bg-white rounded-3xl p-6 sm:p-8 border border-slate-200/80 shadow-sm space-y-6">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-bold text-slate-900">Step 3: Tailored Cover Letter</h2>
              <p className="text-xs text-slate-500 mt-0.5">
                Personalized cover letter grounded in verifiable facts across your chosen tone.
              </p>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setCurrentStep(2)}
                className="px-4 py-2 rounded-xl border border-slate-200 text-slate-600 hover:bg-slate-50 text-xs font-medium"
              >
                Back
              </button>
              <button
                onClick={() => setCurrentStep(4)}
                disabled={!coverLetterText}
                className="px-5 py-2 rounded-xl bg-brand-600 hover:bg-brand-700 text-white font-semibold text-xs shadow-md shadow-brand-500/20 flex items-center gap-1.5 transition-all disabled:opacity-40 disabled:cursor-not-allowed"
              >
                <span>Next: Screening QA</span>
                <ArrowRight size={14} />
              </button>
            </div>
          </div>

          {/* Tone Selector & Draft Button */}
          <div className="flex flex-wrap items-center gap-3 p-4 rounded-2xl bg-slate-50 border border-slate-200">
            <span className="text-xs font-bold text-slate-700">Select Tone:</span>
            {['Professional & Direct', 'Enthusiastic & Modern', 'Executive & Formal', 'Academic & Rigorous'].map(
              (tone) => (
                <button
                  key={tone}
                  onClick={() => setCoverLetterTone(tone)}
                  className={`px-3 py-1.5 rounded-xl text-xs font-semibold border transition-all ${
                    coverLetterTone === tone
                      ? 'bg-brand-600 text-white border-brand-600 shadow-2xs'
                      : 'bg-white text-slate-600 border-slate-200 hover:bg-slate-100'
                  }`}
                >
                  {tone}
                </button>
              )
            )}
            <button
              onClick={handleGenerateCoverLetter}
              disabled={isGeneratingCoverLetter}
              className="ml-auto px-4 py-1.5 rounded-xl bg-brand-600 hover:bg-brand-700 text-white font-semibold text-xs shadow-2xs flex items-center gap-1.5 transition-colors disabled:opacity-50"
            >
              <Sparkles size={13} />
              <span>{isGeneratingCoverLetter ? 'Drafting...' : 'Generate Cover Letter'}</span>
            </button>
          </div>

          {/* Editable Draft Area */}
          <div>
            <label className="block text-xs font-semibold text-slate-700 mb-1.5">
              Review and Edit Cover Letter
            </label>
            <textarea
              rows={12}
              value={coverLetterText}
              onChange={(e) => setCoverLetterText(e.target.value)}
              placeholder="Click 'Generate Cover Letter' or compose your customized letter..."
              className="w-full p-4 rounded-2xl border border-slate-200 text-xs leading-relaxed focus:ring-2 focus:ring-brand-500 focus:outline-none bg-white font-serif"
            />
          </div>

          {/* Provenance Claims Inspector */}
          {coverLetterClaims.length > 0 && (
            <div className="p-4 rounded-2xl bg-slate-50 border border-slate-200 space-y-2">
              <h4 className="text-xs font-bold text-slate-800 flex items-center gap-1.5">
                <ShieldCheck size={14} className="text-brand-600" />
                <span>Grounding Provenance Audit</span>
              </h4>
              <div className="divide-y divide-slate-200/60">
                {coverLetterClaims.map((claim, idx) => (
                  <div key={idx} className="py-2 text-[11px] text-slate-600 flex justify-between">
                    <span>
                      Claim {idx + 1}: <code className="bg-white px-1 rounded">{claim.claim_id}</code>
                    </span>
                    <span className="font-semibold text-emerald-700">{claim.evidence_status}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* ================= STEP 4: SCREENING QA ================= */}
      {currentStep === 4 && (
        <div className="bg-white rounded-3xl p-6 sm:p-8 border border-slate-200/80 shadow-sm space-y-6">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-bold text-slate-900">Step 4: Screening Questions Assistant</h2>
              <p className="text-xs text-slate-500 mt-0.5">
                Drafts responses truthfully. Notice requirements and missing fields are tagged for input.
              </p>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setCurrentStep(3)}
                className="px-4 py-2 rounded-xl border border-slate-200 text-slate-600 hover:bg-slate-50 text-xs font-medium"
              >
                Back
              </button>
              <button
                onClick={handleGenerateScreening}
                disabled={isGeneratingScreening}
                className="px-4 py-2 rounded-xl border border-brand-200 bg-brand-50 hover:bg-brand-100 text-brand-700 font-semibold text-xs flex items-center gap-1.5 transition-colors disabled:opacity-50"
              >
                <Sparkles size={13} />
                <span>{isGeneratingScreening ? 'Drafting...' : 'Draft Screening Answers'}</span>
              </button>
              <button
                onClick={() => setCurrentStep(5)}
                disabled={screeningQs.length === 0}
                className="px-5 py-2 rounded-xl bg-brand-600 hover:bg-brand-700 text-white font-semibold text-xs shadow-md shadow-brand-500/20 flex items-center gap-1.5 transition-all disabled:opacity-40 disabled:cursor-not-allowed"
              >
                <span>Next: Preview & Export</span>
                <ArrowRight size={14} />
              </button>
            </div>
          </div>

          {screeningQs.length === 0 ? (
            <div className="text-center py-12 border-2 border-dashed border-slate-200 rounded-2xl">
              <Edit3 size={36} className="mx-auto text-brand-500 mb-3" />
              <p className="text-sm font-bold text-slate-800">No Screening Answers Drafted Yet</p>
              <p className="text-xs text-slate-400 mt-1 max-w-sm mx-auto">
                Generate role-specific screening answers based on your verified candidate credentials.
              </p>
              <button
                onClick={handleGenerateScreening}
                disabled={isGeneratingScreening}
                className="mt-4 px-6 py-2.5 rounded-xl bg-brand-600 hover:bg-brand-700 text-white font-semibold text-xs shadow-md shadow-brand-500/20 inline-flex items-center gap-1.5 transition-all disabled:opacity-50"
              >
                <Sparkles size={14} />
                <span>{isGeneratingScreening ? 'Drafting...' : 'Generate Screening Answers'}</span>
              </button>
            </div>
          ) : (
            <div className="space-y-4">
              {screeningQs.map((qItem, idx) => (
                <div
                  key={idx}
                  className="p-4 rounded-2xl bg-slate-50 border border-slate-200 space-y-2.5"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-slate-900">
                      Q{idx + 1}: {qItem.q}
                    </span>
                    {qItem.needsInput ? (
                      <span className="text-[10px] font-bold text-amber-700 bg-amber-50 px-2 py-0.5 rounded-full border border-amber-200">
                        Needs Candidate Input
                      </span>
                    ) : (
                      <span className="text-[10px] font-bold text-emerald-700 bg-emerald-50 px-2 py-0.5 rounded-full border border-emerald-200">
                        Draft Ready
                      </span>
                    )}
                  </div>
                  <textarea
                    rows={2}
                    value={qItem.a}
                    onChange={(e) => {
                      const updated = [...screeningQs];
                      updated[idx].a = e.target.value;
                      setScreeningQs(updated);
                    }}
                    className="w-full p-2.5 rounded-xl border border-slate-200 text-xs bg-white focus:outline-none focus:ring-2 focus:ring-brand-500"
                  />
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* ================= STEP 5: PREVIEW & EXPORT ================= */}
      {currentStep === 5 && (
        <div className="bg-white rounded-3xl p-6 sm:p-8 border border-slate-200/80 shadow-sm space-y-6">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-bold text-slate-900">Step 5: Document Preview & ATS Downloads</h2>
              <p className="text-xs text-slate-500 mt-0.5">
                Download ATS-optimized PDF and DOCX files for your application packet.
              </p>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setCurrentStep(4)}
                className="px-4 py-2 rounded-xl border border-slate-200 text-slate-600 hover:bg-slate-50 text-xs font-medium"
              >
                Back
              </button>
              <button
                onClick={handlePreparePacket}
                disabled={isPreparingPacket}
                className="px-4 py-2.5 rounded-xl bg-slate-100 hover:bg-slate-200 text-slate-800 font-semibold text-xs flex items-center gap-1.5 transition-all disabled:opacity-50"
              >
                {isPreparingPacket ? <LoadingSpinner size={13} /> : <CheckCircle2 size={14} className="text-emerald-600" />}
                <span>{isPreparingPacket ? 'Generating Documents...' : 'Generate & Seal Packet'}</span>
              </button>
              <button
                onClick={() => setCurrentStep(6)}
                disabled={!packetInfo}
                className="px-5 py-2.5 rounded-xl bg-brand-600 hover:bg-brand-700 text-white font-semibold text-xs shadow-md shadow-brand-500/20 flex items-center gap-1.5 transition-all disabled:opacity-40 disabled:cursor-not-allowed"
              >
                <span>Next: Human Approval Gate</span>
                <ArrowRight size={14} />
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-6 rounded-2xl border border-slate-200 bg-slate-50 flex flex-col justify-between space-y-4">
              <div>
                <FileText size={28} className="text-brand-600 mb-2" />
                <h4 className="text-sm font-bold text-slate-900">Tailored Resume</h4>
                <p className="text-xs text-slate-500 mt-0.5">
                  Formatted across modern clean typography, validated for extractable ATS text.
                </p>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => handleDownloadDoc('resume', 'pdf')}
                  disabled={downloadingDoc === 'resume_pdf'}
                  className="flex-1 py-2 rounded-xl bg-white border border-slate-200 hover:bg-slate-100 text-slate-700 font-semibold text-xs flex items-center justify-center gap-1 transition-colors disabled:opacity-50"
                >
                  {downloadingDoc === 'resume_pdf' ? <LoadingSpinner size={12} /> : <Download size={13} />}
                  <span>Download PDF</span>
                </button>
                <button
                  onClick={() => handleDownloadDoc('resume', 'docx')}
                  disabled={downloadingDoc === 'resume_docx'}
                  className="flex-1 py-2 rounded-xl bg-white border border-slate-200 hover:bg-slate-100 text-slate-700 font-semibold text-xs flex items-center justify-center gap-1 transition-colors disabled:opacity-50"
                >
                  {downloadingDoc === 'resume_docx' ? <LoadingSpinner size={12} /> : <Download size={13} />}
                  <span>Download DOCX</span>
                </button>
              </div>
            </div>

            <div className="p-6 rounded-2xl border border-slate-200 bg-slate-50 flex flex-col justify-between space-y-4">
              <div>
                <Edit3 size={28} className="text-indigo-600 mb-2" />
                <h4 className="text-sm font-bold text-slate-900">Cover Letter Document</h4>
                <p className="text-xs text-slate-500 mt-0.5">
                  Signed and tailored to {app.company_name} with verified achievements.
                </p>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => handleDownloadDoc('cover-letter', 'pdf')}
                  disabled={downloadingDoc === 'cover-letter_pdf'}
                  className="flex-1 py-2 rounded-xl bg-white border border-slate-200 hover:bg-slate-100 text-slate-700 font-semibold text-xs flex items-center justify-center gap-1 transition-colors disabled:opacity-50"
                >
                  {downloadingDoc === 'cover-letter_pdf' ? <LoadingSpinner size={12} /> : <Download size={13} />}
                  <span>Download PDF</span>
                </button>
                <button
                  onClick={() => handleDownloadDoc('cover-letter', 'docx')}
                  disabled={downloadingDoc === 'cover-letter_docx'}
                  className="flex-1 py-2 rounded-xl bg-white border border-slate-200 hover:bg-slate-100 text-slate-700 font-semibold text-xs flex items-center justify-center gap-1 transition-colors disabled:opacity-50"
                >
                  {downloadingDoc === 'cover-letter_docx' ? <LoadingSpinner size={12} /> : <Download size={13} />}
                  <span>Download DOCX</span>
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ================= STEP 6: HUMAN APPROVAL GATE ================= */}
      {currentStep === 6 && (
        <div className="bg-white rounded-3xl p-6 sm:p-8 border border-slate-200/80 shadow-sm space-y-6">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-bold text-slate-900">Step 6: Strict Human Approval Gate</h2>
              <p className="text-xs text-slate-500 mt-0.5">
                Cryptographic authorization protocol (HMAC single-use ticket). Never automated.
              </p>
            </div>
            {isApproved && (
              <span className="px-3 py-1 rounded-full text-xs font-bold text-emerald-700 bg-emerald-50 border border-emerald-200 flex items-center gap-1.5">
                <ShieldCheck size={14} />
                <span>Authorized</span>
              </span>
            )}
          </div>

          <div className="p-5 rounded-2xl bg-amber-50/70 border border-amber-200/80 text-amber-900 text-xs space-y-2">
            <div className="flex items-center gap-2 font-bold">
              <ShieldAlert size={16} className="text-amber-700 shrink-0" />
              <span>Strict Human-in-the-Loop Safeguard</span>
            </div>
            <p className="leading-relaxed text-amber-800">
              In compliance with safety protocols, this AI Job Assistant will never submit applications
              autonomously. You must personally review the generated documents, verify all statements, and
              confirm approval with your signature.
            </p>
          </div>

          <div className="p-5 rounded-2xl bg-slate-50 border border-slate-200 space-y-4">
            {packetInfo && (
              <div className="p-3 rounded-xl bg-white border border-slate-200 text-[11px] text-slate-500 flex items-center justify-between">
                <span>Packet Version: <strong>v{packetInfo.packet_version}</strong></span>
                <span className="font-mono text-[10px] text-slate-400">
                  {packetInfo.packet_version_hash?.slice(0, 16)}...
                </span>
              </div>
            )}
            <h4 className="text-xs font-bold text-slate-900">Candidate Authorization Statement</h4>
            <div className="flex items-start gap-3">
              <input
                type="checkbox"
                id="candidate-confirm"
                checked={candidateConfirmedApproval}
                onChange={(e) => setCandidateConfirmedApproval(e.target.checked)}
                className="mt-1 w-4 h-4 rounded text-brand-600 focus:ring-brand-500 cursor-pointer"
              />
              <label htmlFor="candidate-confirm" className="text-xs text-slate-700 leading-relaxed cursor-pointer">
                <strong>I explicitly certify:</strong> I have reviewed all tailored documents, answers, and
                credentials for <strong>{app.job_title}</strong> at <strong>{app.company_name}</strong>. I
                confirm their accuracy and authorize this packet for external portal submission.
              </label>
            </div>

            <div className="pt-2">
              <label className="block text-xs font-semibold text-slate-700 mb-1">
                Approver Signature / Candidate Name
              </label>
              <input
                type="text"
                placeholder="Type your full legal name..."
                value={approverName}
                onChange={(e) => setApproverName(e.target.value)}
                className="w-full max-w-sm px-3.5 py-2.5 rounded-xl border border-slate-200 text-xs bg-white focus:outline-none focus:ring-2 focus:ring-brand-500"
              />
            </div>
          </div>

          <div className="flex items-center justify-between pt-2">
            <button
              onClick={() => setCurrentStep(5)}
              className="px-4 py-2 rounded-xl border border-slate-200 text-slate-600 hover:bg-slate-50 text-xs font-medium"
            >
              Back
            </button>
            <div className="flex items-center gap-2">
              <button
                onClick={handleAuthorizePacket}
                disabled={isAuthorizing || isApproved}
                className="px-6 py-2.5 rounded-xl bg-emerald-600 hover:bg-emerald-700 text-white font-semibold text-xs shadow-md shadow-emerald-600/20 flex items-center gap-2 transition-all disabled:opacity-50"
              >
                <Lock size={14} />
                <span>{isApproved ? 'Packet Approved' : isAuthorizing ? 'Authorizing...' : 'Authorize Packet'}</span>
              </button>
              {isApproved && (
                <button
                  onClick={() => setCurrentStep(7)}
                  className="px-5 py-2.5 rounded-xl bg-brand-600 hover:bg-brand-700 text-white font-semibold text-xs shadow-md shadow-brand-500/20 flex items-center gap-1.5 transition-all"
                >
                  <span>Next: Portal Submission</span>
                  <ArrowRight size={14} />
                </button>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ================= STEP 7: MANUAL SUBMISSION CONFIRMATION ================= */}
      {currentStep === 7 && (
        <div className="bg-white rounded-3xl p-6 sm:p-8 border border-slate-200/80 shadow-sm space-y-6">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-bold text-slate-900">Step 7: Manual Portal Submission Confirmation</h2>
              <p className="text-xs text-slate-500 mt-0.5">
                Complete your submission on the employer portal and log your confirmation reference.
              </p>
            </div>
            {isSubmitted && (
              <span className="px-3 py-1 rounded-full text-xs font-bold text-emerald-700 bg-emerald-50 border border-emerald-200 flex items-center gap-1.5">
                <CheckCircle2 size={14} />
                <span>Submitted</span>
              </span>
            )}
          </div>

          {/* Portal Link Box */}
          <div className="p-5 rounded-2xl bg-indigo-50/70 border border-indigo-200 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div>
              <h4 className="text-xs font-bold text-indigo-900">Employer Application Link</h4>
              <p className="text-xs text-indigo-700 mt-0.5">
                Open the official career page, upload your exported documents, and click Submit.
              </p>
            </div>
            {app.external_application_url ? (
              <a
                href={app.external_application_url}
                target="_blank"
                rel="noopener noreferrer"
                className="px-5 py-2.5 rounded-xl bg-indigo-600 hover:bg-indigo-700 text-white font-semibold text-xs shadow-md shadow-indigo-500/20 flex items-center gap-1.5 transition-all self-start sm:self-center shrink-0"
              >
                <span>Open Employer Portal</span>
                <ExternalLink size={14} />
              </a>
            ) : (
              <span className="text-xs text-slate-500">No external URL provided</span>
            )}
          </div>

          {/* Confirmation Checklist */}
          <div className="p-5 rounded-2xl bg-slate-50 border border-slate-200 space-y-4">
            <h4 className="text-xs font-bold text-slate-900">Log Manual Submission</h4>
            <div className="flex items-start gap-3">
              <input
                type="checkbox"
                id="submission-confirm"
                checked={candidateConfirmedSubmission}
                onChange={(e) => setCandidateConfirmedSubmission(e.target.checked)}
                className="mt-1 w-4 h-4 rounded text-brand-600 focus:ring-brand-500 cursor-pointer"
              />
              <label htmlFor="submission-confirm" className="text-xs text-slate-700 leading-relaxed cursor-pointer">
                I have personally navigated to the employer portal and clicked <strong>Submit Application</strong>.
              </label>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-2">
              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1">
                  Submission Channel
                </label>
                <select
                  value={submissionChannel}
                  onChange={(e) => setSubmissionChannel(e.target.value)}
                  className="w-full px-3.5 py-2 rounded-xl border border-slate-200 text-xs bg-white focus:outline-none"
                >
                  <option value="COMPANY_PORTAL">Employer Career Portal</option>
                  <option value="LINKEDIN">LinkedIn Easy Apply</option>
                  <option value="INDEED">Indeed Apply</option>
                  <option value="EMAIL">Email Submission</option>
                  <option value="OTHER">Other Career Portal</option>
                </select>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1">
                  Confirmation Reference # (Optional)
                </label>
                <input
                  type="text"
                  placeholder="e.g. APP-94821 or Job Reference ID"
                  value={confirmationRef}
                  onChange={(e) => setConfirmationRef(e.target.value)}
                  className="w-full px-3.5 py-2 rounded-xl border border-slate-200 text-xs bg-white focus:outline-none"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">
                Candidate Notes
              </label>
              <input
                type="text"
                placeholder="e.g. Applied via Lever, recruiter name Jane Doe"
                value={candidateNotes}
                onChange={(e) => setCandidateNotes(e.target.value)}
                className="w-full px-3.5 py-2 rounded-xl border border-slate-200 text-xs bg-white focus:outline-none"
              />
            </div>
          </div>

          <div className="flex items-center justify-between pt-2">
            <button
              onClick={() => setCurrentStep(6)}
              className="px-4 py-2 rounded-xl border border-slate-200 text-slate-600 hover:bg-slate-50 text-xs font-medium"
            >
              Back
            </button>
            <button
              onClick={handleConfirmManualSubmission}
              disabled={isSubmittingConfirm || isSubmitted}
              className="px-6 py-2.5 rounded-xl bg-emerald-600 hover:bg-emerald-700 text-white font-semibold text-xs shadow-md shadow-emerald-600/20 flex items-center gap-2 transition-all disabled:opacity-50"
            >
              <Send size={14} />
              <span>
                {isSubmitted
                  ? 'Submission Confirmed'
                  : isSubmittingConfirm
                  ? 'Recording...'
                  : 'Confirm Portal Submission'}
              </span>
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
