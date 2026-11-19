import React, { useState, useEffect } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { api } from '@/lib/api';
import { ApplicationItem, FormFillReport, FormFieldResultItem, AutofillPlan } from '@/types';
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
  Copy,
  Check,
  Globe,
  Wand2,
  Layers,
  Activity,
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

  // Phase C.1: External ATS Form Autofill States
  const [targetFormUrl, setTargetFormUrl] = useState('');
  const [isAutofilling, setIsAutofilling] = useState(false);
  const [autofillProgressStep, setAutofillProgressStep] = useState<number>(0);
  const [autofillReport, setAutofillReport] = useState<FormFillReport | null>(null);
  const [autofillPlan, setAutofillPlan] = useState<AutofillPlan | null>(null);
  const [companionCopied, setCompanionCopied] = useState(false);
  const [editedFieldResults, setEditedFieldResults] = useState<FormFieldResultItem[]>([]);
  const [companionInstalled, setCompanionInstalled] = useState(false);
  const [companionHandshakeDone, setCompanionHandshakeDone] = useState(false);
  const [liveExecutionStatus, setLiveExecutionStatus] = useState<any>(null);
  const [showDiagnostics, setShowDiagnostics] = useState(false);

  useEffect(() => {
    const checkExt = () => {
      if ((window as any).__JOBFLOW_EXTENSION_ACTIVE__ || document.documentElement.dataset.jobflowExtensionInstalled === 'true') {
        setCompanionInstalled(true);
      }
    };
    checkExt();
    const handleExtReady = () => setCompanionInstalled(true);
    window.addEventListener('JOBFLOW_EXTENSION_READY', handleExtReady);
    return () => window.removeEventListener('JOBFLOW_EXTENSION_READY', handleExtReady);
  }, []);

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
        if (application?.external_application_url) {
          setTargetFormUrl(application.external_application_url);
        }

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

  // Phase C.1: External ATS Form Autofill Handlers
  const handleStartBrowserAutofill = async (options?: { openInNewTab?: boolean }) => {
    setIsAutofilling(true);
    setErrorMsg(null);
    setSuccessMsg(null);
    setAutofillProgressStep(1); // 1. Opening employer portal
    setCompanionHandshakeDone(false);

    try {
      const plan = await api.getAutofillPlan(appId, targetFormUrl || undefined);
      setAutofillPlan(plan);
      setAutofillProgressStep(2); // 2. Establishing browser connection

      // Signal extension if installed in candidate's browser
      try {
        window.postMessage({ type: 'JOBFLOW_START_AUTOFILL', payload: plan }, '*');
      } catch (e) {
        // Ignore message error
      }

      // If requested or default, open employer application page in separate tab
      if (options?.openInNewTab !== false && plan.target_url) {
        window.open(plan.target_url, '_blank');
      }

      // Start live polling of status while background execution runs
      let pollCount = 0;
      let completedFromPolling = false;
      const pollInterval = setInterval(async () => {
        pollCount++;
        try {
          const st = await api.getAutofillStatus(appId, plan.execution_id);
          if (st) {
            setLiveExecutionStatus(st);
            if (st.companion_connected) {
              setCompanionHandshakeDone(true);
            }
            if (st.stage_index) {
              setAutofillProgressStep(st.stage_index);
            }
            if (st.report) {
              completedFromPolling = true;
              clearInterval(pollInterval);
              finishAutofill(st.report);
            }
          }
        } catch (e) {
          // ignore transient poll error
        }
        if (pollCount > 60) {
          clearInterval(pollInterval);
        }
      }, 1000);

      // Concurrently run headless verification
      try {
        const report = await api.executeBrowserAutofill(appId, targetFormUrl || plan.target_url);
        clearInterval(pollInterval);
        if (!completedFromPolling) {
          finishAutofill(report);
        }
      } catch (execErr: any) {
        if (!completedFromPolling) {
          setIsAutofilling(false);
          const st = await api.getAutofillStatus(appId, plan.execution_id).catch(() => null);
          if (st && st.report) {
            finishAutofill(st.report);
          } else {
            setErrorMsg(execErr.message || 'Browser execution stopped. If using the companion or extension, please inspect the employer tab.');
          }
        }
      }
    } catch (err: any) {
      setErrorMsg(err.message || 'Browser form auto-population failed.');
      setAutofillProgressStep(0);
      setIsAutofilling(false);
    }
  };

  const finishAutofill = (report: FormFillReport) => {
    setAutofillReport(report);
    setEditedFieldResults(report.field_results || []);
    setIsAutofilling(false);

    const hasAnyPopulated = (report.fields_populated_count > 0 || report.fields_ats_parsed_count > 0 || report.resume_uploaded);

    if (!hasAnyPopulated || report.status === 'BLOCKED' || report.status === 'NO_FIELDS_POPULATED' || report.status === 'FAILED') {
      // Eliminate false success!
      setAutofillProgressStep(report.anti_automation_detected ? 2 : 4);
      setSuccessMsg(null);
      setErrorMsg(
        report.message ||
        'Autofill could not populate any fields. The employer form remains unchanged. Please check the browser companion connection.'
      );
    } else {
      setAutofillProgressStep(9); // 9. Ready for human review
      setErrorMsg(null);
      setSuccessMsg(
        `Form auto-population complete! ${report.fields_populated_count} fields filled, ${report.fields_ats_parsed_count} parsed by ATS. Review all values below before submitting.`
      );
    }
  };

  const handleCopyBookmarklet = () => {
    const ticketParam = autofillPlan?.action_ticket ? `?ticket=${encodeURIComponent(autofillPlan.action_ticket)}` : '';
    const code = `javascript:(function(){window.JOBFLOW_CONFIG={apiBase:'http://127.0.0.1:8000/api',appId:${appId},ticket:'${autofillPlan?.action_ticket || ''}',executionId:'${autofillPlan?.execution_id || ''}'};var s=document.createElement('script');s.src='http://127.0.0.1:8000/api/applications/${appId}/autofill/companion.js${ticketParam}';document.body.appendChild(s);})();`;
    navigator.clipboard.writeText(code);
    setCompanionCopied(true);
    setTimeout(() => setCompanionCopied(false), 3500);
  };

  const handleUpdateFieldValue = (index: number, val: string) => {
    setEditedFieldResults((prev) => {
      const copy = [...prev];
      copy[index] = { ...copy[index], actual_value: val, status: 'PRESERVED' };
      return copy;
    });
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

      {/* ================= STEP 7: AUTOMATED FORM POPULATION & MANUAL SUBMISSION ================= */}
      {currentStep === 7 && (
        <div className="bg-white rounded-3xl p-6 sm:p-8 border border-slate-200/80 shadow-sm space-y-6">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-bold text-slate-900">Step 7: External Form Auto-Population & Submission</h2>
              <p className="text-xs text-slate-500 mt-0.5">
                Automatically upload your verified resume and auto-fill employer application forms (Keka, Greenhouse, Lever, etc.).
              </p>
            </div>
            {isSubmitted && (
              <span className="px-3 py-1 rounded-full text-xs font-bold text-emerald-700 bg-emerald-50 border border-emerald-200 flex items-center gap-1.5">
                <CheckCircle2 size={14} />
                <span>Submitted</span>
              </span>
            )}
          </div>

          {/* Section 1: Employer Portal & Smart Auto-Population */}
          <div className="p-5 rounded-2xl bg-indigo-50/70 border border-indigo-200 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div>
                <div className="flex items-center gap-2">
                  <Globe size={16} className="text-indigo-600" />
                  <h4 className="text-xs font-bold text-indigo-900">Employer Application Portal</h4>
                  <span className="px-2 py-0.5 rounded-md text-[10px] font-semibold bg-indigo-100 text-indigo-800 uppercase tracking-wider">
                    {autofillPlan?.ats_provider || 'ATS Auto-Detect'}
                  </span>
                </div>
                <p className="text-xs text-indigo-700 mt-1">
                  Target URL where JobFlow will upload your verified resume and populate candidate fields.
                </p>
              </div>

              <div className="flex items-center gap-2 flex-wrap">
                {targetFormUrl && (
                  <a
                    href={targetFormUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="px-4 py-2 rounded-xl bg-white border border-indigo-300 text-indigo-700 hover:bg-indigo-50 font-semibold text-xs flex items-center gap-1.5 transition-all"
                  >
                    <span>Open in Browser</span>
                    <ExternalLink size={13} />
                  </a>
                )}
              </div>
            </div>

            <div className="flex flex-col sm:flex-row items-center gap-3">
              <input
                type="text"
                placeholder="https://company.keka.com/careers/applyjob/..."
                value={targetFormUrl}
                onChange={(e) => setTargetFormUrl(e.target.value)}
                className="w-full px-3.5 py-2.5 rounded-xl border border-indigo-200 bg-white text-xs text-slate-800 focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
              />
              <div className="flex items-center gap-2 w-full sm:w-auto">
                <button
                  onClick={() => handleStartBrowserAutofill({ openInNewTab: true })}
                  disabled={isAutofilling || !targetFormUrl}
                  className="w-full sm:w-auto px-5 py-2.5 rounded-xl bg-indigo-600 hover:bg-indigo-700 text-white font-semibold text-xs shadow-md shadow-indigo-500/20 flex items-center justify-center gap-2 transition-all shrink-0 disabled:opacity-50"
                  title="Opens the employer portal in a new tab and auto-fills fields via companion/extension"
                >
                  {isAutofilling ? (
                    <>
                      <LoadingSpinner size={16} />
                      <span>Auto-Populating Form...</span>
                    </>
                  ) : (
                    <>
                      <Wand2 size={14} />
                      <span>Open Employer Application Form & Auto-Fill</span>
                      <ExternalLink size={13} />
                    </>
                  )}
                </button>
              </div>
            </div>

            {/* In-Browser Companion Connection & Diagnostics */}
            <div className="pt-2 border-t border-indigo-200/60 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs">
              <div className="flex items-center gap-2">
                <span
                  className={`w-2.5 h-2.5 rounded-full inline-block ${
                    companionHandshakeDone
                      ? 'bg-emerald-500'
                      : companionInstalled
                      ? 'bg-blue-500 animate-pulse'
                      : 'bg-amber-400'
                  }`}
                ></span>
                <span className="font-medium text-slate-700">
                  {companionHandshakeDone
                    ? 'Companion Handshake Verified • Active Tab Connected'
                    : companionInstalled
                    ? 'Extension Detected • Waiting for Tab Handshake'
                    : 'Extension Not Detected • Use 1-Click Bookmarklet Companion'}
                </span>
                <span className="text-slate-400 hidden sm:inline">• Strict Human Control Guarantee</span>
              </div>
              <div className="flex items-center gap-3">
                <button
                  type="button"
                  onClick={() => setShowDiagnostics((prev) => !prev)}
                  className="text-xs font-semibold text-indigo-600 hover:text-indigo-800 flex items-center gap-1 transition-colors"
                >
                  <Activity size={13} />
                  <span>{showDiagnostics ? 'Hide Diagnostics' : 'Diagnostics'}</span>
                </button>
                <button
                  onClick={handleCopyBookmarklet}
                  className="text-xs font-semibold text-indigo-700 hover:text-indigo-900 flex items-center gap-1.5 self-start sm:self-auto transition-colors"
                  title="Copy secure 1-click companion bookmarklet"
                >
                  {companionCopied ? (
                    <>
                      <Check size={13} className="text-emerald-600" />
                      <span className="text-emerald-700 font-bold">Bookmarklet Copied!</span>
                    </>
                  ) : (
                    <>
                      <Copy size={13} />
                      <span>Copy 1-Click Bookmarklet</span>
                    </>
                  )}
                </button>
              </div>
            </div>

            {/* Collapsible Diagnostic Panel */}
            {showDiagnostics && (
              <div className="p-4 rounded-xl bg-slate-900 text-slate-100 text-xs font-mono space-y-2 border border-slate-700 shadow-inner">
                <div className="flex items-center justify-between border-b border-slate-700 pb-2">
                  <span className="font-bold text-slate-300 flex items-center gap-1.5">
                    <Activity size={13} className="text-indigo-400" />
                    <span>Autofill Diagnostics & Handshake Inspector</span>
                  </span>
                  <span className="text-[11px] text-slate-400">Application #{appId}</span>
                </div>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px]">
                  <div>
                    <span className="text-slate-400 block">Companion Status:</span>
                    <span className={companionHandshakeDone ? 'text-emerald-400 font-bold' : companionInstalled ? 'text-blue-400' : 'text-amber-400'}>
                      {companionHandshakeDone ? 'CONNECTED (Verified)' : companionInstalled ? 'INSTALLED_WAITING' : 'NOT_DETECTED'}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400 block">Employer ATS:</span>
                    <span className="text-blue-300 font-bold">{autofillPlan?.ats_provider || liveExecutionStatus?.ats_provider || 'DETECTING...'}</span>
                  </div>
                  <div>
                    <span className="text-slate-400 block">Target Domain:</span>
                    <span className="text-slate-300 truncate block">{autofillPlan?.validated_domain || liveExecutionStatus?.validated_domain || 'N/A'}</span>
                  </div>
                  <div>
                    <span className="text-slate-400 block">Execution ID:</span>
                    <span className="text-slate-300 truncate block">{autofillPlan?.execution_id || 'N/A'}</span>
                  </div>
                </div>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px] pt-1.5 border-t border-slate-800">
                  <div>
                    <span className="text-slate-400 block">Resume Staged:</span>
                    <span className={(autofillReport?.resume_uploaded || liveExecutionStatus?.resume_uploaded) ? 'text-emerald-400 font-bold' : 'text-slate-400'}>
                      {(autofillReport?.resume_uploaded || liveExecutionStatus?.resume_uploaded) ? 'YES (Uploaded)' : 'NO'}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400 block">Fields Populated:</span>
                    <span className="text-emerald-400 font-bold">{autofillReport?.fields_populated_count ?? liveExecutionStatus?.fields_populated_count ?? 0}</span>
                  </div>
                  <div>
                    <span className="text-slate-400 block">Preserved / ATS:</span>
                    <span className="text-blue-400 font-bold">{(autofillReport?.fields_ats_parsed_count ?? 0) + (autofillReport?.fields_preserved_count ?? 0)}</span>
                  </div>
                  <div>
                    <span className="text-slate-400 block">Needs Input (Zero Hallucination):</span>
                    <span className="text-amber-400 font-bold">{autofillReport?.fields_manual_review_count ?? liveExecutionStatus?.fields_manual_review_count ?? 0}</span>
                  </div>
                </div>
                {(liveExecutionStatus?.message || autofillReport?.message) && (
                  <div className="pt-1.5 text-[11px] text-slate-300 border-t border-slate-800 flex items-start gap-1.5">
                    <span className="text-slate-400 shrink-0">Status Message:</span>
                    <span className="text-slate-200">{liveExecutionStatus?.message || autofillReport?.message}</span>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* IAGH Intelligent Gate & Human Interaction Banner */}
          {(liveExecutionStatus?.is_blocking || liveExecutionStatus?.current_state === 'WAITING_FOR_USER' || liveExecutionStatus?.current_state === 'AUTHENTICATION_REQUIRED' || liveExecutionStatus?.current_state === 'SECURITY_CHALLENGE_REQUIRED') && (
            <div className="p-5 rounded-2xl bg-amber-500/10 border-2 border-amber-500/30 space-y-3 animate-in fade-in duration-300">
              <div className="flex items-start justify-between gap-3">
                <div className="flex items-start gap-3">
                  <div className="p-2.5 rounded-xl bg-amber-500/20 text-amber-700 shrink-0 mt-0.5">
                    <ShieldAlert size={20} className="animate-pulse" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider bg-amber-200 text-amber-900">
                        {liveExecutionStatus.current_state === 'AUTHENTICATION_REQUIRED'
                          ? 'Authentication Required'
                          : liveExecutionStatus.current_state === 'SECURITY_CHALLENGE_REQUIRED'
                          ? 'Security Challenge Required'
                          : 'Action Required in Employer Tab'}
                      </span>
                      <span className="text-[11px] font-medium text-amber-800">
                        Automation Paused Safely
                      </span>
                    </div>
                    <h4 className="text-sm font-bold text-slate-900 mt-1">
                      {liveExecutionStatus.interaction_guidance?.title ||
                       (liveExecutionStatus.current_state === 'AUTHENTICATION_REQUIRED' ? 'Employer Portal Sign-In Required' :
                        liveExecutionStatus.current_state === 'SECURITY_CHALLENGE_REQUIRED' ? 'Security Verification Required' :
                        'Review & Decision Required in Employer Portal')}
                    </h4>
                    <p className="text-xs text-slate-700 mt-1 leading-relaxed">
                      {liveExecutionStatus.interaction_guidance?.instruction ||
                       liveExecutionStatus.required_user_action ||
                       liveExecutionStatus.message ||
                       'The employer requires you to perform a manual action (such as accepting terms or signing in) before displaying the application form. Please complete it in the employer tab.'}
                    </p>
                  </div>
                </div>
              </div>

              <div className="pt-2 border-t border-amber-500/20 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs">
                <div className="flex items-center gap-2 text-amber-900 font-medium">
                  <span className="w-2 h-2 rounded-full bg-amber-500 animate-ping"></span>
                  <span>JobFlow will automatically resume once the application form becomes accessible.</span>
                </div>
                {targetFormUrl && (
                  <a
                    href={targetFormUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-amber-600 hover:bg-amber-700 text-white font-bold text-xs transition-colors shrink-0"
                  >
                    <span>Go to Employer Tab</span>
                    <ExternalLink size={12} />
                  </a>
                )}
              </div>
            </div>
          )}

          {/* Progress Stepper (Visible during or after autofill) */}
          {(isAutofilling || autofillProgressStep > 0) && (
            <div className="p-5 rounded-2xl bg-slate-50 border border-slate-200 space-y-3">
              <div className="flex items-center justify-between">
                <h4 className="text-xs font-bold text-slate-900 flex items-center gap-2">
                  <Layers size={14} className="text-brand-600" />
                  <span>Form Auto-Population Execution Progress</span>
                </h4>
                <span className="text-[11px] font-semibold text-slate-500">
                  {autofillProgressStep === 9
                    ? 'Status: Ready for Human Inspection'
                    : isAutofilling
                    ? `Running: Stage ${autofillProgressStep} of 9`
                    : 'Execution Completed'}
                </span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-[11px]">
                {[
                  { num: 1, title: '1. Opening employer portal' },
                  { num: 2, title: '2. Establishing browser connection' },
                  { num: 3, title: '3. Identifying ATS & application form' },
                  { num: 4, title: '4. Retrieving verified candidate facts' },
                  { num: 5, title: '5. Uploading verified resume' },
                  { num: 6, title: '6. Waiting for ATS resume parsing' },
                  { num: 7, title: '7. Mapping and populating fields' },
                  { num: 8, title: '8. Verifying populated values' },
                  { num: 9, title: '9. Ready for human review' },
                ].map((st) => {
                  const isDone = autofillProgressStep > st.num || (!isAutofilling && autofillProgressStep === 9);
                  const isAct = autofillProgressStep === st.num && isAutofilling;
                  return (
                    <div
                      key={st.num}
                      className={`p-2.5 rounded-lg border flex items-center gap-2 transition-all ${
                        isDone
                          ? 'bg-emerald-50 border-emerald-200 text-emerald-800'
                          : isAct
                          ? 'bg-blue-50 border-blue-300 text-blue-900 font-bold shadow-sm'
                          : 'bg-white border-slate-200 text-slate-400'
                      }`}
                    >
                      {isDone ? (
                        <CheckCircle2 size={14} className="text-emerald-600 shrink-0" />
                      ) : isAct ? (
                        <LoadingSpinner size={14} />
                      ) : (
                        <div className="w-3.5 h-3.5 rounded-full border border-slate-300 shrink-0" />
                      )}
                      <span className="truncate">{st.title}</span>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Autofill Results Summary & Editable Field Table */}
          {autofillReport && (
            <div className="p-5 rounded-2xl bg-white border border-slate-200 space-y-4 shadow-sm">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div>
                  <h4 className="text-xs font-bold text-slate-900 flex items-center gap-2">
                    <CheckCircle2 size={15} className="text-emerald-600" />
                    <span>Auto-Population Results & Review</span>
                  </h4>
                  <p className="text-xs text-slate-500 mt-0.5">
                    Review and verify all populated values below. You can edit any field before final submission.
                  </p>
                </div>

                <div className="flex items-center gap-2 flex-wrap">
                  <span className="px-2.5 py-1 rounded-full text-xs font-semibold bg-emerald-100 text-emerald-800">
                    {autofillReport.fields_populated_count} Populated
                  </span>
                  <span className="px-2.5 py-1 rounded-full text-xs font-semibold bg-blue-100 text-blue-800">
                    {autofillReport.fields_ats_parsed_count} ATS Parsed
                  </span>
                  <span className="px-2.5 py-1 rounded-full text-xs font-semibold bg-amber-100 text-amber-800">
                    {autofillReport.fields_manual_review_count} Requires Review
                  </span>
                </div>
              </div>

              {/* Editable Field Table with 5 Columns */}
              <div className="overflow-x-auto border border-slate-200 rounded-xl">
                <table className="min-w-full divide-y divide-slate-200 text-xs">
                  <thead className="bg-slate-50 text-slate-600">
                    <tr>
                      <th className="px-3.5 py-2.5 text-left font-semibold">Field Name</th>
                      <th className="px-3.5 py-2.5 text-left font-semibold">Value on Form (Editable)</th>
                      <th className="px-3.5 py-2.5 text-left font-semibold">Source / Provenance</th>
                      <th className="px-3.5 py-2.5 text-left font-semibold">Verification Status</th>
                      <th className="px-3.5 py-2.5 text-left font-semibold">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 bg-white">
                    {editedFieldResults.map((item, idx) => (
                      <tr key={idx} className="hover:bg-slate-50/60 transition-colors">
                        <td className="px-3.5 py-2.5 font-medium text-slate-900 max-w-[180px] truncate" title={item.field_name}>
                          {item.field_name}
                        </td>
                        <td className="px-3.5 py-2.5">
                          <input
                            type="text"
                            value={item.actual_value || ''}
                            onChange={(e) => handleUpdateFieldValue(idx, e.target.value)}
                            placeholder={item.status === 'MANUAL_REVIEW' ? 'Requires candidate input' : ''}
                            className={`w-full px-2.5 py-1.5 rounded-lg border text-xs ${
                              item.status === 'AUTO_FILLED'
                                ? 'bg-emerald-50/50 border-emerald-300 text-emerald-950 font-medium'
                                : item.status === 'ATS_PARSED'
                                ? 'bg-blue-50/50 border-blue-200 text-blue-950'
                                : item.status === 'MANUAL_REVIEW'
                                ? 'bg-amber-50/60 border-amber-300 text-amber-950'
                                : 'bg-slate-50 border-slate-200 text-slate-800'
                            }`}
                          />
                        </td>
                        <td className="px-3.5 py-2.5">
                          <span className="px-2 py-0.5 rounded text-[10px] font-medium bg-slate-100 text-slate-700">
                            {item.provenance}
                          </span>
                        </td>
                        <td className="px-3.5 py-2.5">
                          <span
                            className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${
                              item.status === 'AUTO_FILLED'
                                ? 'bg-emerald-100 text-emerald-800'
                                : item.status === 'ATS_PARSED'
                                ? 'bg-blue-100 text-blue-800'
                                : item.status === 'PRESERVED'
                                ? 'bg-indigo-100 text-indigo-800'
                                : 'bg-amber-100 text-amber-800'
                            }`}
                          >
                            {item.status.replace('_', ' ')}
                          </span>
                        </td>
                        <td className="px-3.5 py-2.5">
                          <span className="text-[11px] font-medium text-slate-500">
                            {item.status === 'AUTO_FILLED' ? (
                              <span className="text-emerald-700 font-semibold">Verified Match</span>
                            ) : item.status === 'ATS_PARSED' ? (
                              <span className="text-blue-700 font-semibold">ATS Extracted</span>
                            ) : item.status === 'MANUAL_REVIEW' ? (
                              <span className="text-amber-700 font-semibold">Needs Input</span>
                            ) : (
                              <span className="text-slate-600">Candidate Edited</span>
                            )}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Section 2: Strict Human Review & Manual Submission Confirmation */}
          <div className="p-5 rounded-2xl bg-slate-50 border border-slate-200 space-y-4">
            <div className="flex items-start gap-3 p-3.5 rounded-xl bg-amber-50/80 border border-amber-200 text-amber-900 text-xs leading-relaxed">
              <AlertTriangle size={16} className="text-amber-600 shrink-0 mt-0.5" />
              <div>
                <strong>Strict Human-in-the-Loop Protocol:</strong> JobFlow AI will never submit an application autonomously.
                Please inspect all filled fields on the employer portal, complete any mandatory declarations, and click
                <strong> Submit Application</strong> personally.
              </div>
            </div>

            <h4 className="text-xs font-bold text-slate-900">Log Manual Submission Confirmation</h4>
            <div className="flex items-start gap-3">
              <input
                type="checkbox"
                id="submission-confirm"
                checked={candidateConfirmedSubmission}
                onChange={(e) => setCandidateConfirmedSubmission(e.target.checked)}
                className="mt-1 w-4 h-4 rounded text-brand-600 focus:ring-brand-500 cursor-pointer"
              />
              <label htmlFor="submission-confirm" className="text-xs text-slate-700 leading-relaxed cursor-pointer">
                I have inspected the populated form on the employer portal and personally clicked <strong>Submit Application</strong>.
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
                  <option value="COMPANY_PORTAL">Employer Career Portal (Keka / ATS)</option>
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
                  placeholder="e.g. KEKA-94821 or Job Reference ID"
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
                placeholder="e.g. Applied via Keka ATS, notice period set to 0 days"
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
