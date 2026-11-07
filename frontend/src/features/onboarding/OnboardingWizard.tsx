import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '@/features/auth/AuthContext';
import { api } from '@/lib/api';
import { CandidateProfile, InferredRole } from '@/types';
import {
  Sparkles,
  CheckCircle2,
  ArrowRight,
  ArrowLeft,
  FileText,
  AlertCircle,
  GraduationCap,
  Briefcase,
  Code2,
  Check,
  Compass,
  FolderGit2,
} from 'lucide-react';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { FileDropzone } from '@/components/common/FileDropzone';

export const OnboardingWizard: React.FC = () => {
  const { user } = useAuth();
  const navigate = useNavigate();

  const [step, setStep] = useState(1);
  const [file, setFile] = useState<File | null>(null);
  const [isUploading, setIsUploading] = useState(false);
  const [isFinishing, setIsFinishing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [uploadedResume, setUploadedResume] = useState<any>(null);

  // Extracted data for Step 3
  const [profileData, setProfileData] = useState<CandidateProfile | null>(null);
  const [suggestedRoles, setSuggestedRoles] = useState<InferredRole[]>([]);
  const [selectedRoleTitles, setSelectedRoleTitles] = useState<string[]>([]);
  const [customRoleInput, setCustomRoleInput] = useState('');

  const handleUpload = async () => {
    if (!file) return;
    setIsUploading(true);
    setError(null);

    try {
      const res = await api.uploadResume(file);
      setUploadedResume(res);

      if (res.sync_status === 'FAILED') {
        console.warn('Initial profile sync warning:', res.sync_error);
      }

      // Fetch newly extracted profile and dynamic suggested roles
      const [profRes, rolesRes] = await Promise.allSettled([
        api.getProfile(),
        api.getSuggestedRoles(),
      ]);

      if (profRes.status === 'fulfilled' && profRes.value?.profile_data) {
        setProfileData(profRes.value.profile_data);
      }

      if (rolesRes.status === 'fulfilled' && rolesRes.value?.suggested_roles) {
        const roles = rolesRes.value.suggested_roles;
        setSuggestedRoles(roles);
        setSelectedRoleTitles(roles.slice(0, 4).map((r) => r.role_title));
      }

      setStep(3);
    } catch (err: any) {
      setError(err.message || 'Failed to upload and parse resume.');
    } finally {
      setIsUploading(false);
    }
  };

  const toggleRoleSelection = (title: string) => {
    setSelectedRoleTitles((prev) =>
      prev.includes(title) ? prev.filter((t) => t !== title) : [...prev, title]
    );
  };

  const handleAddCustomRole = () => {
    const trimmed = customRoleInput.trim();
    if (trimmed && !selectedRoleTitles.includes(trimmed)) {
      setSelectedRoleTitles((prev) => [...prev, trimmed]);
      setCustomRoleInput('');
    }
  };

  const handleConfirmAndDiscover = async () => {
    setIsFinishing(true);
    setError(null);

    try {
      // 1. Resolve candidate locations, avoiding forcing India if international
      const candLoc = personal?.location || (profileData as any)?.location;
      const targetLocs = candLoc && !candLoc.toLowerCase().includes('india')
        ? [candLoc, 'Remote']
        : ['Remote', 'India'];

      // 2. Save candidate confirmed target roles & preferences
      await api.updateSearchPreferences({
        target_roles: selectedRoleTitles,
        target_locations: targetLocs,
        auto_discover_enabled: true,
      });

      // 3. Trigger automatic candidate-scoped discovery
      await api.triggerDiscovery(selectedRoleTitles, targetLocs);

      // 4. Direct candidate straight to Find Jobs with their recommendations
      navigate('/jobs');
    } catch (err: any) {
      setError(err.message || 'Failed to start automated discovery.');
      setIsFinishing(false);
    }
  };

  // Helper to resolve personal details
  const personal = profileData?.personal || profileData?.personal_info || {};
  const education = profileData?.education || [];
  const primaryEdu = education[0];
  const technicalSkills = Array.isArray(profileData?.technical_skills)
    ? profileData.technical_skills
    : profileData?.technical_skills && typeof profileData.technical_skills === 'object'
    ? Object.values(profileData.technical_skills).flat()
    : [];
  const projects = profileData?.projects || [];
  const experience = profileData?.work_experience || [];

  return (
    <div className="min-h-screen bg-slate-50 flex items-center justify-center p-6">
      <div className={`w-full ${step === 3 ? 'max-w-4xl' : 'max-w-2xl'} bg-white rounded-3xl shadow-xl border border-slate-100 overflow-hidden transition-all duration-300`}>
        {/* Stepper progress */}
        <div className="bg-slate-900 px-8 py-6 text-white flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-xl bg-brand-500/20 text-brand-400 border border-brand-500/30 flex items-center justify-center font-bold text-sm">
              <Sparkles size={16} />
            </div>
            <div>
              <h2 className="font-bold text-base">Quick Start Setup</h2>
              <p className="text-xs text-slate-400">Step {step} of 3</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {[1, 2, 3].map((s) => (
              <div
                key={s}
                className={`w-7 h-1.5 rounded-full transition-all ${
                  s === step ? 'bg-brand-500 w-10' : s < step ? 'bg-emerald-500' : 'bg-slate-700'
                }`}
              />
            ))}
          </div>
        </div>

        <div className="p-8">
          {error && (
            <div className="mb-6 p-4 rounded-xl bg-rose-50 border border-rose-200 text-rose-700 text-sm flex items-start gap-3">
              <AlertCircle size={18} className="shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          {/* STEP 1: WELCOME */}
          {step === 1 && (
            <div className="text-center py-6">
              <div className="w-16 h-16 rounded-3xl bg-brand-50 text-brand-600 flex items-center justify-center mx-auto mb-4">
                <Sparkles size={32} />
              </div>
              <h3 className="text-2xl font-bold text-slate-900">
                Welcome to JobFlow AI, {user?.full_name}!
              </h3>
              <p className="mt-2 text-slate-500 text-sm max-w-md mx-auto leading-relaxed">
                Let's set up your profile in seconds. By uploading your resume, JobFlow will automatically
                extract your verified skills, experience, and educational background without fabricating any details.
              </p>

              <div className="mt-8 flex justify-center">
                <button
                  onClick={() => setStep(2)}
                  className="px-6 py-3 rounded-xl bg-brand-600 hover:bg-brand-700 text-white font-semibold text-sm shadow-md shadow-brand-500/20 flex items-center gap-2 transition-all"
                >
                  <span>Continue to Resume Upload</span>
                  <ArrowRight size={16} />
                </button>
              </div>
            </div>
          )}

          {/* STEP 2: RESUME UPLOAD */}
          {step === 2 && (
            <div>
              <div className="mb-6">
                <h3 className="text-xl font-bold text-slate-900">Upload your latest resume</h3>
                <p className="text-xs text-slate-500 mt-1">
                  Supported formats: PDF or DOCX (max. 10 MB).
                </p>
              </div>

              <FileDropzone
                id="onboarding-resume-upload"
                onFileSelect={(selectedFile) => {
                  setFile(selectedFile);
                  setError(null);
                }}
                onError={(err) => setError(err)}
                selectedFile={file}
                onClearFile={() => setFile(null)}
                isLoading={isUploading}
                loadingText="Parsing resume..."
                title="Click to browse or drag and drop"
                subtitle="PDF or DOCX documents up to 10 MB"
              />

              <div className="mt-8 flex items-center justify-between">
                <button
                  onClick={() => setStep(1)}
                  className="px-4 py-2.5 rounded-xl text-slate-600 hover:bg-slate-100 text-sm font-medium flex items-center gap-2 transition-all"
                >
                  <ArrowLeft size={16} />
                  <span>Back</span>
                </button>
                <div className="flex items-center gap-3">
                  <button
                    onClick={() => navigate('/dashboard')}
                    className="px-4 py-2.5 rounded-xl text-slate-500 hover:text-slate-700 text-sm font-medium"
                  >
                    Skip for now
                  </button>
                  <button
                    disabled={!file || isUploading}
                    onClick={handleUpload}
                    className="px-6 py-2.5 rounded-xl bg-brand-600 hover:bg-brand-700 text-white font-semibold text-sm shadow-md shadow-brand-500/20 flex items-center gap-2 transition-all disabled:opacity-50"
                  >
                    {isUploading ? (
                      <>
                        <LoadingSpinner size={16} className="text-white" />
                        <span>Parsing Resume...</span>
                      </>
                    ) : (
                      <>
                        <span>Upload & Parse</span>
                        <ArrowRight size={16} />
                      </>
                    )}
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* STEP 3: EXTRACTED PROFILE & CAREER PATHS PREVIEW */}
          {step === 3 && (
            <div className="space-y-6">
              <div>
                <div className="flex items-center gap-2 text-emerald-600 text-xs font-semibold uppercase tracking-wider mb-1">
                  <CheckCircle2 size={15} />
                  <span>Resume Parsed Successfully</span>
                </div>
                <h3 className="text-2xl font-bold text-slate-900">
                  Profile Generated & Ready for Discovery
                </h3>
                <p className="text-xs text-slate-500 mt-1">
                  JobFlow extracted your verified background without hallucination. Review your details and select the career paths you'd like us to target.
                </p>
              </div>

              {/* Two Column Grid */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {/* Left Card: Verified Profile Overview */}
                <div className="p-5 rounded-2xl bg-slate-50 border border-slate-200/80 space-y-4">
                  <div className="flex items-center justify-between pb-3 border-b border-slate-200/60">
                    <div>
                      <h4 className="text-sm font-bold text-slate-900">
                        {personal.full_name || user?.full_name || 'Candidate'}
                      </h4>
                      <p className="text-[11px] text-slate-500">
                        {personal.location || 'Location Not Specified'}
                      </p>
                    </div>
                    {uploadedResume && (
                      <span className="px-2 py-0.5 rounded-full text-[10px] bg-emerald-100 text-emerald-700 font-medium flex items-center gap-1">
                        <FileText size={11} />
                        <span>Verified</span>
                      </span>
                    )}
                  </div>

                  {/* Education */}
                  {primaryEdu && (
                    <div className="flex items-start gap-2.5 text-xs text-slate-700">
                      <GraduationCap size={16} className="text-brand-600 shrink-0 mt-0.5" />
                      <div>
                        <p className="font-semibold text-slate-900">{primaryEdu.degree}</p>
                        <p className="text-slate-500 text-[11px]">
                          {primaryEdu.institution}{' '}
                          {primaryEdu.graduation_year ? `(${primaryEdu.graduation_year})` : ''}
                        </p>
                      </div>
                    </div>
                  )}

                  {/* Experience or Fresher Note */}
                  <div className="flex items-start gap-2.5 text-xs text-slate-700">
                    <Briefcase size={16} className="text-brand-600 shrink-0 mt-0.5" />
                    <div>
                      {experience.length > 0 ? (
                        <>
                          <p className="font-semibold text-slate-900">{experience[0].job_title}</p>
                          <p className="text-slate-500 text-[11px]">
                            {experience[0].employer}{' '}
                            {experience[0].duration ? `· ${experience[0].duration}` : ''}
                          </p>
                        </>
                      ) : (
                        <>
                          <p className="font-semibold text-slate-900">Fresher / Early Career</p>
                          <p className="text-slate-500 text-[11px]">
                            Academic projects and technical skills will be highlighted.
                          </p>
                        </>
                      )}
                    </div>
                  </div>

                  {/* Projects count */}
                  {projects.length > 0 && (
                    <div className="flex items-start gap-2.5 text-xs text-slate-700">
                      <FolderGit2 size={16} className="text-brand-600 shrink-0 mt-0.5" />
                      <div>
                        <p className="font-semibold text-slate-900">
                          {projects.length} Verified Project{projects.length > 1 ? 's' : ''}
                        </p>
                        <p className="text-slate-500 text-[11px] truncate max-w-[240px]">
                          {projects.map((p) => p.name || p.title).filter(Boolean).join(', ')}
                        </p>
                      </div>
                    </div>
                  )}

                  {/* Extracted Skills */}
                  <div>
                    <div className="flex items-center gap-1.5 text-[11px] font-semibold text-slate-700 mb-2">
                      <Code2 size={13} className="text-brand-600" />
                      <span>Extracted Technical Skills</span>
                    </div>
                    <div className="flex flex-wrap gap-1.5 max-h-24 overflow-y-auto pr-1">
                      {technicalSkills.slice(0, 10).map((skill: string, idx: number) => (
                        <span
                          key={idx}
                          className="px-2 py-0.5 rounded-lg text-[10px] font-medium bg-white border border-slate-200 text-slate-700 shadow-2xs"
                        >
                          {skill}
                        </span>
                      ))}
                      {technicalSkills.length > 10 && (
                        <span className="text-[10px] text-slate-400 self-center">
                          +{technicalSkills.length - 10} more
                        </span>
                      )}
                    </div>
                  </div>
                </div>

                {/* Right Card: Suggested Career Paths & Role Selection */}
                <div className="p-5 rounded-2xl bg-white border border-slate-200/80 shadow-xs flex flex-col justify-between space-y-4">
                  <div>
                    <div className="flex items-center gap-2 mb-2">
                      <div className="p-1.5 rounded-lg bg-brand-50 text-brand-600">
                        <Compass size={16} />
                      </div>
                      <div>
                        <h4 className="text-sm font-bold text-slate-900">Suggested Career Paths</h4>
                        <p className="text-[11px] text-slate-500">
                          Select the target job roles you wish to discover:
                        </p>
                      </div>
                    </div>

                    {/* Role Badges */}
                    <div className="space-y-2 mt-3">
                      {suggestedRoles.map((role, idx) => {
                        const isSelected = selectedRoleTitles.includes(role.role_title);
                        return (
                          <button
                            key={idx}
                            type="button"
                            onClick={() => toggleRoleSelection(role.role_title)}
                            className={`w-full text-left p-3 rounded-xl border text-xs transition-all flex items-center justify-between ${
                              isSelected
                                ? 'border-brand-500 bg-brand-50/60 text-brand-900 shadow-2xs'
                                : 'border-slate-200 bg-white hover:border-slate-300 text-slate-700'
                            }`}
                          >
                            <div className="space-y-0.5">
                              <div className="flex items-center gap-2">
                                <span className="font-semibold">{role.role_title}</span>
                                <span className="px-1.5 py-0.2 rounded-md text-[9px] font-bold bg-slate-100 text-slate-600">
                                  {Math.round(role.confidence * 100)}% Match
                                </span>
                              </div>
                              <p className="text-[10px] text-slate-400">
                                From: {role.supporting_skills?.slice(0, 3).join(', ') || 'Resume profile'}
                              </p>
                            </div>
                            <div
                              className={`w-5 h-5 rounded-md flex items-center justify-center shrink-0 ${
                                isSelected ? 'bg-brand-600 text-white' : 'border border-slate-300'
                              }`}
                            >
                              {isSelected && <Check size={12} />}
                            </div>
                          </button>
                        );
                      })}
                    </div>

                    {/* Add Custom Role */}
                    <div className="mt-3 flex gap-2">
                      <input
                        type="text"
                        value={customRoleInput}
                        onChange={(e) => setCustomRoleInput(e.target.value)}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter') {
                            e.preventDefault();
                            handleAddCustomRole();
                          }
                        }}
                        placeholder="Add another target role..."
                        className="flex-1 px-3 py-1.5 rounded-xl border border-slate-200 text-xs focus:ring-2 focus:ring-brand-500 focus:outline-none"
                      />
                      <button
                        type="button"
                        onClick={handleAddCustomRole}
                        disabled={!customRoleInput.trim()}
                        className="px-3 py-1.5 rounded-xl bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-semibold disabled:opacity-50"
                      >
                        Add
                      </button>
                    </div>
                  </div>

                  <p className="text-[10px] text-slate-400 italic">
                    Location preference defaults to Remote and verified home country.
                  </p>
                </div>
              </div>

              {/* Bottom Navigation */}
              <div className="mt-8 pt-4 border-t border-slate-100 flex items-center justify-between">
                <button
                  type="button"
                  onClick={() => navigate('/profile')}
                  className="px-4 py-2.5 rounded-xl text-slate-600 hover:bg-slate-100 text-xs font-medium transition-all"
                >
                  Review Full Profile First
                </button>

                <button
                  type="button"
                  disabled={isFinishing || selectedRoleTitles.length === 0}
                  onClick={handleConfirmAndDiscover}
                  className="px-6 py-2.5 rounded-xl bg-brand-600 hover:bg-brand-700 text-white font-semibold text-xs shadow-md shadow-brand-500/20 flex items-center gap-2 transition-all disabled:opacity-50"
                >
                  {isFinishing ? (
                    <>
                      <LoadingSpinner size={14} className="text-white" />
                      <span>Initiating Discovery...</span>
                    </>
                  ) : (
                    <>
                      <Sparkles size={14} />
                      <span>Confirm & Discover Matching Jobs</span>
                      <ArrowRight size={14} />
                    </>
                  )}
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
