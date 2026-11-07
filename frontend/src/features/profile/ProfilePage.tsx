import React, { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { api } from '@/lib/api';
import { CandidateProfile, ResumeItem } from '@/types';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { FileDropzone } from '@/components/common/FileDropzone';
import {
  User,
  FileText,
  GraduationCap,
  Briefcase,
  Code2,
  CheckCircle2,
  Trash2,
  RefreshCw,
  Star,
  Plus,
  Save,
  AlertCircle,
} from 'lucide-react';

export const ProfilePage: React.FC = () => {
  const [searchParams] = useSearchParams();
  const initialTab = searchParams.get('tab') === 'resumes' ? 'resumes' : 'personal';

  const [activeTab, setActiveTab] = useState<'personal' | 'education' | 'experience' | 'skills' | 'resumes'>(
    initialTab as any
  );

  const [profile, setProfile] = useState<CandidateProfile>({});
  const [resumes, setResumes] = useState<ResumeItem[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isSaving, setIsSaving] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // Resume upload state
  const [uploadingResume, setUploadingResume] = useState(false);

  const loadData = async () => {
    setIsLoading(true);
    try {
      const [profData, resList] = await Promise.all([
        api.getProfile(),
        api.getResumes(),
      ]);
      setProfile(profData.profile_data || {});
      setResumes(resList);
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to load candidate profile.');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleSaveProfile = async () => {
    setIsSaving(true);
    setErrorMsg(null);
    setSaveSuccess(false);
    try {
      await api.updateProfile(profile);
      setSaveSuccess(true);
      setTimeout(() => setSaveSuccess(false), 3000);
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to save profile changes.');
    } finally {
      setIsSaving(false);
    }
  };

  const handleResumeFileSelect = async (file: File) => {
    setUploadingResume(true);
    setErrorMsg(null);
    try {
      const uploaded = await api.uploadResume(file);
      // Automatically sync profile with parsed resume
      try {
        await api.syncProfileWithResume(uploaded.id);
      } catch (syncErr: any) {
        console.warn('Profile sync non-fatal warning:', syncErr);
      }
      await loadData();
    } catch (err: any) {
      setErrorMsg(err.message || 'Resume upload failed.');
    } finally {
      setUploadingResume(false);
    }
  };

  const handleSetPrimary = async (resumeId: number) => {
    try {
      await api.setPrimaryResume(resumeId);
      await loadData();
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to set primary resume.');
    }
  };

  const handleDeleteResume = async (resumeId: number) => {
    if (!window.confirm('Are you sure you want to delete this resume?')) return;
    try {
      await api.deleteResume(resumeId);
      await loadData();
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to delete resume.');
    }
  };

  const handleSyncResume = async (resumeId: number) => {
    try {
      await api.syncProfileWithResume(resumeId);
      await loadData();
      setSaveSuccess(true);
      setTimeout(() => setSaveSuccess(false), 3000);
    } catch (err: any) {
      setErrorMsg(err.message || 'Sync failed.');
    }
  };

  if (isLoading) {
    return (
      <div className="py-20 flex justify-center">
        <LoadingSpinner size={32} />
      </div>
    );
  }

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-extrabold text-slate-900 tracking-tight">
            Candidate Profile & Credentials
          </h1>
          <p className="text-xs text-slate-500 mt-1">
            Grounded in verifiable facts. Used to calculate match scores and tailor application documents.
          </p>
        </div>

        {activeTab !== 'resumes' && (
          <button
            onClick={handleSaveProfile}
            disabled={isSaving}
            className="px-5 py-2.5 rounded-xl bg-brand-600 hover:bg-brand-700 text-white font-semibold text-xs shadow-md shadow-brand-500/20 flex items-center gap-2 self-start sm:self-center transition-all disabled:opacity-50"
          >
            {isSaving ? (
              <LoadingSpinner size={14} className="text-white" />
            ) : (
              <Save size={15} />
            )}
            <span>{isSaving ? 'Saving...' : 'Save Profile Changes'}</span>
          </button>
        )}
      </div>

      {errorMsg && (
        <div className="p-4 rounded-xl bg-rose-50 border border-rose-200 text-rose-700 text-xs flex items-center gap-2">
          <AlertCircle size={16} />
          <span>{errorMsg}</span>
        </div>
      )}

      {saveSuccess && (
        <div className="p-4 rounded-xl bg-emerald-50 border border-emerald-200 text-emerald-700 text-xs flex items-center gap-2">
          <CheckCircle2 size={16} />
          <span>Profile changes saved successfully!</span>
        </div>
      )}

      {/* Main Tabs Navigation */}
      <div className="flex items-center gap-2 border-b border-slate-200 overflow-x-auto pb-px">
        {[
          { id: 'personal', label: 'Personal Details', icon: User },
          { id: 'education', label: 'Education', icon: GraduationCap },
          { id: 'experience', label: 'Work Experience', icon: Briefcase },
          { id: 'skills', label: 'Skills & Tech', icon: Code2 },
          { id: 'resumes', label: 'Resume Library', icon: FileText, badge: resumes.length },
        ].map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`flex items-center gap-2 px-4 py-3 border-b-2 font-semibold text-xs whitespace-nowrap transition-all ${
                isActive
                  ? 'border-brand-600 text-brand-700'
                  : 'border-transparent text-slate-500 hover:text-slate-800 hover:border-slate-300'
              }`}
            >
              <Icon size={16} />
              <span>{tab.label}</span>
              {tab.badge !== undefined && (
                <span className="ml-1 px-1.5 py-0.2 rounded-full text-[10px] bg-slate-100 text-slate-700">
                  {tab.badge}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* TAB 1: PERSONAL DETAILS */}
      {activeTab === 'personal' && (
        <div className="bg-white rounded-3xl p-6 sm:p-8 border border-slate-200/80 shadow-sm space-y-6">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-5">
            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1.5">
                Full Name
              </label>
              <input
                type="text"
                value={profile.personal_info?.full_name || ''}
                onChange={(e) =>
                  setProfile({
                    ...profile,
                    personal_info: { ...profile.personal_info, full_name: e.target.value },
                  })
                }
                placeholder="e.g. Pranay Agrawal"
                className="w-full px-3.5 py-2.5 rounded-xl border border-slate-200 text-xs focus:ring-2 focus:ring-brand-500 focus:outline-none"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1.5">
                Email Address
              </label>
              <input
                type="email"
                value={profile.personal_info?.email || ''}
                onChange={(e) =>
                  setProfile({
                    ...profile,
                    personal_info: { ...profile.personal_info, email: e.target.value },
                  })
                }
                placeholder="you@example.com"
                className="w-full px-3.5 py-2.5 rounded-xl border border-slate-200 text-xs focus:ring-2 focus:ring-brand-500 focus:outline-none"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1.5">
                Phone Number
              </label>
              <input
                type="tel"
                value={profile.personal_info?.phone || ''}
                onChange={(e) =>
                  setProfile({
                    ...profile,
                    personal_info: { ...profile.personal_info, phone: e.target.value },
                  })
                }
                placeholder="+91 98765 43210"
                className="w-full px-3.5 py-2.5 rounded-xl border border-slate-200 text-xs focus:ring-2 focus:ring-brand-500 focus:outline-none"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1.5">
                Current Location
              </label>
              <input
                type="text"
                value={profile.personal_info?.location || ''}
                onChange={(e) =>
                  setProfile({
                    ...profile,
                    personal_info: { ...profile.personal_info, location: e.target.value },
                  })
                }
                placeholder="Pune, India"
                className="w-full px-3.5 py-2.5 rounded-xl border border-slate-200 text-xs focus:ring-2 focus:ring-brand-500 focus:outline-none"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1.5">
                LinkedIn Profile URL
              </label>
              <input
                type="url"
                value={profile.personal_info?.linkedin || ''}
                onChange={(e) =>
                  setProfile({
                    ...profile,
                    personal_info: { ...profile.personal_info, linkedin: e.target.value },
                  })
                }
                placeholder="https://linkedin.com/in/username"
                className="w-full px-3.5 py-2.5 rounded-xl border border-slate-200 text-xs focus:ring-2 focus:ring-brand-500 focus:outline-none"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1.5">
                GitHub Profile URL
              </label>
              <input
                type="url"
                value={profile.personal_info?.github || ''}
                onChange={(e) =>
                  setProfile({
                    ...profile,
                    personal_info: { ...profile.personal_info, github: e.target.value },
                  })
                }
                placeholder="https://github.com/username"
                className="w-full px-3.5 py-2.5 rounded-xl border border-slate-200 text-xs focus:ring-2 focus:ring-brand-500 focus:outline-none"
              />
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: EDUCATION */}
      {activeTab === 'education' && (
        <div className="bg-white rounded-3xl p-6 sm:p-8 border border-slate-200/80 shadow-sm space-y-6">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-slate-900">Academic Background</h3>
            <button
              onClick={() => {
                const eduList = profile.education || [];
                setProfile({
                  ...profile,
                  education: [
                    ...eduList,
                    {
                      institution: '',
                      degree: '',
                      field_of_study: '',
                      graduation_year: '',
                      cgpa: '',
                      provenance: 'USER_CONFIRMED',
                    },
                  ],
                });
              }}
              className="px-3 py-1.5 rounded-xl bg-brand-50 text-brand-700 font-semibold text-xs border border-brand-200 flex items-center gap-1"
            >
              <Plus size={14} />
              <span>Add Degree</span>
            </button>
          </div>

          {(profile.education || []).length === 0 ? (
            <div className="text-center py-8 text-slate-400">
              <GraduationCap size={32} className="mx-auto mb-2 text-slate-300" />
              <p className="text-xs">No educational records added yet.</p>
            </div>
          ) : (
            <div className="space-y-4">
              {profile.education?.map((edu, idx) => (
                <div
                  key={idx}
                  className="p-4 rounded-2xl bg-slate-50 border border-slate-200/80 space-y-3"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-slate-800">Degree #{idx + 1}</span>
                    <button
                      onClick={() => {
                        const updated = [...(profile.education || [])];
                        updated.splice(idx, 1);
                        setProfile({ ...profile, education: updated });
                      }}
                      className="text-rose-600 hover:text-rose-700"
                    >
                      <Trash2 size={15} />
                    </button>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                    <input
                      type="text"
                      placeholder="University / College"
                      value={edu.institution}
                      onChange={(e) => {
                        const updated = [...(profile.education || [])];
                        updated[idx].institution = e.target.value;
                        setProfile({ ...profile, education: updated });
                      }}
                      className="px-3 py-2 rounded-xl border border-slate-200 text-xs bg-white"
                    />
                    <input
                      type="text"
                      placeholder="Degree (e.g. B.Tech Computer Science)"
                      value={edu.degree}
                      onChange={(e) => {
                        const updated = [...(profile.education || [])];
                        updated[idx].degree = e.target.value;
                        setProfile({ ...profile, education: updated });
                      }}
                      className="px-3 py-2 rounded-xl border border-slate-200 text-xs bg-white"
                    />
                    <div className="flex gap-2">
                      <input
                        type="text"
                        placeholder="Grad Year"
                        value={edu.graduation_year || ''}
                        onChange={(e) => {
                          const updated = [...(profile.education || [])];
                          updated[idx].graduation_year = e.target.value;
                          setProfile({ ...profile, education: updated });
                        }}
                        className="w-1/2 px-3 py-2 rounded-xl border border-slate-200 text-xs bg-white"
                      />
                      <input
                        type="text"
                        placeholder="CGPA (e.g. 7.6)"
                        value={edu.cgpa || ''}
                        onChange={(e) => {
                          const updated = [...(profile.education || [])];
                          updated[idx].cgpa = e.target.value;
                          setProfile({ ...profile, education: updated });
                        }}
                        className="w-1/2 px-3 py-2 rounded-xl border border-slate-200 text-xs bg-white"
                      />
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* TAB 3: WORK EXPERIENCE */}
      {activeTab === 'experience' && (
        <div className="bg-white rounded-3xl p-6 sm:p-8 border border-slate-200/80 shadow-sm space-y-6">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-slate-900">Work Experience</h3>
            <button
              onClick={() => {
                const expList = profile.work_experience || [];
                setProfile({
                  ...profile,
                  work_experience: [
                    ...expList,
                    {
                      employer: '',
                      job_title: '',
                      start_date: '',
                      end_date: '',
                      duration: '',
                      responsibilities: [],
                      provenance: 'USER_CONFIRMED',
                    },
                  ],
                });
              }}
              className="px-3 py-1.5 rounded-xl bg-brand-50 text-brand-700 font-semibold text-xs border border-brand-200 flex items-center gap-1"
            >
              <Plus size={14} />
              <span>Add Role</span>
            </button>
          </div>

          {(profile.work_experience || []).length === 0 ? (
            <div className="text-center py-8 text-slate-400">
              <Briefcase size={32} className="mx-auto mb-2 text-slate-300" />
              <p className="text-xs">No work experience records added yet.</p>
            </div>
          ) : (
            <div className="space-y-4">
              {profile.work_experience?.map((exp, idx) => (
                <div
                  key={idx}
                  className="p-4 rounded-2xl bg-slate-50 border border-slate-200/80 space-y-3"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-slate-800">Experience #{idx + 1}</span>
                    <button
                      onClick={() => {
                        const updated = [...(profile.work_experience || [])];
                        updated.splice(idx, 1);
                        setProfile({ ...profile, work_experience: updated });
                      }}
                      className="text-rose-600 hover:text-rose-700"
                    >
                      <Trash2 size={15} />
                    </button>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <input
                      type="text"
                      placeholder="Employer / Company Name"
                      value={exp.employer}
                      onChange={(e) => {
                        const updated = [...(profile.work_experience || [])];
                        updated[idx].employer = e.target.value;
                        setProfile({ ...profile, work_experience: updated });
                      }}
                      className="px-3 py-2 rounded-xl border border-slate-200 text-xs bg-white"
                    />
                    <input
                      type="text"
                      placeholder="Job Title"
                      value={exp.job_title}
                      onChange={(e) => {
                        const updated = [...(profile.work_experience || [])];
                        updated[idx].job_title = e.target.value;
                        setProfile({ ...profile, work_experience: updated });
                      }}
                      className="px-3 py-2 rounded-xl border border-slate-200 text-xs bg-white"
                    />
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                    <input
                      type="text"
                      placeholder="Start Date (e.g. 2023-01)"
                      value={exp.start_date || ''}
                      onChange={(e) => {
                        const updated = [...(profile.work_experience || [])];
                        updated[idx].start_date = e.target.value;
                        setProfile({ ...profile, work_experience: updated });
                      }}
                      className="px-3 py-2 rounded-xl border border-slate-200 text-xs bg-white"
                    />
                    <input
                      type="text"
                      placeholder="End Date (e.g. Present)"
                      value={exp.end_date || ''}
                      onChange={(e) => {
                        const updated = [...(profile.work_experience || [])];
                        updated[idx].end_date = e.target.value;
                        setProfile({ ...profile, work_experience: updated });
                      }}
                      className="px-3 py-2 rounded-xl border border-slate-200 text-xs bg-white"
                    />
                    <input
                      type="text"
                      placeholder="Duration (e.g. 6 mos)"
                      value={exp.duration || ''}
                      onChange={(e) => {
                        const updated = [...(profile.work_experience || [])];
                        updated[idx].duration = e.target.value;
                        setProfile({ ...profile, work_experience: updated });
                      }}
                      className="px-3 py-2 rounded-xl border border-slate-200 text-xs bg-white"
                    />
                  </div>

                  {/* Bullet points */}
                  <div>
                    <label className="block text-[11px] font-semibold text-slate-600 mb-1">
                      Responsibilities & Achievements (one per line)
                    </label>
                    <textarea
                      rows={3}
                      value={(exp.responsibilities || []).join('\n')}
                      onChange={(e) => {
                        const updated = [...(profile.work_experience || [])];
                        updated[idx].responsibilities = e.target.value
                          .split('\n')
                          .filter((s) => s.trim().length > 0);
                        setProfile({ ...profile, work_experience: updated });
                      }}
                      placeholder="Built REST APIs using FastAPI...&#10;Integrated AI models into mobile application..."
                      className="w-full p-2.5 rounded-xl border border-slate-200 text-xs bg-white"
                    />
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* TAB 4: SKILLS */}
      {activeTab === 'skills' && (
        <div className="bg-white rounded-3xl p-6 sm:p-8 border border-slate-200/80 shadow-sm space-y-6">
          <div>
            <h3 className="text-sm font-bold text-slate-900 mb-1">Technical Skills & Competencies</h3>
            <p className="text-xs text-slate-500 mb-4">
              Enter skills separated by commas (e.g. Python, React, Machine Learning, Docker).
            </p>

            <textarea
              rows={4}
              value={
                Array.isArray(profile.technical_skills)
                  ? profile.technical_skills.join(', ')
                  : typeof profile.technical_skills === 'object' && profile.technical_skills !== null
                  ? Object.values(profile.technical_skills).flat().join(', ')
                  : ''
              }
              onChange={(e) => {
                const skills = e.target.value
                  .split(',')
                  .map((s) => s.trim())
                  .filter((s) => s.length > 0);
                setProfile({ ...profile, technical_skills: skills });
              }}
              placeholder="Python, TypeScript, FastAPI, React, SQL, PyTorch, Docker, Git"
              className="w-full p-3.5 rounded-xl border border-slate-200 text-xs focus:ring-2 focus:ring-brand-500 focus:outline-none"
            />
          </div>
        </div>
      )}

      {/* TAB 5: RESUME LIBRARY */}
      {activeTab === 'resumes' && (
        <div className="space-y-6">
          {/* Upload card */}
          <div className="bg-white rounded-3xl p-6 sm:p-8 border border-slate-200/80 shadow-sm">
            <h3 className="text-base font-bold text-slate-900 mb-1">Upload New Resume</h3>
            <p className="text-xs text-slate-500 mb-4">
              Upload PDF or DOCX resume to extract verified candidate credentials and sync your profile.
            </p>

            <FileDropzone
              id="resume-lib-upload"
              onFileSelect={handleResumeFileSelect}
              onError={(err) => setErrorMsg(err)}
              isLoading={uploadingResume}
              loadingText="Uploading & Parsing Resume..."
              title="Click to upload PDF or DOCX"
              subtitle="Maximum file size: 10 MB"
            />
          </div>

          {/* Resumes list */}
          <div className="bg-white rounded-3xl p-6 sm:p-8 border border-slate-200/80 shadow-sm space-y-4">
            <h3 className="text-base font-bold text-slate-900">Stored Resumes ({resumes.length})</h3>

            {resumes.length === 0 ? (
              <div className="py-8 text-center text-slate-400">
                <FileText size={32} className="mx-auto mb-2 text-slate-300" />
                <p className="text-xs">No resumes uploaded yet.</p>
              </div>
            ) : (
              <div className="divide-y divide-slate-100">
                {resumes.map((res) => (
                  <div
                    key={res.id}
                    className="py-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4"
                  >
                    <div className="flex items-start gap-3">
                      <div className="p-2.5 rounded-xl bg-brand-50 text-brand-600 shrink-0">
                        <FileText size={20} />
                      </div>
                      <div>
                        <div className="flex items-center gap-2">
                          <p className="text-xs font-bold text-slate-900">{res.original_filename}</p>
                          {res.is_primary && (
                            <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-50 text-emerald-700 border border-emerald-200">
                              Primary
                            </span>
                          )}
                        </div>
                        <p className="text-[11px] text-slate-400 mt-0.5">
                          Format: {res.file_format.toUpperCase()} &middot; Size:{' '}
                          {(res.file_size_bytes / 1024).toFixed(1)} KB &middot; Hash:{' '}
                          <code className="text-[10px] bg-slate-100 px-1 rounded">
                            {res.file_hash.slice(0, 10)}...
                          </code>
                        </p>
                      </div>
                    </div>

                    <div className="flex items-center gap-2 self-end sm:self-center">
                      {!res.is_primary && (
                        <button
                          onClick={() => handleSetPrimary(res.id)}
                          className="px-3 py-1.5 rounded-xl border border-slate-200 hover:bg-slate-50 text-slate-700 font-semibold text-xs flex items-center gap-1 transition-colors"
                        >
                          <Star size={13} />
                          <span>Make Primary</span>
                        </button>
                      )}
                      <button
                        onClick={() => handleSyncResume(res.id)}
                        className="px-3 py-1.5 rounded-xl bg-brand-50 hover:bg-brand-100 text-brand-700 font-semibold text-xs border border-brand-200 flex items-center gap-1 transition-colors"
                      >
                        <RefreshCw size={13} />
                        <span>Sync Profile</span>
                      </button>
                      <button
                        onClick={() => handleDeleteResume(res.id)}
                        className="p-1.5 rounded-xl text-slate-400 hover:text-rose-600 hover:bg-rose-50 transition-colors"
                      >
                        <Trash2 size={16} />
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
