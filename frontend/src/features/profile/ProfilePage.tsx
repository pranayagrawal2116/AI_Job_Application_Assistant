import React, { useState, useEffect } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { api } from '@/lib/api';
import { CandidateProfile, InferredRole, ResumeItem } from '@/types';
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
  Compass,
  FolderGit2,
  Check,
  Sparkles,
  X,
  ShieldCheck,
  Award,
  Languages,
  Wrench,
} from 'lucide-react';

export const ProfilePage: React.FC = () => {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const initialTab = searchParams.get('tab') === 'resumes' ? 'resumes' : 'personal';

  const [activeTab, setActiveTab] = useState<
    'personal' | 'education' | 'experience' | 'projects' | 'skills' | 'preferences' | 'resumes'
  >(initialTab as any);

  const [profile, setProfile] = useState<CandidateProfile>({});
  const [resumes, setResumes] = useState<ResumeItem[]>([]);
  const [suggestedRoles, setSuggestedRoles] = useState<InferredRole[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isSaving, setIsSaving] = useState(false);
  const [isDiscovering, setIsDiscovering] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(false);
  const [discoverySuccess, setDiscoverySuccess] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // Resume upload state
  const [uploadingResume, setUploadingResume] = useState(false);

  // Input states for Preferences
  const [newRoleInput, setNewRoleInput] = useState('');
  const [newLocInput, setNewLocInput] = useState('');

  const loadData = async () => {
    setIsLoading(true);
    try {
      const [profData, resList, rolesRes] = await Promise.all([
        api.getProfile(),
        api.getResumes(),
        api.getSuggestedRoles().catch(() => ({ suggested_roles: [], suggested_locations: [] })),
      ]);
      setProfile(profData.profile_data || {});
      setResumes(resList);
      setSuggestedRoles(rolesRes.suggested_roles || []);
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
      if (uploaded.sync_status === 'FAILED') {
        setErrorMsg(`Resume uploaded, but profile synchronization encountered an error: ${uploaded.sync_error || 'Check document structure'}`);
      } else {
        setSaveSuccess(true);
        setTimeout(() => setSaveSuccess(false), 4000);
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

  const handleTriggerDiscovery = async () => {
    setIsDiscovering(true);
    setDiscoverySuccess(null);
    setErrorMsg(null);

    const searchPrefs = profile.search_preferences || profile.preferences || {};
    const roles = searchPrefs.target_roles || [];
    const locs = searchPrefs.target_locations || ['Remote', 'India'];

    try {
      const res = await api.triggerDiscovery(roles, locs);
      setDiscoverySuccess(res.message || 'Discovery started! Searching opportunities in background.');
      setTimeout(() => {
        navigate('/jobs');
      }, 1500);
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to trigger discovery.');
      setIsDiscovering(false);
    }
  };

  // Safe personal details accessor
  const personal = profile.personal || profile.personal_info || {};

  const updatePersonalField = (field: string, value: string) => {
    const updated = { ...personal, [field]: value };
    setProfile({
      ...profile,
      personal: updated,
      personal_info: updated,
    });
  };

  // Preferences accessors
  const currentPrefs = profile.search_preferences || profile.preferences || {
    target_roles: [],
    target_locations: ['Remote', 'India'],
    auto_discover_enabled: true,
  };
  const targetRoles: string[] = currentPrefs.target_roles || [];
  const targetLocations: string[] = currentPrefs.target_locations || ['Remote', 'India'];

  const updatePreferences = (newPrefs: any) => {
    setProfile({
      ...profile,
      search_preferences: newPrefs,
      preferences: newPrefs,
    });
  };

  const handleAddTargetRole = (role: string) => {
    const trimmed = role.trim();
    if (trimmed && !targetRoles.includes(trimmed)) {
      updatePreferences({
        ...currentPrefs,
        target_roles: [...targetRoles, trimmed],
      });
      setNewRoleInput('');
    }
  };

  const handleRemoveTargetRole = (role: string) => {
    updatePreferences({
      ...currentPrefs,
      target_roles: targetRoles.filter((r) => r !== role),
    });
  };

  const handleAddLocation = (loc: string) => {
    const trimmed = loc.trim();
    if (trimmed && !targetLocations.includes(trimmed)) {
      updatePreferences({
        ...currentPrefs,
        target_locations: [...targetLocations, trimmed],
      });
      setNewLocInput('');
    }
  };

  const handleRemoveLocation = (loc: string) => {
    updatePreferences({
      ...currentPrefs,
      target_locations: targetLocations.filter((l) => l !== loc),
    });
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
            Grounded in verifiable facts. Used to calculate personalized match scores and tailor applications.
          </p>
        </div>

        {activeTab !== 'resumes' && (
          <div className="flex items-center gap-2 self-start sm:self-center">
            {activeTab === 'preferences' && (
              <button
                onClick={handleTriggerDiscovery}
                disabled={isDiscovering}
                className="px-4 py-2.5 rounded-xl bg-slate-900 hover:bg-slate-800 text-white font-semibold text-xs shadow-md flex items-center gap-1.5 transition-all disabled:opacity-50"
              >
                {isDiscovering ? (
                  <LoadingSpinner size={14} className="text-white" />
                ) : (
                  <Sparkles size={14} className="text-amber-400" />
                )}
                <span>{isDiscovering ? 'Searching...' : 'Discover Jobs Now'}</span>
              </button>
            )}

            <button
              onClick={handleSaveProfile}
              disabled={isSaving}
              className="px-5 py-2.5 rounded-xl bg-brand-600 hover:bg-brand-700 text-white font-semibold text-xs shadow-md shadow-brand-500/20 flex items-center gap-2 transition-all disabled:opacity-50"
            >
              {isSaving ? (
                <LoadingSpinner size={14} className="text-white" />
              ) : (
                <Save size={15} />
              )}
              <span>{isSaving ? 'Saving...' : 'Save Profile Changes'}</span>
            </button>
          </div>
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

      {discoverySuccess && (
        <div className="p-4 rounded-xl bg-blue-50 border border-blue-200 text-blue-700 text-xs flex items-center gap-2">
          <Sparkles size={16} className="text-blue-600" />
          <span>{discoverySuccess}</span>
        </div>
      )}

      {/* Main Tabs Navigation */}
      <div className="flex items-center gap-2 border-b border-slate-200 overflow-x-auto pb-px">
        {[
          { id: 'personal', label: 'Personal Details', icon: User },
          { id: 'education', label: 'Education', icon: GraduationCap },
          { id: 'experience', label: 'Work Experience', icon: Briefcase },
          { id: 'projects', label: 'Projects', icon: FolderGit2, badge: (profile.projects || []).length },
          { id: 'skills', label: 'Skills & Tech', icon: Code2 },
          { id: 'preferences', label: 'Career Preferences', icon: Compass },
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
              {tab.badge !== undefined && tab.badge > 0 && (
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
          <div className="flex items-center justify-between pb-3 border-b border-slate-100">
            <div>
              <h3 className="text-sm font-bold text-slate-900">Personal & Contact Information</h3>
              <p className="text-xs text-slate-500">Verified credentials from your primary uploaded resume.</p>
            </div>
            <span className="px-2.5 py-1 rounded-full text-[11px] font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200/60 flex items-center gap-1.5">
              <ShieldCheck size={13} />
              <span>Verified Facts Only</span>
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-5">
            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1.5">
                Full Name
              </label>
              <input
                type="text"
                value={personal.full_name || ''}
                onChange={(e) => updatePersonalField('full_name', e.target.value)}
                placeholder="e.g. Alex Candidate"
                className="w-full px-3.5 py-2.5 rounded-xl border border-slate-200 text-xs focus:ring-2 focus:ring-brand-500 focus:outline-none"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1.5">
                Email Address
              </label>
              <input
                type="email"
                value={personal.email || ''}
                onChange={(e) => updatePersonalField('email', e.target.value)}
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
                value={personal.phone || ''}
                onChange={(e) => updatePersonalField('phone', e.target.value)}
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
                value={personal.location || ''}
                onChange={(e) => updatePersonalField('location', e.target.value)}
                placeholder="e.g. Bengaluru, India"
                className="w-full px-3.5 py-2.5 rounded-xl border border-slate-200 text-xs focus:ring-2 focus:ring-brand-500 focus:outline-none"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1.5">
                LinkedIn Profile URL
              </label>
              <input
                type="url"
                value={personal.linkedin || ''}
                onChange={(e) => updatePersonalField('linkedin', e.target.value)}
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
                value={personal.github || ''}
                onChange={(e) => updatePersonalField('github', e.target.value)}
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
            <div>
              <h3 className="text-sm font-bold text-slate-900">Academic Background</h3>
              <p className="text-xs text-slate-500">Degree, institution, graduation timeline, and grades.</p>
            </div>
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
                        value={edu.graduation_year || edu.expected_graduation_year || ''}
                        onChange={(e) => {
                          const updated = [...(profile.education || [])];
                          updated[idx].graduation_year = e.target.value;
                          updated[idx].expected_graduation_year = e.target.value;
                          setProfile({ ...profile, education: updated });
                        }}
                        className="w-1/2 px-3 py-2 rounded-xl border border-slate-200 text-xs bg-white"
                      />
                      <input
                        type="text"
                        placeholder="CGPA / %"
                        value={edu.cgpa || edu.current_cgpa || (edu.percentage ? `${edu.percentage}%` : '')}
                        onChange={(e) => {
                          const updated = [...(profile.education || [])];
                          updated[idx].cgpa = e.target.value;
                          updated[idx].current_cgpa = e.target.value;
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
            <div>
              <h3 className="text-sm font-bold text-slate-900">Work Experience</h3>
              <p className="text-xs text-slate-500">Professional internships and full-time positions.</p>
            </div>
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
            <div className="text-center py-12 px-6 rounded-2xl bg-slate-50 border border-dashed border-slate-200">
              <div className="w-12 h-12 rounded-2xl bg-brand-50 text-brand-600 flex items-center justify-center mx-auto mb-3">
                <Briefcase size={22} />
              </div>
              <h4 className="text-sm font-bold text-slate-800">No Employment Experience Identified</h4>
              <p className="text-xs text-slate-500 mt-1 max-w-sm mx-auto">
                No employment experience was identified in your resume. If you are a student, recent graduate, or fresher, your academic projects and verified technical skills are used for matching.
              </p>
              <button
                type="button"
                onClick={() => {
                  setProfile({
                    ...profile,
                    work_experience: [
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
                className="mt-4 px-4 py-2 rounded-xl bg-white border border-slate-200 hover:bg-slate-50 text-slate-700 font-semibold text-xs inline-flex items-center gap-1.5 shadow-2xs"
              >
                <Plus size={14} />
                <span>Add Work Experience Manually</span>
              </button>
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

          {/* ACCA Practical Experience Requirement (PER) / Supervised Training */}
          <div className="pt-6 border-t border-slate-200/80 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div>
                <div className="flex items-center gap-2">
                  <h4 className="text-sm font-bold text-slate-900">
                    ACCA Practical Experience Requirement (PER) / Supervised Training
                  </h4>
                  <span className="px-2 py-0.5 rounded-full text-[10px] font-semibold bg-blue-50 text-blue-700 border border-blue-200">
                    Professional Qualification Record
                  </span>
                </div>
                <p className="text-xs text-slate-500 mt-0.5">
                  Supervised professional experience, mentor sign-offs, and practical performance objectives.
                </p>
              </div>
              <button
                type="button"
                onClick={() => {
                  const current = profile.per_experience || [];
                  setProfile({
                    ...profile,
                    per_experience: [
                      ...current,
                      {
                        employer: '',
                        job_title: 'Trainee / Supervised Experience',
                        supervisory_context: 'Supervised by ACCA Member / Senior Accountant',
                        start_date: '',
                        end_date: '',
                        duration: '',
                        responsibilities: [],
                        provenance: 'USER_CONFIRMED',
                      },
                    ],
                  });
                }}
                className="px-3 py-1.5 rounded-xl bg-blue-50 text-blue-700 font-semibold text-xs border border-blue-200 flex items-center gap-1 hover:bg-blue-100 self-start sm:self-auto"
              >
                <Plus size={14} />
                <span>Add PER Record</span>
              </button>
            </div>

            {(profile.per_experience || []).length === 0 ? (
              <div className="p-4 rounded-2xl bg-slate-50 border border-slate-200/70 text-slate-500 text-xs flex items-center gap-2">
                <Briefcase size={16} className="text-slate-400 shrink-0" />
                <span>No ACCA Practical Experience Requirement (PER) records identified. Add records above if applicable to your professional credentialing.</span>
              </div>
            ) : (
              <div className="space-y-4">
                {profile.per_experience?.map((per, idx) => (
                  <div key={idx} className="p-4 rounded-2xl bg-blue-50/40 border border-blue-200/70 space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold text-blue-950">PER Objective #{idx + 1}</span>
                      <button
                        type="button"
                        onClick={() => {
                          const updated = [...(profile.per_experience || [])];
                          updated.splice(idx, 1);
                          setProfile({ ...profile, per_experience: updated });
                        }}
                        className="text-rose-600 hover:text-rose-700"
                      >
                        <Trash2 size={15} />
                      </button>
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                      <input
                        type="text"
                        placeholder="Organization / Mentor Context"
                        value={per.employer || per.supervisory_context || ''}
                        onChange={(e) => {
                          const updated = [...(profile.per_experience || [])];
                          updated[idx].employer = e.target.value;
                          setProfile({ ...profile, per_experience: updated });
                        }}
                        className="px-3 py-2 rounded-xl border border-slate-200 text-xs bg-white"
                      />
                      <input
                        type="text"
                        placeholder="Role / Objective Title"
                        value={per.job_title || per.role_name || ''}
                        onChange={(e) => {
                          const updated = [...(profile.per_experience || [])];
                          updated[idx].job_title = e.target.value;
                          setProfile({ ...profile, per_experience: updated });
                        }}
                        className="px-3 py-2 rounded-xl border border-slate-200 text-xs bg-white"
                      />
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                      <input
                        type="text"
                        placeholder="Start Date (e.g. 2023-01)"
                        value={per.start_date || ''}
                        onChange={(e) => {
                          const updated = [...(profile.per_experience || [])];
                          updated[idx].start_date = e.target.value;
                          setProfile({ ...profile, per_experience: updated });
                        }}
                        className="px-3 py-2 rounded-xl border border-slate-200 text-xs bg-white"
                      />
                      <input
                        type="text"
                        placeholder="End Date (e.g. Present)"
                        value={per.end_date || ''}
                        onChange={(e) => {
                          const updated = [...(profile.per_experience || [])];
                          updated[idx].end_date = e.target.value;
                          setProfile({ ...profile, per_experience: updated });
                        }}
                        className="px-3 py-2 rounded-xl border border-slate-200 text-xs bg-white"
                      />
                      <input
                        type="text"
                        placeholder="Duration (e.g. 12 mos)"
                        value={per.duration || ''}
                        onChange={(e) => {
                          const updated = [...(profile.per_experience || [])];
                          updated[idx].duration = e.target.value;
                          setProfile({ ...profile, per_experience: updated });
                        }}
                        className="px-3 py-2 rounded-xl border border-slate-200 text-xs bg-white"
                      />
                    </div>

                    <div>
                      <label className="block text-[11px] font-semibold text-slate-600 mb-1">
                        Performance Objectives & Practical Competencies Achieved
                      </label>
                      <textarea
                        rows={2}
                        value={(per.responsibilities || []).join('\n')}
                        onChange={(e) => {
                          const updated = [...(profile.per_experience || [])];
                          updated[idx].responsibilities = e.target.value
                            .split('\n')
                            .filter((s) => s.trim().length > 0);
                          setProfile({ ...profile, per_experience: updated });
                        }}
                        placeholder="Achieved Performance Objectives: SA100 preparation, UK Corporation Tax compliance, Bank reconciliation..."
                        className="w-full p-2.5 rounded-xl border border-slate-200 text-xs bg-white"
                      />
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 4: PROJECTS */}
      {activeTab === 'projects' && (
        <div className="bg-white rounded-3xl p-6 sm:p-8 border border-slate-200/80 shadow-sm space-y-6">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-bold text-slate-900">Academic & Personal Projects</h3>
              <p className="text-xs text-slate-500">Crucial for student/fresher matching and demonstrating real technical capabilities.</p>
            </div>
            <button
              onClick={() => {
                const projList = profile.projects || [];
                setProfile({
                  ...profile,
                  projects: [
                    ...projList,
                    {
                      name: '',
                      description: '',
                      technologies: [],
                      provenance: 'USER_CONFIRMED',
                    },
                  ],
                });
              }}
              className="px-3 py-1.5 rounded-xl bg-brand-50 text-brand-700 font-semibold text-xs border border-brand-200 flex items-center gap-1"
            >
              <Plus size={14} />
              <span>Add Project</span>
            </button>
          </div>

          {(profile.projects || []).length === 0 ? (
            <div className="text-center py-12 px-6 rounded-2xl bg-slate-50 border border-dashed border-slate-200">
              <FolderGit2 size={32} className="mx-auto mb-2 text-slate-300" />
              <h4 className="text-sm font-bold text-slate-800">No Projects Added Yet</h4>
              <p className="text-xs text-slate-500 mt-1 max-w-sm mx-auto">
                Add key engineering, research, or academic projects to significantly boost your match scores for technical positions.
              </p>
            </div>
          ) : (
            <div className="space-y-4">
              {profile.projects?.map((proj, idx) => (
                <div
                  key={idx}
                  className="p-4 rounded-2xl bg-slate-50 border border-slate-200/80 space-y-3"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-slate-800">Project #{idx + 1}</span>
                    <button
                      onClick={() => {
                        const updated = [...(profile.projects || [])];
                        updated.splice(idx, 1);
                        setProfile({ ...profile, projects: updated });
                      }}
                      className="text-rose-600 hover:text-rose-700"
                    >
                      <Trash2 size={15} />
                    </button>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <input
                      type="text"
                      placeholder="Project Name (e.g. Medical Chatbot)"
                      value={proj.name || proj.title || ''}
                      onChange={(e) => {
                        const updated = [...(profile.projects || [])];
                        updated[idx].name = e.target.value;
                        updated[idx].title = e.target.value;
                        setProfile({ ...profile, projects: updated });
                      }}
                      className="px-3 py-2 rounded-xl border border-slate-200 text-xs bg-white"
                    />
                    <input
                      type="text"
                      placeholder="Technologies (comma separated, e.g. Python, PyTorch, FastAPI)"
                      value={(proj.technologies || []).join(', ')}
                      onChange={(e) => {
                        const updated = [...(profile.projects || [])];
                        updated[idx].technologies = e.target.value
                          .split(',')
                          .map((t) => t.trim())
                          .filter((t) => t.length > 0);
                        setProfile({ ...profile, projects: updated });
                      }}
                      className="px-3 py-2 rounded-xl border border-slate-200 text-xs bg-white"
                    />
                  </div>

                  <div>
                    <label className="block text-[11px] font-semibold text-slate-600 mb-1">
                      Project Description & Deliverables
                    </label>
                    <textarea
                      rows={2}
                      value={proj.description || ''}
                      onChange={(e) => {
                        const updated = [...(profile.projects || [])];
                        updated[idx].description = e.target.value;
                        setProfile({ ...profile, projects: updated });
                      }}
                      placeholder="Implemented NLP symptom classification pipeline resulting in 92% diagnostic accuracy..."
                      className="w-full p-2.5 rounded-xl border border-slate-200 text-xs bg-white"
                    />
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* TAB 5: SKILLS & QUALIFICATIONS */}
      {activeTab === 'skills' && (
        <div className="bg-white rounded-3xl p-6 sm:p-8 border border-slate-200/80 shadow-sm space-y-8">
          {/* Domain & Technical Skills */}
          <div>
            <div className="flex items-center gap-2 mb-1">
              <Code2 size={16} className="text-brand-600" />
              <h3 className="text-sm font-bold text-slate-900">Domain Competencies & Technical Skills</h3>
            </div>
            <p className="text-xs text-slate-500 mb-3">
              Core professional capabilities separated by commas (e.g. UK Taxation, SA100 Self Assessment, Financial Reporting, Python, Docker).
            </p>

            <textarea
              rows={3}
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
              placeholder="UK Taxation, SA100 Self Assessment, Financial Reporting, Audit, Python, SQL"
              className="w-full p-3.5 rounded-xl border border-slate-200 text-xs focus:ring-2 focus:ring-brand-500 focus:outline-none"
            />
          </div>

          {/* Professional Qualifications & Statutory Certifications */}
          <div className="pt-6 border-t border-slate-100">
            <div className="flex items-center justify-between mb-3">
              <div>
                <div className="flex items-center gap-2">
                  <Award size={16} className="text-purple-600" />
                  <h3 className="text-sm font-bold text-slate-900">Professional Qualifications & Memberships</h3>
                </div>
                <p className="text-xs text-slate-500 mt-0.5">
                  Statutory professional bodies, credentials, and memberships (e.g. ACCA Member, CPA, CFA, Bar Council).
                </p>
              </div>
              <button
                type="button"
                onClick={() => {
                  const current = profile.professional_qualifications || profile.certifications || [];
                  const updated = [
                    ...current,
                    {
                      name: '',
                      issuer: 'ACCA (Association of Chartered Certified Accountants)',
                      membership: 'Full Member',
                      provenance: 'USER_CONFIRMED',
                    },
                  ];
                  setProfile({
                    ...profile,
                    professional_qualifications: updated,
                    certifications: updated,
                  });
                }}
                className="px-3 py-1.5 rounded-xl bg-purple-50 text-purple-700 font-semibold text-xs border border-purple-200 flex items-center gap-1 hover:bg-purple-100"
              >
                <Plus size={14} />
                <span>Add Credential</span>
              </button>
            </div>

            {((profile.professional_qualifications || profile.certifications || []).length === 0) ? (
              <div className="p-4 rounded-2xl bg-slate-50 border border-slate-200/70 text-slate-500 text-xs flex items-center gap-2">
                <Award size={16} className="text-slate-400 shrink-0" />
                <span>No professional qualifications or certifications recorded. Click Add Credential to record verified credentials.</span>
              </div>
            ) : (
              <div className="space-y-3">
                {(profile.professional_qualifications || profile.certifications || []).map((qual, idx) => (
                  <div key={idx} className="p-3.5 rounded-2xl bg-purple-50/30 border border-purple-200/60 flex items-center justify-between gap-3">
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 flex-1">
                      <input
                        type="text"
                        placeholder="Credential / Title (e.g. ACCA Member)"
                        value={qual.name}
                        onChange={(e) => {
                          const updated = [...(profile.professional_qualifications || profile.certifications || [])];
                          updated[idx] = { ...updated[idx], name: e.target.value };
                          setProfile({
                            ...profile,
                            professional_qualifications: updated,
                            certifications: updated,
                          });
                        }}
                        className="px-3 py-2 rounded-xl border border-slate-200 text-xs bg-white font-medium"
                      />
                      <input
                        type="text"
                        placeholder="Issuing Authority (e.g. ACCA)"
                        value={qual.issuer || ''}
                        onChange={(e) => {
                          const updated = [...(profile.professional_qualifications || profile.certifications || [])];
                          updated[idx] = { ...updated[idx], issuer: e.target.value };
                          setProfile({
                            ...profile,
                            professional_qualifications: updated,
                            certifications: updated,
                          });
                        }}
                        className="px-3 py-2 rounded-xl border border-slate-200 text-xs bg-white"
                      />
                      <input
                        type="text"
                        placeholder="Membership Status (e.g. Member / Affiliate)"
                        value={qual.membership || ''}
                        onChange={(e) => {
                          const updated = [...(profile.professional_qualifications || profile.certifications || [])];
                          updated[idx] = { ...updated[idx], membership: e.target.value };
                          setProfile({
                            ...profile,
                            professional_qualifications: updated,
                            certifications: updated,
                          });
                        }}
                        className="px-3 py-2 rounded-xl border border-slate-200 text-xs bg-white"
                      />
                    </div>
                    <button
                      type="button"
                      onClick={() => {
                        const updated = [...(profile.professional_qualifications || profile.certifications || [])];
                        updated.splice(idx, 1);
                        setProfile({
                          ...profile,
                          professional_qualifications: updated,
                          certifications: updated,
                        });
                      }}
                      className="text-rose-600 hover:text-rose-700 p-1"
                    >
                      <Trash2 size={15} />
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Software Tools & Enterprise Platforms */}
          <div className="pt-6 border-t border-slate-100">
            <div className="flex items-center gap-2 mb-1">
              <Wrench size={16} className="text-emerald-600" />
              <h3 className="text-sm font-bold text-slate-900">Software Tools & Platforms</h3>
            </div>
            <p className="text-xs text-slate-500 mb-3">
              Industry applications and software suites separated by commas (e.g. Digita, Xero, ApprovalMax, FYI, Coreplan, Microsoft Office Suite).
            </p>

            <textarea
              rows={2}
              value={(profile.tools_and_software || []).join(', ')}
              onChange={(e) => {
                const tools = e.target.value
                  .split(',')
                  .map((s) => s.trim())
                  .filter((s) => s.length > 0);
                setProfile({ ...profile, tools_and_software: tools });
              }}
              placeholder="Digita, Xero, ApprovalMax, FYI, Coreplan, Microsoft Office Suite"
              className="w-full p-3 rounded-xl border border-slate-200 text-xs focus:ring-2 focus:ring-brand-500 focus:outline-none"
            />
          </div>

          {/* Languages */}
          <div className="pt-6 border-t border-slate-100">
            <div className="flex items-center gap-2 mb-1">
              <Languages size={16} className="text-blue-600" />
              <h3 className="text-sm font-bold text-slate-900">Languages</h3>
            </div>
            <p className="text-xs text-slate-500 mb-3">
              Spoken and business languages separated by commas (e.g. English, Hindi, Gujarati).
            </p>

            <input
              type="text"
              value={(profile.languages || []).join(', ')}
              onChange={(e) => {
                const langs = e.target.value
                  .split(',')
                  .map((s) => s.trim())
                  .filter((s) => s.length > 0);
                setProfile({ ...profile, languages: langs });
              }}
              placeholder="English, Hindi, Gujarati"
              className="w-full p-3 rounded-xl border border-slate-200 text-xs focus:ring-2 focus:ring-brand-500 focus:outline-none"
            />
          </div>
        </div>
      )}

      {/* TAB 6: CAREER PREFERENCES */}
      {activeTab === 'preferences' && (
        <div className="bg-white rounded-3xl p-6 sm:p-8 border border-slate-200/80 shadow-sm space-y-6">
          <div>
            <h3 className="text-sm font-bold text-slate-900 mb-1">Career & Discovery Preferences</h3>
            <p className="text-xs text-slate-500 mb-4">
              Configure target job roles and locations used by the automated discovery scraper.
            </p>
          </div>

          {/* Suggested Roles from Resume */}
          {suggestedRoles.length > 0 && (
            <div className="p-4 rounded-2xl bg-brand-50/50 border border-brand-100 space-y-3">
              <div className="flex items-center gap-2">
                <Compass size={16} className="text-brand-600" />
                <h4 className="text-xs font-bold text-brand-900">Suggested Roles (Inferred from your Resume)</h4>
              </div>
              <p className="text-[11px] text-slate-600">
                Click any suggested role to add it to your active target search roles:
              </p>
              <div className="flex flex-wrap gap-2">
                {suggestedRoles.map((role, idx) => {
                  const isAdded = targetRoles.includes(role.role_title);
                  return (
                    <button
                      key={idx}
                      type="button"
                      onClick={() => handleAddTargetRole(role.role_title)}
                      className={`px-3 py-1.5 rounded-xl text-xs font-semibold flex items-center gap-1.5 transition-all ${
                        isAdded
                          ? 'bg-brand-600 text-white shadow-2xs'
                          : 'bg-white border border-brand-200 text-brand-800 hover:bg-brand-100/60'
                      }`}
                    >
                      <span>{role.role_title}</span>
                      <span className="text-[10px] opacity-75">({Math.round(role.confidence * 100)}%)</span>
                      {isAdded ? <Check size={12} /> : <Plus size={12} />}
                    </button>
                  );
                })}
              </div>
            </div>
          )}

          {/* Active Target Roles */}
          <div className="space-y-3">
            <label className="block text-xs font-semibold text-slate-800">
              Active Target Roles ({targetRoles.length})
            </label>
            <div className="flex flex-wrap gap-2">
              {targetRoles.map((role, idx) => (
                <span
                  key={idx}
                  className="px-3 py-1.5 rounded-xl text-xs font-semibold bg-slate-100 text-slate-800 border border-slate-200 flex items-center gap-1.5"
                >
                  <span>{role}</span>
                  <button
                    type="button"
                    onClick={() => handleRemoveTargetRole(role)}
                    className="text-slate-400 hover:text-rose-600"
                  >
                    <X size={13} />
                  </button>
                </span>
              ))}
            </div>

            <div className="flex gap-2 max-w-md">
              <input
                type="text"
                value={newRoleInput}
                onChange={(e) => setNewRoleInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    e.preventDefault();
                    handleAddTargetRole(newRoleInput);
                  }
                }}
                placeholder="Add custom target role (e.g. AI Engineer)..."
                className="flex-1 px-3.5 py-2 rounded-xl border border-slate-200 text-xs focus:ring-2 focus:ring-brand-500 focus:outline-none"
              />
              <button
                type="button"
                onClick={() => handleAddTargetRole(newRoleInput)}
                disabled={!newRoleInput.trim()}
                className="px-4 py-2 rounded-xl bg-brand-600 hover:bg-brand-700 text-white font-semibold text-xs disabled:opacity-50"
              >
                Add Role
              </button>
            </div>
          </div>

          {/* Target Locations */}
          <div className="space-y-3 pt-3 border-t border-slate-100">
            <label className="block text-xs font-semibold text-slate-800">
              Target Locations ({targetLocations.length})
            </label>
            <div className="flex flex-wrap gap-2">
              {targetLocations.map((loc, idx) => (
                <span
                  key={idx}
                  className="px-3 py-1.5 rounded-xl text-xs font-semibold bg-slate-100 text-slate-800 border border-slate-200 flex items-center gap-1.5"
                >
                  <span>{loc}</span>
                  <button
                    type="button"
                    onClick={() => handleRemoveLocation(loc)}
                    className="text-slate-400 hover:text-rose-600"
                  >
                    <X size={13} />
                  </button>
                </span>
              ))}
            </div>

            <div className="flex gap-2 max-w-md">
              <input
                type="text"
                value={newLocInput}
                onChange={(e) => setNewLocInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    e.preventDefault();
                    handleAddLocation(newLocInput);
                  }
                }}
                placeholder="Add location (e.g. Pune, Bengaluru, Hybrid)..."
                className="flex-1 px-3.5 py-2 rounded-xl border border-slate-200 text-xs focus:ring-2 focus:ring-brand-500 focus:outline-none"
              />
              <button
                type="button"
                onClick={() => handleAddLocation(newLocInput)}
                disabled={!newLocInput.trim()}
                className="px-4 py-2 rounded-xl bg-brand-600 hover:bg-brand-700 text-white font-semibold text-xs disabled:opacity-50"
              >
                Add Location
              </button>
            </div>
          </div>

          {/* Auto-discovery setting */}
          <div className="pt-3 border-t border-slate-100 flex items-center justify-between">
            <div>
              <h4 className="text-xs font-bold text-slate-900">Background Automatic Discovery</h4>
              <p className="text-[11px] text-slate-500">
                Periodically scrape and evaluate job postings matching your resume qualifications.
              </p>
            </div>
            <input
              type="checkbox"
              checked={Boolean(currentPrefs.auto_discover_enabled)}
              onChange={(e) =>
                updatePreferences({
                  ...currentPrefs,
                  auto_discover_enabled: e.target.checked,
                })
              }
              className="w-4 h-4 text-brand-600 rounded border-slate-300 focus:ring-brand-500"
            />
          </div>
        </div>
      )}

      {/* TAB 7: RESUME LIBRARY */}
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
                          <span className="text-xs font-bold text-slate-800">
                            {res.original_filename}
                          </span>
                          {res.is_primary && (
                            <span className="px-2 py-0.5 rounded-full text-[10px] font-semibold bg-emerald-100 text-emerald-800 flex items-center gap-1">
                              <Star size={10} className="fill-emerald-800" />
                              <span>Primary</span>
                            </span>
                          )}
                        </div>
                        <p className="text-[11px] text-slate-400 mt-0.5">
                          {res.file_format.toUpperCase()} &middot; {(res.file_size_bytes / 1024).toFixed(1)} KB &middot; SHA-256 verified
                        </p>
                      </div>
                    </div>

                    <div className="flex items-center gap-2 self-end sm:self-center">
                      {!res.is_primary && (
                        <button
                          onClick={() => handleSetPrimary(res.id)}
                          className="px-3 py-1.5 rounded-xl border border-slate-200 hover:bg-slate-50 text-slate-700 text-xs font-medium flex items-center gap-1"
                        >
                          <Star size={13} />
                          <span>Set Primary</span>
                        </button>
                      )}
                      <button
                        onClick={() => handleSyncResume(res.id)}
                        title="Re-extract verified candidate profile"
                        className="px-3 py-1.5 rounded-xl bg-brand-50 hover:bg-brand-100 text-brand-700 text-xs font-medium flex items-center gap-1"
                      >
                        <RefreshCw size={13} />
                        <span>Re-Sync</span>
                      </button>
                      <button
                        onClick={() => handleDeleteResume(res.id)}
                        className="p-1.5 rounded-xl text-slate-400 hover:text-rose-600 hover:bg-rose-50"
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
