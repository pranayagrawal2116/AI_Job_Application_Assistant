import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '@/features/auth/AuthContext';
import { api } from '@/lib/api';
import { Sparkles, CheckCircle2, ArrowRight, ArrowLeft, FileText, AlertCircle } from 'lucide-react';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { FileDropzone } from '@/components/common/FileDropzone';

export const OnboardingWizard: React.FC = () => {
  const { user } = useAuth();
  const navigate = useNavigate();

  const [step, setStep] = useState(1);
  const [file, setFile] = useState<File | null>(null);
  const [isUploading, setIsUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [uploadedResume, setUploadedResume] = useState<any>(null);

  const handleUpload = async () => {
    if (!file) return;
    setIsUploading(true);
    setError(null);

    try {
      const res = await api.uploadResume(file);
      setUploadedResume(res);
      // Automatically sync profile with parsed resume
      await api.syncProfileWithResume(res.id);
      setStep(3);
    } catch (err: any) {
      setError(err.message || 'Failed to upload and parse resume.');
    } finally {
      setIsUploading(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-50 flex items-center justify-center p-6">
      <div className="w-full max-w-2xl bg-white rounded-3xl shadow-xl border border-slate-100 overflow-hidden">
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

          {/* STEP 3: CONFIRMATION & COMPLETION */}
          {step === 3 && (
            <div className="text-center py-6">
              <div className="w-16 h-16 rounded-3xl bg-emerald-50 text-emerald-600 flex items-center justify-center mx-auto mb-4">
                <CheckCircle2 size={36} />
              </div>
              <h3 className="text-2xl font-bold text-slate-900">You're ready to start applying!</h3>
              <p className="mt-2 text-slate-500 text-sm max-w-md mx-auto leading-relaxed">
                Your resume was parsed successfully and your candidate profile has been synchronized.
                JobFlow will now rank opportunities based on your verified qualifications.
              </p>

              {uploadedResume && (
                <div className="mt-6 p-4 rounded-2xl bg-slate-50 border border-slate-200/80 max-w-md mx-auto flex items-center gap-3 text-left">
                  <FileText size={20} className="text-brand-600 shrink-0" />
                  <div className="truncate">
                    <p className="text-xs font-bold text-slate-800 truncate">
                      {uploadedResume.original_filename}
                    </p>
                    <p className="text-[11px] text-slate-400">
                      Primary active resume &middot; SHA-256 verified
                    </p>
                  </div>
                </div>
              )}

              <div className="mt-8 flex justify-center">
                <button
                  onClick={() => navigate('/dashboard')}
                  className="px-8 py-3 rounded-xl bg-brand-600 hover:bg-brand-700 text-white font-semibold text-sm shadow-md shadow-brand-500/20 flex items-center gap-2 transition-all"
                >
                  <span>Go to My Dashboard</span>
                  <ArrowRight size={16} />
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
