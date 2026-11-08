import React, { useRef, useState } from 'react';
import { UploadCloud, FileText, X } from 'lucide-react';
import { LoadingSpinner } from './LoadingSpinner';

export interface FileDropzoneProps {
  id?: string;
  onFileSelect: (file: File) => void;
  onError?: (errorMsg: string) => void;
  accept?: string;
  maxSizeBytes?: number;
  disabled?: boolean;
  isLoading?: boolean;
  loadingText?: string;
  title?: string;
  subtitle?: string;
  selectedFile?: File | null;
  onClearFile?: () => void;
  className?: string;
}

export const FileDropzone: React.FC<FileDropzoneProps> = ({
  id = 'file-upload-input',
  onFileSelect,
  onError,
  accept = '.pdf,.docx,.doc,application/pdf,application/vnd.openxmlformats-officedocument.wordprocessingml.document,application/msword',
  maxSizeBytes = 10 * 1024 * 1024, // 10 MB
  disabled = false,
  isLoading = false,
  loadingText = 'Processing file...',
  title = 'Click to browse or drag and drop',
  subtitle = 'PDF or DOCX documents up to 10 MB',
  selectedFile = null,
  onClearFile,
  className = '',
}) => {
  const [isDragging, setIsDragging] = useState(false);
  const dragCounter = useRef(0);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const validateAndSelectFile = (file: File) => {
    if (!file) return;

    // Validate format
    const name = file.name.toLowerCase();
    const isPdf = name.endsWith('.pdf') || file.type === 'application/pdf';
    const isDocx =
      name.endsWith('.docx') ||
      name.endsWith('.doc') ||
      file.type.includes('word') ||
      file.type === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' ||
      file.type === 'application/msword';

    if (!isPdf && !isDocx) {
      const msg = 'Only PDF or DOCX documents are supported.';
      if (onError) onError(msg);
      return;
    }

    // Validate size
    if (file.size > maxSizeBytes) {
      const maxMb = (maxSizeBytes / (1024 * 1024)).toFixed(0);
      const msg = `File size exceeds ${maxMb} MB limit. (Selected file: ${(file.size / (1024 * 1024)).toFixed(2)} MB)`;
      if (onError) onError(msg);
      return;
    }

    onFileSelect(file);
  };

  const handleDragEnter = (e: React.DragEvent<HTMLElement>) => {
    e.preventDefault();
    e.stopPropagation();
    dragCounter.current += 1;
    if (e.dataTransfer.items && e.dataTransfer.items.length > 0) {
      setIsDragging(true);
    }
  };

  const handleDragOver = (e: React.DragEvent<HTMLElement>) => {
    e.preventDefault();
    e.stopPropagation();
    e.dataTransfer.dropEffect = 'copy';
    if (!isDragging) {
      setIsDragging(true);
    }
  };

  const handleDragLeave = (e: React.DragEvent<HTMLElement>) => {
    e.preventDefault();
    e.stopPropagation();
    dragCounter.current -= 1;
    if (dragCounter.current <= 0) {
      dragCounter.current = 0;
      setIsDragging(false);
    }
  };

  const handleDrop = (e: React.DragEvent<HTMLElement>) => {
    e.preventDefault();
    e.stopPropagation();
    dragCounter.current = 0;
    setIsDragging(false);

    if (disabled || isLoading) return;

    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      validateAndSelectFile(e.dataTransfer.files[0]);
    }
  };

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      validateAndSelectFile(e.target.files[0]);
    }
    // Reset value so selecting the same file again triggers onChange
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const handleClick = (e: React.MouseEvent) => {
    // If click originated from clear button, don't reopen file dialog
    if ((e.target as HTMLElement).closest('[data-clear-btn]')) {
      return;
    }
    if (!disabled && !isLoading && fileInputRef.current) {
      fileInputRef.current.click();
    }
  };

  return (
    <div
      onClick={selectedFile ? handleClick : undefined}
      onDragEnter={handleDragEnter}
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
      className={`relative border-2 border-dashed rounded-2xl p-6 sm:p-8 text-center transition-all cursor-pointer select-none overflow-hidden ${
        disabled || isLoading
          ? 'opacity-60 cursor-not-allowed bg-slate-50 border-slate-200'
          : isDragging
          ? 'border-brand-500 bg-brand-50/80 ring-4 ring-brand-500/20 shadow-lg scale-[1.01]'
          : 'border-slate-200 hover:border-brand-400 bg-slate-50/50 hover:bg-slate-50'
      } ${className}`}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          fileInputRef.current?.click();
        }
      }}
      aria-label="Upload document dropzone"
    >
      {/* Native file input overlay: directly receives click & drop gestures across the entire dropzone */}
      <input
        ref={fileInputRef}
        type="file"
        id={id}
        name={id}
        accept={accept}
        disabled={disabled || isLoading}
        onChange={handleInputChange}
        onDragEnter={handleDragEnter}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        className={
          selectedFile || isLoading || disabled
            ? 'hidden'
            : 'absolute inset-0 w-full h-full opacity-0 cursor-pointer z-10'
        }
        tabIndex={selectedFile ? -1 : 0}
        aria-label={title}
      />

      {isLoading ? (
        <div className="flex flex-col items-center justify-center py-2 pointer-events-none">
          <LoadingSpinner size={32} className="text-brand-600 mb-3" />
          <p className="text-xs sm:text-sm font-semibold text-slate-800">{loadingText}</p>
          <p className="text-[11px] text-slate-400 mt-1">Please wait while we parse your document</p>
        </div>
      ) : selectedFile ? (
        <div className="flex items-center justify-between p-3 sm:p-4 rounded-xl bg-white border border-slate-200 shadow-sm max-w-md mx-auto text-left">
          <div className="flex items-center gap-3 min-w-0 pointer-events-none">
            <div className="w-10 h-10 rounded-xl bg-brand-50 border border-brand-100 flex items-center justify-center text-brand-600 shrink-0">
              <FileText size={20} />
            </div>
            <div className="min-w-0">
              <p className="text-xs sm:text-sm font-bold text-slate-900 truncate">
                {selectedFile.name}
              </p>
              <p className="text-[11px] text-slate-400 mt-0.5">
                {(selectedFile.size / (1024 * 1024)).toFixed(2)} MB &middot; Ready
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 shrink-0 ml-3">
            <span className="text-[10px] font-semibold text-brand-600 bg-brand-50 px-2 py-0.5 rounded-full border border-brand-100 pointer-events-none">
              Change
            </span>
            {onClearFile && (
              <button
                type="button"
                data-clear-btn="true"
                onClick={(e) => {
                  e.stopPropagation();
                  onClearFile();
                  if (fileInputRef.current) fileInputRef.current.value = '';
                }}
                className="relative z-20 p-1 rounded-lg text-slate-400 hover:text-rose-600 hover:bg-rose-50 transition-colors pointer-events-auto"
                title="Remove file"
              >
                <X size={16} />
              </button>
            )}
          </div>
        </div>
      ) : (
        <div className="flex flex-col items-center justify-center py-2 pointer-events-none">
          <div
            className={`w-14 h-14 rounded-2xl flex items-center justify-center mb-3 transition-transform ${
              isDragging
                ? 'bg-brand-600 text-white scale-110 shadow-md shadow-brand-500/30'
                : 'bg-white shadow-sm border border-slate-200 text-brand-600'
            }`}
          >
            <UploadCloud size={28} />
          </div>

          <p className="text-xs sm:text-sm font-bold text-slate-800">
            {isDragging ? 'Drop your document here now' : title}
          </p>
          <p className="text-[11px] text-slate-400 mt-1">{subtitle}</p>
        </div>
      )}
    </div>
  );
};
