import React from 'react';

export const JobCardSkeleton: React.FC = () => {
  return (
    <div
      data-testid="job-card-skeleton"
      className="bg-white rounded-3xl p-5 border border-slate-200/80 shadow-sm flex flex-col justify-between animate-pulse transition-all"
    >
      <div>
        {/* Card Top: Match Score & Bookmark Placeholders */}
        <div className="flex items-center justify-between gap-2 mb-3.5">
          <div className="flex items-center gap-2">
            <div className="h-6 w-24 bg-slate-200 rounded-full" />
            <div className="h-6 w-20 bg-slate-100 rounded-full" />
          </div>
          <div className="h-8 w-8 bg-slate-100 rounded-xl" />
        </div>

        {/* Job Title & Company Placeholders */}
        <div className="space-y-2 mb-3">
          <div className="h-5 bg-slate-200 rounded-lg w-4/5" />
          <div className="h-3.5 bg-slate-100 rounded-md w-2/5" />
        </div>

        {/* Metadata Chips Placeholders */}
        <div className="flex flex-wrap gap-2 mb-4">
          <div className="h-5 w-20 bg-slate-100 rounded-md" />
          <div className="h-5 w-16 bg-slate-100 rounded-md" />
          <div className="h-5 w-24 bg-slate-100 rounded-md" />
        </div>

        {/* Matching Qualifications Placeholder */}
        <div className="space-y-1.5 mt-3">
          <div className="h-2.5 w-28 bg-slate-100 rounded" />
          <div className="flex flex-wrap gap-1.5">
            <div className="h-5 w-20 bg-slate-100 rounded-md" />
            <div className="h-5 w-24 bg-slate-100 rounded-md" />
            <div className="h-5 w-16 bg-slate-100 rounded-md" />
          </div>
        </div>
      </div>

      {/* Card Bottom Buttons Placeholders */}
      <div className="mt-5 pt-3 border-t border-slate-100 flex items-center gap-2">
        <div className="h-8 bg-slate-100 rounded-xl flex-1" />
        <div className="h-8 bg-slate-200 rounded-xl flex-1" />
      </div>
    </div>
  );
};

interface JobCardSkeletonGridProps {
  count?: number;
}

export const JobCardSkeletonGrid: React.FC<JobCardSkeletonGridProps> = ({ count = 6 }) => {
  return (
    <div
      data-testid="job-card-skeleton-grid"
      className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5"
    >
      {Array.from({ length: count }).map((_, idx) => (
        <JobCardSkeleton key={idx} />
      ))}
    </div>
  );
};
