import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatScore(score?: number | null): string {
  if (score === null || score === undefined) return 'Not Evaluated';
  return `${Math.round(score)}%`;
}

export function getScoreColor(score?: number | null): string {
  if (score === null || score === undefined) return 'text-slate-500 bg-slate-100 border-slate-200';
  if (score >= 85) return 'text-emerald-600 bg-emerald-50 border-emerald-200';
  if (score >= 70) return 'text-blue-600 bg-blue-50 border-blue-200';
  if (score >= 50) return 'text-amber-600 bg-amber-50 border-amber-200';
  return 'text-rose-600 bg-rose-50 border-rose-200';
}

export function getStatusBadgeColor(status: string): string {
  const s = status.toUpperCase();
  switch (s) {
    case 'DRAFT':
    case 'SAVED':
    case 'DISCOVERED':
      return 'bg-slate-100 text-slate-700 border-slate-200';
    case 'PREPARING':
    case 'UNDER REVIEW':
    case 'SHORTLISTED':
      return 'bg-blue-100 text-blue-700 border-blue-200';
    case 'READY_FOR_REVIEW':
    case 'APPLICATION PREPARED':
      return 'bg-purple-100 text-purple-700 border-purple-200';
    case 'APPROVED':
    case 'AWAITING APPROVAL':
      return 'bg-indigo-100 text-indigo-700 border-indigo-200';
    case 'SUBMITTED':
    case 'APPLIED':
    case 'IN_PROGRESS':
      return 'bg-emerald-100 text-emerald-800 border-emerald-200';
    case 'INTERVIEW':
    case 'ASSESSMENT':
      return 'bg-teal-100 text-teal-800 border-teal-200';
    case 'OFFER':
      return 'bg-green-200 text-green-900 border-green-300';
    case 'REJECTED':
      return 'bg-rose-100 text-rose-700 border-rose-200';
    case 'WITHDRAWN':
    case 'CLOSED':
      return 'bg-gray-100 text-gray-600 border-gray-200';
    default:
      return 'bg-slate-100 text-slate-700 border-slate-200';
  }
}
