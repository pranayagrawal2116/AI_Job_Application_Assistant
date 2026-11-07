import React from 'react';
import { Loader2 } from 'lucide-react';
import { cn } from '@/lib/utils';

export const LoadingSpinner: React.FC<{ className?: string; size?: number }> = ({ className, size = 24 }) => {
  return (
    <div className="flex items-center justify-center p-4">
      <Loader2 size={size} className={cn('animate-spin text-brand-600', className)} />
    </div>
  );
};
