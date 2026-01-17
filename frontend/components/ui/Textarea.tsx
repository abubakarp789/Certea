import React from 'react';
import { cn } from '@/lib/utils';

interface TextareaProps extends React.TextareaHTMLAttributes<HTMLTextAreaElement> {
  label?: string;
  error?: string;
}

export default function Textarea({
  className,
  label,
  error,
  id,
  rows = 4,
  ...props
}: TextareaProps) {
  return (
    <div className="space-y-3">
      {label && (
        <label htmlFor={id} className="block text-sm font-bold text-text-muted uppercase tracking-wider">
          {label}
        </label>
      )}
      <textarea
        id={id}
        rows={rows}
        className={cn(
          'w-full px-4 py-3 rounded-xl bg-black/40 border border-glass-border text-text-primary placeholder:text-text-secondary focus:outline-none focus:border-accent focus:ring-2 focus:ring-accent/20 transition-all resize-none font-mono',
          error && 'border-error focus:border-error focus:ring-error/20',
          className
        )}
        {...props}
      />
      {error && (
        <p className="text-sm text-error">{error}</p>
      )}
    </div>
  );
}
