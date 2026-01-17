import React from 'react';
import { cn } from '@/lib/utils';

interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  error?: string;
}

export default function Input({
  className,
  label,
  error,
  id,
  ...props
}: InputProps) {
  return (
    <div className="space-y-3">
      {label && (
        <label htmlFor={id} className="block text-sm font-bold text-text-muted uppercase tracking-wider">
          {label}
        </label>
      )}
      <input
        id={id}
        className={cn(
          'w-full px-4 py-3 rounded-xl bg-black/40 border border-glass-border text-text-primary placeholder:text-text-secondary focus:outline-none focus:border-accent focus:ring-2 focus:ring-accent/20 transition-all',
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
