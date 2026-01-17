import React from 'react';
import { cn } from '@/lib/utils';

interface SelectProps extends React.SelectHTMLAttributes<HTMLSelectElement> {
  label?: string;
  options: Array<{ value: string; label: string }>;
}

export default function Select({
  className,
  label,
  options,
  ...props
}: SelectProps) {
  return (
    <div className="space-y-3">
      {label && (
        <label className="block text-sm font-bold text-text-muted uppercase tracking-wider">
          {label}
        </label>
      )}
      <select
        className={cn(
          'w-full px-4 py-3 rounded-xl bg-black/40 border border-glass-border text-text-primary focus:outline-none focus:border-accent focus:ring-2 focus:ring-accent/20 transition-all cursor-pointer',
          className
        )}
        {...props}
      >
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
    </div>
  );
}
