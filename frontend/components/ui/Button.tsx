import React from 'react';
import { Loader2 } from 'lucide-react';
import { cn } from '@/lib/utils';

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary';
  size?: 'sm' | 'md' | 'lg';
  loading?: boolean;
  icon?: React.ReactNode;
}

export default function Button({
  className,
  children,
  variant = 'primary',
  size = 'md',
  loading = false,
  icon,
  disabled,
  ...props
}: ButtonProps) {
  const sizes = {
    sm: 'px-3 py-2 text-sm',
    md: 'px-6 py-4 text-base',
    lg: 'px-8 py-5 text-lg',
  };

  const variants = {
    primary: 'bg-accent text-background hover:bg-accent/90 focus:ring-accent',
    secondary: 'bg-white/10 text-white hover:bg-white/20 focus:ring-white',
  };

  return (
    <button
      className={cn(
        'font-bold rounded-xl transition-all',
        'focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-background',
        'disabled:opacity-50 disabled:cursor-not-allowed',
        'hover:shadow-lg hover:shadow-accent/20',
        sizes[size],
        variants[variant],
        className
      )}
      disabled={disabled || loading}
      {...props}
    >
      {loading ? (
        <span className="flex items-center justify-center gap-2">
          <Loader2 className="w-5 h-5 animate-spin" />
          {children}
        </span>
      ) : (
        <span className="flex items-center justify-center gap-2">
          {icon && icon}
          {children}
        </span>
      )}
    </button>
  );
}
