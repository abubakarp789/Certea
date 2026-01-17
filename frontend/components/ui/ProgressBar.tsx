'use client';

import React from 'react';
import { motion } from 'framer-motion';
import { cn } from '@/lib/utils';

interface ProgressBarProps {
  value: number;
  max?: number;
  showLabel?: boolean;
  className?: string;
}

export default function ProgressBar({
  value,
  max = 100,
  showLabel = false,
  className
}: ProgressBarProps) {
  const percentage = Math.min((value / max) * 100, 100);

  return (
    <div className={cn('w-full', className)}>
      {showLabel && (
        <div className="flex justify-between text-sm mb-2 text-text-secondary">
          <span>Progress</span>
          <span>{percentage.toFixed(0)}%</span>
        </div>
      )}
      <div className="w-full h-2 bg-black/40 rounded-full overflow-hidden">
        <motion.div
          initial={{ width: 0 }}
          animate={{ width: `${percentage}%` }}
          transition={{ duration: 0.5, ease: 'easeOut' }}
          className="h-full bg-accent rounded-full"
        />
      </div>
    </div>
  );
}
