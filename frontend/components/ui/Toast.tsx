'use client';

import { useEffect, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, CheckCircle, AlertCircle, AlertTriangle, Info } from 'lucide-react';
import { ToastType } from '@/lib/types';

interface ToastProps {
  id: string;
  message: string;
  type: ToastType;
  onClose: (id: string) => void;
}

const icons = {
  success: CheckCircle,
  error: AlertCircle,
  warning: AlertTriangle,
  info: Info,
};

const colors = {
  success: 'border-success bg-success/10 text-success',
  error: 'border-error bg-error/10 text-error',
  warning: 'border-warning bg-warning/10 text-warning',
  info: 'border-accent bg-accent/10 text-accent',
};

export default function Toast({ id, message, type, onClose }: ToastProps) {
  const Icon = icons[type];

  useEffect(() => {
    const timer = setTimeout(() => {
      onClose(id);
    }, 4000);

    return () => clearTimeout(timer);
  }, [id, onClose]);

  return (
    <motion.div
      initial={{ opacity: 0, x: 100 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: 100 }}
      className={`flex items-center gap-3 p-4 rounded-lg border ${colors[type]} glass`}
    >
      <Icon className="w-5 h-5 flex-shrink-0" />
      <span className="flex-1 font-medium">{message}</span>
      <button
        onClick={() => onClose(id)}
        className="flex-shrink-0 hover:opacity-70 transition-opacity"
      >
        <X className="w-4 h-4" />
      </button>
    </motion.div>
  );
}

interface ToastContainerProps {
  toasts: Array<{ id: string; message: string; type: ToastType }>;
  onClose: (id: string) => void;
}

export function ToastContainer({ toasts, onClose }: ToastContainerProps) {
  return (
    <div className="fixed top-4 right-4 z-50 flex flex-col gap-2">
      <AnimatePresence mode="popLayout">
        {toasts.map((toast) => (
          <Toast
            key={toast.id}
            id={toast.id}
            message={toast.message}
            type={toast.type}
            onClose={onClose}
          />
        ))}
      </AnimatePresence>
    </div>
  );
}
