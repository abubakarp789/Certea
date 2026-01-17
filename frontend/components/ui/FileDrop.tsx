'use client';

import React, { useState, useCallback } from 'react';
import { Upload, File as FileIcon, X } from 'lucide-react';
import { motion } from 'framer-motion';
import { cn } from '@/lib/utils';

interface FileDropProps {
  label: string;
  file: File | null;
  setFile: (file: File | null) => void;
  accept?: string;
  icon?: 'key' | 'file';
}

export default function FileDrop({
  label,
  file,
  setFile,
  accept = '*',
  icon = 'file',
}: FileDropProps) {
  const [isDragging, setIsDragging] = useState(false);

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    const droppedFile = e.dataTransfer.files[0];
    if (droppedFile) {
      setFile(droppedFile);
    }
  }, [setFile]);

  const handleFileUpload = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFile = e.target.files?.[0];
    if (selectedFile) {
      setFile(selectedFile);
    }
  }, [setFile]);

  const handleRemove = useCallback(() => {
    setFile(null);
  }, [setFile]);

  return (
    <div className="space-y-3">
      <label className="block text-sm font-bold text-text-muted uppercase tracking-wider">
        {label}
      </label>
      <label className="relative cursor-pointer">
        <input
          type="file"
          accept={accept}
          onChange={handleFileUpload}
          className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
        />
        <motion.div
          whileHover={{ scale: 1.01 }}
          className={cn(
            'relative flex flex-col items-center justify-center gap-3 px-4 py-8 rounded-xl border-2 border-dashed transition-all',
            isDragging && 'border-accent bg-accent/5',
            !isDragging && file ? 'border-success bg-success/10' : 'border-glass-border bg-white/5 hover:border-accent/50 hover:bg-accent/5'
          )}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
        >
          {file ? (
            <>
              <FileIcon className="w-8 h-8 text-success" />
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium text-success">
                  Selected: {file.name}
                </span>
                <button
                  type="button"
                  onClick={(e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    handleRemove();
                  }}
                  className="p-1 hover:bg-error/20 rounded-full transition-colors"
                >
                  <X className="w-4 h-4 text-error" />
                </button>
              </div>
            </>
          ) : (
            <>
              <Upload className="w-8 h-8 text-accent opacity-60" />
              <span className="text-sm font-medium text-text-secondary">
                Drop {icon === 'key' ? 'Private Key' : icon === 'file' ? 'Document/File' : 'file'} here
              </span>
            </>
          )}
        </motion.div>
      </label>
    </div>
  );
}
