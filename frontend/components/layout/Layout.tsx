'use client';

import { ReactNode } from 'react';
import Sidebar from './Sidebar';
import { ToastContainer } from '@/components/ui/Toast';
import { useToast } from '@/hooks/useToast';

interface LayoutProps {
  children: ReactNode;
}

export default function Layout({ children }: LayoutProps) {
  const { toasts, removeToast } = useToast();

  return (
    <div className="flex min-h-screen bg-gradient-mesh">
      <Sidebar />
      
      <main className="flex-1 overflow-y-auto p-4 lg:p-8 lg:pl-0">
        <div className="max-w-6xl mx-auto animate-fadeIn">
          {children}
        </div>
      </main>

      <ToastContainer toasts={toasts} onClose={removeToast} />
    </div>
  );
}
