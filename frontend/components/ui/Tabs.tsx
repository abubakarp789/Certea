'use client';

import React from 'react';
import { cn } from '@/lib/utils';

interface TabsProps {
  tabs: Array<{ id: string; label: string }>;
  activeTab: string;
  setActiveTab: (tab: string) => void;
}

export default function Tabs({ tabs, activeTab, setActiveTab }: TabsProps) {
  return (
    <div className="flex gap-2 bg-black/40 p-2 rounded-xl inline-flex w-full">
      {tabs.map((tab) => (
        <button
          key={tab.id}
          onClick={() => setActiveTab(tab.id)}
          className={cn(
            'flex-1 py-3 px-6 rounded-lg font-medium transition-all',
            activeTab === tab.id
              ? 'bg-accent text-background shadow-lg shadow-accent/20'
              : 'text-text-secondary hover:text-text-primary hover:bg-white/5'
          )}
        >
          {tab.label}
        </button>
      ))}
    </div>
  );
}
