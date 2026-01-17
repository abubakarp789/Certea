'use client';

import Link from 'next/link';
import Image from 'next/image';
import { usePathname } from 'next/navigation';
import { ShieldCheck, LayoutDashboard, Key, PenTool, Search, FileKey2, FileCheck2, Landmark, Activity, Menu, X } from 'lucide-react';
import { useState } from 'react';

const navigation = [
  { name: 'Dashboard', href: '/', icon: LayoutDashboard },
  { name: 'Key Generator', href: '/generate', icon: Key },
  { name: 'Sign Text', href: '/sign-text', icon: PenTool },
  { name: 'Verify Text', href: '/verify-text', icon: Search },
  { name: 'Sign File', href: '/sign-file', icon: FileKey2 },
  { name: 'Verify File', href: '/verify-file', icon: FileCheck2 },
  { name: 'Certificate Authority', href: '/certificate-authority', icon: Landmark },
  { name: 'Audit Logs', href: '/audit-logs', icon: Activity },
];

export default function Sidebar() {
  const pathname = usePathname();
  const [isOpen, setIsOpen] = useState(false);

  return (
    <>
      <button
        className="lg:hidden fixed top-4 left-4 z-50 p-2 rounded-lg glass"
        onClick={() => setIsOpen(true)}
      >
        <Menu className="w-6 h-6 text-accent" />
      </button>

      <aside
        className={`fixed lg:static inset-y-0 left-0 z-40 w-72 transform transition-transform duration-300 ease-in-out lg:translate-x-0 ${isOpen ? 'translate-x-0' : '-translate-x-full'
          }`}
      >
        <div className="h-full glass m-4 rounded-2xl p-6 flex flex-col">
          <div className="flex items-center justify-between mb-8">
            <Link href="/" className="relative block h-16 w-48 group">
              <div className="absolute inset-0 transition-transform group-hover:scale-105">
                <Image
                  src="/images/logo.png"
                  alt="Certea Logo"
                  fill
                  className="object-contain invert hue-rotate-180 mix-blend-screen brightness-110 opacity-90"
                  priority
                />
              </div>
            </Link>
            <button
              className="lg:hidden p-1 hover:text-accent transition-colors"
              onClick={() => setIsOpen(false)}
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          <nav className="flex-1 space-y-2">
            {navigation.map((item) => {
              const isActive = pathname === item.href;
              const Icon = item.icon;
              return (
                <Link
                  key={item.name}
                  href={item.href}
                  className={`flex items-center gap-3 px-4 py-3 rounded-xl transition-all duration-300 group ${isActive
                    ? 'bg-accent/10 text-accent border border-accent/20 shadow-lg shadow-accent/5'
                    : 'text-text-secondary hover:text-text-primary hover:bg-white/5'
                    }`}
                  onClick={() => setIsOpen(false)}
                >
                  <Icon
                    className={`w-5 h-5 transition-transform duration-300 ${isActive ? 'scale-110' : 'group-hover:scale-110'
                      }`}
                  />
                  <span className="font-medium">{item.name}</span>
                </Link>
              );
            })}
          </nav>

          <div className="mt-auto pt-6 border-t border-glass-border">
            <p className="text-xs text-text-muted text-center">
              © 2024 Certea. All rights reserved.
            </p>
          </div>
        </div>
      </aside>

      {isOpen && (
        <div
          className="fixed inset-0 bg-black/50 z-30 lg:hidden"
          onClick={() => setIsOpen(false)}
        />
      )}
    </>
  );
}
