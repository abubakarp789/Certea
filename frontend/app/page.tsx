'use client';

import { motion } from 'framer-motion';
import { Lock, Zap, Activity, Key, FileSignature, ShieldCheck, Landmark, LayoutDashboard, FileText, FileCheck } from 'lucide-react';
import Link from 'next/link';
import Hero from '@/components/Hero';
import Background from '@/components/Background';

export default function HomePage() {
  return (
    <main className="min-h-screen relative">
      <Background />

      {/* Hero Section */}
      <Hero />

      <div className="container mx-auto px-4 pb-20">

        {/* Quick Stats Row */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-16 -mt-10 relative z-20">
          <StatsCard
            icon={Lock}
            value="RSA-4096"
            label="Encryption Standard"
            trend="+Security"
            color="accent"
          />
          <StatsCard
            icon={Activity}
            value="99.9%"
            label="System Uptime"
            trend="Stable"
            color="success"
          />
          <StatsCard
            icon={Zap}
            value="<50ms"
            label="Signing Latency"
            trend="Fast"
            color="warning"
          />
        </div>

        {/* Main Dashboard / Features Section */}
        <div className="space-y-4 mb-8">
          <h2 className="text-3xl font-bold font-display text-white">Core Modules</h2>
          <p className="text-text-secondary">Access your cryptographic toolkit.</p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          <FeatureCard
            icon={Key}
            title="Key Management"
            description="Generate cryptographically secure RSA public and private key pairs (up to 4096 bits)."
            href="/generate"
            special
          />
          <FeatureCard
            icon={FileSignature}
            title="Sign Documents"
            description="Apply digital signatures to PDF, DOCX, or any arbitrary file to prove authorship and integrity."
            href="/sign-file"
          />
          <FeatureCard
            icon={ShieldCheck}
            title="Verify File Integrity"
            description="Check if a received file has been tampered with or modified by verifying its cryptographic signature."
            href="/verify-file"
          />
          <FeatureCard
            icon={FileText}
            title="Sign Text"
            description="Create a digital signature for text messages to ensure authenticity."
            href="/sign-text"
          />
          <FeatureCard
            icon={FileCheck}
            title="Verify Text"
            description="Verify authenticity of signed text messages using public keys."
            href="/verify-text"
          />
          <FeatureCard
            icon={Landmark}
            title="Certificate Authority"
            description="Act as a Root CA to issue and validate identity certificates for your trusted organization."
            href="/certificate-authority"
          />
          <FeatureCard
            icon={LayoutDashboard}
            title="Audit Logs"
            description="Track and monitor all cryptographic operations performed within the system."
            href="/audit-logs"
            width="full"
          />
        </div>
      </div>
    </main>
  );
}

function StatsCard({ icon: Icon, value, label, trend, color }: any) {
  const colors = {
    accent: 'text-accent',
    success: 'text-success',
    warning: 'text-warning',
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true }}
      className="glass p-6 rounded-2xl border border-white/5 hover:border-accent/20 transition-colors backdrop-blur-xl bg-background-secondary/50"
    >
      <div className="flex items-start justify-between mb-4">
        <div className={`p-3 rounded-xl bg-white/5 ${(colors as any)[color]}`}>
          <Icon size={24} />
        </div>
        <div className={`text-xs font-mono px-2 py-1 rounded-full bg-white/5 ${(colors as any)[color]}`}>
          {trend}
        </div>
      </div>
      <div className="text-2xl font-bold text-white mb-1">{value}</div>
      <div className="text-sm text-text-secondary">{label}</div>
    </motion.div>
  );
}

function FeatureCard({ icon: Icon, title, description, href, special, width }: any) {
  return (
    <Link href={href} className={width === 'full' ? 'md:col-span-2 lg:col-span-3' : ''}>
      <motion.div
        whileHover={{ y: -5, scale: 1.01 }}
        className={`h-full glass rounded-2xl p-8 cursor-pointer group hover:border-accent/40 transition-all duration-300 relative overflow-hidden ${special ? 'bg-accent/5 border-accent/20' : 'bg-background-secondary/30 border-white/5'}`}
      >
        {special && (
          <div className="absolute -right-10 -top-10 w-32 h-32 bg-accent/10 rounded-full blur-3xl group-hover:bg-accent/20 transition-colors" />
        )}

        <div className="flex items-start gap-4 mb-4 relative z-10">
          <div className={`p-4 rounded-xl ${special ? 'bg-accent/20 text-accent' : 'bg-white/5 text-text-primary'} group-hover:scale-110 transition-transform duration-300`}>
            <Icon className="w-8 h-8" />
          </div>
        </div>
        <h3 className="text-xl font-bold font-display mb-3 text-white group-hover:text-accent transition-colors">{title}</h3>
        <p className="text-text-secondary leading-relaxed text-sm">{description}</p>

        <div className="absolute bottom-4 right-4 opacity-0 group-hover:opacity-100 transition-opacity transform translate-y-2 group-hover:translate-y-0 text-accent">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M5 12h14" /><path d="m12 5 7 7-7 7" /></svg>
        </div>
      </motion.div>
    </Link>
  );
}

