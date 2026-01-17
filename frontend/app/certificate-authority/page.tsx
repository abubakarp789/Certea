'use client';

import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Loader2, Download, CheckCircle, XCircle, Upload, File } from 'lucide-react';
import { api } from '@/lib/api';
import { useToast } from '@/hooks/useToast';
import { CreateCAResponse, SignCertificateResponse, VerifyCertificateResponse } from '@/lib/types';

type TabType = 'create' | 'issue' | 'verify';

export default function CertificateAuthorityPage() {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="max-w-2xl mx-auto"
    >
      <div className="mb-8">
        <h1 className="text-4xl font-bold font-display text-white mb-2">
          Certificate Authority
        </h1>
        <p className="text-text-secondary text-lg">
          Manage trusted certificates and identities
        </p>
      </div>

      <CATabs />
    </motion.div>
  );
}

function CATabs() {
  const [activeTab, setActiveTab] = useState<TabType>('create');

  return (
    <div className="space-y-6">
      <div className="flex gap-2 bg-black/40 p-2 rounded-xl inline-flex w-full">
        <TabButton active={activeTab === 'create'} onClick={() => setActiveTab('create')}>
          Create CA
        </TabButton>
        <TabButton active={activeTab === 'issue'} onClick={() => setActiveTab('issue')}>
          Issue Cert
        </TabButton>
        <TabButton active={activeTab === 'verify'} onClick={() => setActiveTab('verify')}>
          Verify Cert
        </TabButton>
      </div>

      <AnimatePresence mode="wait">
        {activeTab === 'create' && (
          <motion.div
            key="create"
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: 20 }}
          >
            <CreateCA />
          </motion.div>
        )}
        {activeTab === 'issue' && (
          <motion.div
            key="issue"
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: 20 }}
          >
            <IssueCert />
          </motion.div>
        )}
        {activeTab === 'verify' && (
          <motion.div
            key="verify"
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: 20 }}
          >
            <VerifyCert />
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

function TabButton({ active, onClick, children }: any) {
  return (
    <button
      onClick={onClick}
      className={`flex-1 py-3 px-6 rounded-lg font-medium transition-all ${active
          ? 'bg-accent text-background shadow-lg shadow-accent/20'
          : 'text-text-secondary hover:text-text-primary hover:bg-white/5'
        }`}
    >
      {children}
    </button>
  );
}

function CreateCA() {
  const { showToast } = useToast();
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<CreateCAResponse | null>(null);
  const [name, setName] = useState('My Secure CA');
  const [passphrase, setPassphrase] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setResult(null);

    try {
      const { data, error } = await api.post<CreateCAResponse>('/api/ca/create', {
        name,
        passphrase,
        response_format: 'json'
      });

      if (error) {
        showToast(error, 'error');
      } else if (data) {
        setResult(data);
        showToast('CA Initialized!', 'success');
      }
    } catch (err) {
      showToast('Network error occurred', 'error');
    } finally {
      setLoading(false);
    }
  };

  const downloadKeys = async () => {
    if (!result) return;

    try {
      const blob = await api.download('/api/ca/create', {
        name,
        passphrase,
        response_format: 'zip'
      });

      if (blob) {
        const url = window.URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = 'ca_keys.zip';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        window.URL.revokeObjectURL(url);
        showToast('Download started', 'success');
      } else {
        showToast('Download failed', 'error');
      }
    } catch (err) {
      showToast('Download failed', 'error');
    }
  };

  return (
    <form onSubmit={handleSubmit} className="glass rounded-2xl p-8 space-y-6">
      <div>
        <label htmlFor="caName" className="block text-sm font-bold text-text-muted uppercase tracking-wider mb-3">
          CA Name
        </label>
        <input
          id="caName"
          type="text"
          value={name}
          onChange={(e) => setName(e.target.value)}
          className="w-full px-4 py-3 rounded-xl bg-black/40 border border-glass-border text-text-primary placeholder:text-text-secondary focus:outline-none focus:border-accent focus:ring-2 focus:ring-accent/20 transition-all"
        />
      </div>

      <div>
        <label htmlFor="caPass" className="block text-sm font-bold text-text-muted uppercase tracking-wider mb-3">
          Passphrase
        </label>
        <input
          id="caPass"
          type="password"
          placeholder="Protect CA private key"
          value={passphrase}
          onChange={(e) => setPassphrase(e.target.value)}
          className="w-full px-4 py-3 rounded-xl bg-black/40 border border-glass-border text-text-primary placeholder:text-text-secondary focus:outline-none focus:border-accent focus:ring-2 focus:ring-accent/20 transition-all"
        />
      </div>

      <button
        type="submit"
        disabled={loading}
        className="w-full bg-accent text-background font-bold py-4 px-6 rounded-xl hover:bg-accent/90 focus:outline-none focus:ring-2 focus:ring-accent focus:ring-offset-2 focus:ring-offset-background disabled:opacity-50 disabled:cursor-not-allowed transition-all hover:shadow-lg hover:shadow-accent/20"
      >
        {loading ? (
          <span className="flex items-center justify-center gap-2">
            <Loader2 className="w-5 h-5 animate-spin" />
            Initializing...
          </span>
        ) : (
          'Initialize CA'
        )}
      </button>

      {result && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="pt-6 border-t border-glass-border"
        >
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <CheckCircle className="w-6 h-6 text-success" />
              <h3 className="text-xl font-bold text-white">CA Created!</h3>
            </div>
            <button
              onClick={downloadKeys}
              className="flex items-center gap-2 bg-success/10 text-success px-4 py-2 rounded-lg hover:bg-success/20 transition-colors font-medium text-sm"
            >
              <Download className="w-4 h-4" />
              Download CA Keys (.zip)
            </button>
          </div>
          <p className="text-text-secondary">Download your Root CA keys below.</p>
        </motion.div>
      )}
    </form>
  );
}

function IssueCert() {
  const { showToast } = useToast();
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<SignCertificateResponse | null>(null);
  const [subject, setSubject] = useState('');
  const [caKeyFile, setCaKeyFile] = useState<File | null>(null);
  const [subKeyFile, setSubKeyFile] = useState<File | null>(null);
  const [passphrase, setPassphrase] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!subject || !caKeyFile || !subKeyFile) {
      showToast('Missing required fields', 'error');
      return;
    }

    setLoading(true);
    setResult(null);

    try {
      const formData = new FormData();
      formData.append('subject_name', subject);
      formData.append('ca_private_key', caKeyFile);
      formData.append('subject_public_key', subKeyFile);
      if (passphrase) formData.append('passphrase', passphrase);
      formData.append('days', '365');

      const { data, error } = await api.postFormData<SignCertificateResponse>('/api/ca/sign-certificate', formData);

      if (error) {
        showToast(error, 'error');
      } else if (data) {
        setResult(data);
        showToast('Certificate issued!', 'success');
      }
    } catch (err) {
      showToast('Network error occurred', 'error');
    } finally {
      setLoading(false);
    }
  };

  const downloadCert = () => {
    if (!result) return;
    const content = JSON.stringify(result, null, 2);
    const blob = new Blob([content], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `certificate_${result.subject}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  return (
    <form onSubmit={handleSubmit} className="glass rounded-2xl p-8 space-y-6">
      <div>
        <label htmlFor="subject" className="block text-sm font-bold text-text-muted uppercase tracking-wider mb-3">
          Subject Name
        </label>
        <input
          id="subject"
          type="text"
          placeholder="e.g. Alice or server.com"
          value={subject}
          onChange={(e) => setSubject(e.target.value)}
          className="w-full px-4 py-3 rounded-xl bg-black/40 border border-glass-border text-text-primary placeholder:text-text-secondary focus:outline-none focus:border-accent focus:ring-2 focus:ring-accent/20 transition-all"
        />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <CertFileUpload
          label="Subject Public Key"
          file={subKeyFile}
          setFile={setSubKeyFile}
          accept=".pem"
        />
        <CertFileUpload
          label="CA Private Key"
          file={caKeyFile}
          setFile={setCaKeyFile}
          accept=".pem"
        />
      </div>

      <div>
        <label htmlFor="certPass" className="block text-sm font-bold text-text-muted uppercase tracking-wider mb-3">
          CA Passphrase
        </label>
        <input
          id="certPass"
          type="password"
          placeholder="Enter CA passphrase"
          value={passphrase}
          onChange={(e) => setPassphrase(e.target.value)}
          className="w-full px-4 py-3 rounded-xl bg-black/40 border border-glass-border text-text-primary placeholder:text-text-secondary focus:outline-none focus:border-accent focus:ring-2 focus:ring-accent/20 transition-all"
        />
      </div>

      <button
        type="submit"
        disabled={loading}
        className="w-full bg-accent text-background font-bold py-4 px-6 rounded-xl hover:bg-accent/90 focus:outline-none focus:ring-2 focus:ring-accent focus:ring-offset-2 focus:ring-offset-background disabled:opacity-50 disabled:cursor-not-allowed transition-all hover:shadow-lg hover:shadow-accent/20"
      >
        {loading ? (
          <span className="flex items-center justify-center gap-2">
            <Loader2 className="w-5 h-5 animate-spin" />
            Issuing...
          </span>
        ) : (
          'Issue Certificate'
        )}
      </button>

      {result && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="pt-6 border-t border-glass-border"
        >
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <CheckCircle className="w-6 h-6 text-success" />
              <h3 className="text-xl font-bold text-white">Certificate Issued</h3>
            </div>
            <button
              onClick={downloadCert}
              className="flex items-center gap-2 bg-success/10 text-success px-4 py-2 rounded-lg hover:bg-success/20 transition-colors font-medium text-sm"
            >
              <Download className="w-4 h-4" />
              Download Cert
            </button>
          </div>
        </motion.div>
      )}
    </form>
  );
}

function VerifyCert() {
  const { showToast } = useToast();
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<VerifyCertificateResponse | null>(null);
  const [certFile, setCertFile] = useState<File | null>(null);
  const [caKeyFile, setCaKeyFile] = useState<File | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!certFile || !caKeyFile) {
      showToast('Missing files', 'error');
      return;
    }

    setLoading(true);
    setResult(null);

    try {
      const formData = new FormData();
      formData.append('certificate_file', certFile);
      formData.append('ca_public_key', caKeyFile);

      const { data, error } = await api.postFormData<VerifyCertificateResponse>('/api/ca/verify-certificate', formData);

      if (error) {
        showToast(error, 'error');
      } else if (data) {
        setResult(data);
        if (data.is_valid) {
          showToast('Certificate trusted!', 'success');
        } else {
          showToast('Certificate invalid!', 'error');
        }
      }
    } catch (err) {
      showToast('Network error occurred', 'error');
    } finally {
      setLoading(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="glass rounded-2xl p-8 space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <CertFileUpload
          label="Certificate File"
          file={certFile}
          setFile={setCertFile}
          accept=".json"
        />
        <CertFileUpload
          label="CA Public Key"
          file={caKeyFile}
          setFile={setCaKeyFile}
          accept=".pem"
        />
      </div>

      <button
        type="submit"
        disabled={loading}
        className="w-full bg-accent text-background font-bold py-4 px-6 rounded-xl hover:bg-accent/90 focus:outline-none focus:ring-2 focus:ring-accent focus:ring-offset-2 focus:ring-offset-background disabled:opacity-50 disabled:cursor-not-allowed transition-all hover:shadow-lg hover:shadow-accent/20"
      >
        {loading ? (
          <span className="flex items-center justify-center gap-2">
            <Loader2 className="w-5 h-5 animate-spin" />
            Verifying...
          </span>
        ) : (
          'Verify Validity'
        )}
      </button>

      {result && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className={`p-6 rounded-xl border-2 ${result.is_valid ? 'bg-success/10 border-success/50' : 'bg-error/10 border-error/50'
            }`}
        >
          <div className="flex items-center gap-4">
            {result.is_valid ? (
              <CheckCircle className="w-12 h-12 text-success flex-shrink-0" />
            ) : (
              <XCircle className="w-12 h-12 text-error flex-shrink-0" />
            )}
            <div>
              <h2 className={`text-2xl font-bold mb-2 ${result.is_valid ? 'text-success' : 'text-error'}`}>
                {result.is_valid ? 'TRUSTED' : 'UNTRUSTED / INVALID'}
              </h2>
              <p className="text-text-secondary">
                {result.is_valid && result.issuer
                  ? `Issued by: ${result.issuer}`
                  : result.error || 'Signature mismatch'}
              </p>
            </div>
          </div>
        </motion.div>
      )}
    </form>
  );
}

function CertFileUpload({ label, file, setFile, accept }: any) {
  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFile = e.target.files?.[0];
    if (selectedFile) {
      setFile(selectedFile);
    }
  };

  return (
    <div>
      <label className="block text-sm font-bold text-text-muted uppercase tracking-wider mb-3">
        {label}
      </label>
      <label className="relative cursor-pointer">
        <input
          type="file"
          accept={accept}
          onChange={handleFileUpload}
          className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
        />
        <div className={`flex flex-col items-center justify-center gap-3 px-4 py-8 rounded-xl border-2 border-dashed transition-all ${file ? 'border-success bg-success/10' : 'border-glass-border bg-white/5 hover:border-accent/50 hover:bg-accent/5'
          }`}>
          {file ? (
            <>
              <File className="w-8 h-8 text-success" />
              <span className="text-sm font-medium text-success">
                Selected: {file.name}
              </span>
            </>
          ) : (
            <>
              <Upload className="w-8 h-8 text-accent opacity-60" />
              <span className="text-sm font-medium text-text-secondary">
                Drop Certificate here
              </span>
            </>
          )}
        </div>
      </label>
    </div>
  );
}
