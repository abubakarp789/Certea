'use client';

import { useState } from 'react';
import { motion } from 'framer-motion';
import { Loader2, Upload, File } from 'lucide-react';
import { api } from '@/lib/api';
import { useToast } from '@/hooks/useToast';
import { SignFileResponse } from '@/lib/types';
import { CopyButton } from '@/components/ui/CopyButton';

export default function SignFilePage() {
  const { showToast } = useToast();
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<SignFileResponse | null>(null);
  const [keyFile, setKeyFile] = useState<File | null>(null);
  const [docFile, setDocFile] = useState<File | null>(null);
  const [passphrase, setPassphrase] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!keyFile || !docFile) {
      showToast('Please select both Key and File', 'error');
      return;
    }

    setLoading(true);
    setResult(null);

    try {
      const formData = new FormData();
      formData.append('file', docFile);
      formData.append('private_key', keyFile);
      if (passphrase) formData.append('passphrase', passphrase);

      const { data, error } = await api.postFormData<SignFileResponse>('/api/sign/file', formData);

      if (error) {
        showToast(error, 'error');
      } else if (data) {
        setResult(data);
        showToast('File signed successfully!', 'success');
      }
    } catch (err) {
      showToast('Network error occurred', 'error');
    } finally {
      setLoading(false);
    }
  };



  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="max-w-2xl mx-auto"
    >
      <div className="mb-8">
        <h1 className="text-4xl font-bold font-display text-white mb-2">
          Sign File
        </h1>
        <p className="text-text-secondary text-lg">
          Create a digital signature for any file (PDF, Image, etc.)
        </p>
      </div>

      <form onSubmit={handleSubmit} className="space-y-6">
        <div className="glass rounded-2xl p-8 space-y-6">
          <FileUpload
            label="Private Key"
            file={keyFile}
            setFile={setKeyFile}
            accept=".pem"
            icon="key"
          />

          <FileUpload
            label="File to Sign"
            file={docFile}
            setFile={setDocFile}
            accept="*"
            icon="file"
          />

          <div>
            <label htmlFor="passphrase" className="block text-sm font-bold text-text-muted uppercase tracking-wider mb-3">
              Passphrase
            </label>
            <input
              id="passphrase"
              type="password"
              placeholder="Enter passphrase..."
              value={passphrase}
              onChange={(e) => setPassphrase(e.target.value)}
              className="w-full px-4 py-3 rounded-xl bg-black/40 border border-glass-border text-text-primary placeholder:text-text-secondary focus:outline-none focus:border-accent focus:ring-2 focus:ring-accent/20 transition-all"
            />
          </div>

          <button
            type="submit"
            disabled={loading || !keyFile || !docFile}
            className="w-full bg-accent text-background font-bold py-4 px-6 rounded-xl hover:bg-accent/90 focus:outline-none focus:ring-2 focus:ring-accent focus:ring-offset-2 focus:ring-offset-background disabled:opacity-50 disabled:cursor-not-allowed transition-all hover:shadow-lg hover:shadow-accent/20"
          >
            {loading ? (
              <span className="flex items-center justify-center gap-2">
                <Loader2 className="w-5 h-5 animate-spin" />
                Signing...
              </span>
            ) : (
              'Sign File'
            )}
          </button>
        </div>
      </form>

      {result && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="mt-6 glass rounded-2xl p-8 border-success/30"
        >
          <div className="flex items-start justify-between mb-4">
            <label className="text-sm font-bold text-text-muted uppercase tracking-wider">
              Generated Signature (Hex)
            </label>
            <CopyButton text={result.signature} />
          </div>
          <pre className="bg-black/40 rounded-xl p-4 overflow-x-auto text-sm text-text-secondary font-mono mb-6 max-h-32">
            {result.signature}
          </pre>

          <div className="flex items-start justify-between mb-2">
            <label className="text-sm font-bold text-text-muted uppercase tracking-wider">
              SHA-256 Digest
            </label>
            <CopyButton text={result.message_digest} />
          </div>
          <pre className="bg-black/40 rounded-xl p-4 overflow-x-auto text-sm text-text-secondary font-mono">
            {result.message_digest}
          </pre>
        </motion.div>
      )}
    </motion.div>
  );
}

function FileUpload({ label, file, setFile, accept, icon }: any) {
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
                Drop {icon === 'key' ? 'Private Key' : 'Document/File'} here
              </span>
            </>
          )}
        </div>
      </label>
    </div>
  );
}
