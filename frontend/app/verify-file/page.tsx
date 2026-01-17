'use client';

import { useState } from 'react';
import { motion } from 'framer-motion';
import { Loader2, Upload, CheckCircle, XCircle, File } from 'lucide-react';
import { api } from '@/lib/api';
import { useToast } from '@/hooks/useToast';
import { VerifyFileResponse } from '@/lib/types';

export default function VerifyFilePage() {
  const { showToast } = useToast();
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<VerifyFileResponse | null>(null);
  const [keyFile, setKeyFile] = useState<File | null>(null);
  const [docFile, setDocFile] = useState<File | null>(null);
  const [signature, setSignature] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!keyFile || !docFile || !signature) {
      showToast('Missing required fields', 'error');
      return;
    }

    setLoading(true);
    setResult(null);

    try {
      const formData = new FormData();
      formData.append('file', docFile);
      formData.append('public_key', keyFile);
      formData.append('signature', signature);

      const { data, error } = await api.postFormData<VerifyFileResponse>('/api/verify/file', formData);

      if (error) {
        showToast(error, 'error');
      } else if (data) {
        setResult(data);
        if (data.is_valid) {
          showToast('Verification passed!', 'success');
        } else {
          showToast('Verification failed!', 'error');
        }
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
          Verify File
        </h1>
        <p className="text-text-secondary text-lg">
          Check if a file has been modified since it was signed
        </p>
      </div>

      <form onSubmit={handleSubmit} className="space-y-6">
        <div className="glass rounded-2xl p-8 space-y-6">
          <FileUpload
            label="Public Key"
            file={keyFile}
            setFile={setKeyFile}
            accept=".pem"
            icon="key"
          />

          <FileUpload
            label="Original File"
            file={docFile}
            setFile={setDocFile}
            accept="*"
            icon="file"
          />

          <div>
            <label htmlFor="signature" className="block text-sm font-bold text-text-muted uppercase tracking-wider mb-3">
              Signature (Hex String)
            </label>
            <input
              id="signature"
              type="text"
              placeholder="Paste the long signature string here..."
              value={signature}
              onChange={(e) => setSignature(e.target.value)}
              className="w-full px-4 py-3 rounded-xl bg-black/40 border border-glass-border text-text-primary placeholder:text-text-secondary focus:outline-none focus:border-accent focus:ring-2 focus:ring-accent/20 transition-all font-mono text-sm"
            />
          </div>

          <button
            type="submit"
            disabled={loading || !keyFile || !docFile || !signature}
            className="w-full bg-accent text-background font-bold py-4 px-6 rounded-xl hover:bg-accent/90 focus:outline-none focus:ring-2 focus:ring-accent focus:ring-offset-2 focus:ring-offset-background disabled:opacity-50 disabled:cursor-not-allowed transition-all hover:shadow-lg hover:shadow-accent/20"
          >
            {loading ? (
              <span className="flex items-center justify-center gap-2">
                <Loader2 className="w-5 h-5 animate-spin" />
                Checking Integrity...
              </span>
            ) : (
              'Verify Integrity'
            )}
          </button>
        </div>
      </form>

      {result && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className={`mt-6 glass rounded-2xl p-8 border-2 ${
            result.is_valid ? 'border-success/50' : 'border-error/50'
          }`}
        >
          <div className="flex items-center gap-4 mb-6">
            {result.is_valid ? (
              <CheckCircle className="w-12 h-12 text-success flex-shrink-0" />
            ) : (
              <XCircle className="w-12 h-12 text-error flex-shrink-0" />
            )}
            <div>
              <h2 className={`text-2xl font-bold mb-2 ${result.is_valid ? 'text-success' : 'text-error'}`}>
                {result.is_valid ? 'FILE IS AUTHENTIC' : 'FILE CORRUPTED / INVALID'}
              </h2>
              <p className="text-text-secondary">
                {result.is_valid 
                  ? 'Matches signature. File matches the original.' 
                  : result.error_message || 'Signature does NOT match this file.'}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2 text-sm text-text-muted pt-4 border-t border-glass-border">
            <span className="font-semibold">File Digest:</span>
            <span className="font-mono text-accent">{result.file_digest}</span>
          </div>
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
        <div className={`flex flex-col items-center justify-center gap-3 px-4 py-8 rounded-xl border-2 border-dashed transition-all ${
          file ? 'border-success bg-success/10' : 'border-glass-border bg-white/5 hover:border-accent/50 hover:bg-accent/5'
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
                Drop {icon === 'key' ? 'Public Key' : 'Document/File'} here
              </span>
            </>
          )}
        </div>
      </label>
    </div>
  );
}
