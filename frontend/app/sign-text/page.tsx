'use client';

import { useState } from 'react';
import { motion } from 'framer-motion';
import { Loader2, Upload, Copy } from 'lucide-react';
import { api } from '@/lib/api';
import { useToast } from '@/hooks/useToast';
import { SignMessageRequest, SignMessageResponse } from '@/lib/types';
import { copyToClipboard } from '@/lib/utils';

export default function SignTextPage() {
  const { showToast } = useToast();
  const [loading, setLoading] = useState(false);
  const [signature, setSignature] = useState<SignMessageResponse | null>(null);
  const [keyFile, setKeyFile] = useState<File | null>(null);
  const [formData, setFormData] = useState<SignMessageRequest>({
    message: '',
    private_key_pem: '',
    passphrase: '',
  });

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setKeyFile(file);
    const content = await file.text();
    setFormData({ ...formData, private_key_pem: content });
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!keyFile) {
      showToast('Please select a private key file', 'error');
      return;
    }

    setLoading(true);
    setSignature(null);

    try {
      const { data, error } = await api.post<SignMessageResponse>('/api/sign/message', formData);

      if (error) {
        showToast(error, 'error');
      } else if (data) {
        setSignature(data);
        showToast('Message signed successfully!', 'success');
      }
    } catch (err) {
      showToast('Network error occurred', 'error');
    } finally {
      setLoading(false);
    }
  };

  const copySignature = async () => {
    if (!signature) return;
    const success = await copyToClipboard(signature.signature);
    if (success) {
      showToast('Signature copied to clipboard!', 'success');
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
          Sign Text
        </h1>
        <p className="text-text-secondary text-lg">
          Create a digital signature for a text message
        </p>
      </div>

      <form onSubmit={handleSubmit} className="space-y-6">
        <div className="glass rounded-2xl p-8 space-y-6">
          <div>
            <label className="block text-sm font-bold text-text-muted uppercase tracking-wider mb-3">
              Private Key
            </label>
            <label className="relative cursor-pointer">
              <input
                type="file"
                accept=".pem"
                onChange={handleFileUpload}
                className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
              />
              <div className={`flex flex-col items-center justify-center gap-3 px-4 py-8 rounded-xl border-2 border-dashed transition-all ${
                keyFile ? 'border-success bg-success/10' : 'border-glass-border bg-white/5 hover:border-accent/50 hover:bg-accent/5'
              }`}>
                <Upload className={`w-8 h-8 ${keyFile ? 'text-success' : 'text-accent opacity-60'}`} />
                <span className={`text-sm font-medium ${keyFile ? 'text-success' : 'text-text-secondary'}`}>
                  {keyFile ? `Selected: ${keyFile.name}` : 'Drag & drop private_key.pem here or click to browse'}
                </span>
              </div>
            </label>
          </div>

          <div>
            <label htmlFor="passphrase" className="block text-sm font-bold text-text-muted uppercase tracking-wider mb-3">
              Passphrase (if key is encrypted)
            </label>
            <input
              id="passphrase"
              type="password"
              placeholder="Enter passphrase..."
              value={formData.passphrase}
              onChange={(e) => setFormData({ ...formData, passphrase: e.target.value })}
              className="w-full px-4 py-3 rounded-xl bg-black/40 border border-glass-border text-text-primary placeholder:text-text-secondary focus:outline-none focus:border-accent focus:ring-2 focus:ring-accent/20 transition-all"
            />
          </div>

          <div>
            <label htmlFor="message" className="block text-sm font-bold text-text-muted uppercase tracking-wider mb-3">
              Message
            </label>
            <textarea
              id="message"
              rows={6}
              placeholder="Enter message to sign..."
              value={formData.message}
              onChange={(e) => setFormData({ ...formData, message: e.target.value })}
              className="w-full px-4 py-3 rounded-xl bg-black/40 border border-glass-border text-text-primary placeholder:text-text-secondary focus:outline-none focus:border-accent focus:ring-2 focus:ring-accent/20 transition-all resize-none font-mono"
            />
          </div>

          <button
            type="submit"
            disabled={loading || !keyFile}
            className="w-full bg-accent text-background font-bold py-4 px-6 rounded-xl hover:bg-accent/90 focus:outline-none focus:ring-2 focus:ring-accent focus:ring-offset-2 focus:ring-offset-background disabled:opacity-50 disabled:cursor-not-allowed transition-all hover:shadow-lg hover:shadow-accent/20"
          >
            {loading ? (
              <span className="flex items-center justify-center gap-2">
                <Loader2 className="w-5 h-5 animate-spin" />
                Signing...
              </span>
            ) : (
              'Sign Message'
            )}
          </button>
        </div>
      </form>

      {signature && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="mt-6 glass rounded-2xl p-8 border-success/30"
        >
          <div className="flex items-start justify-between mb-4">
            <label className="text-sm font-bold text-text-muted uppercase tracking-wider">
              Signature (Hex)
            </label>
            <button
              onClick={copySignature}
              className="flex items-center gap-2 bg-accent/10 text-accent px-4 py-2 rounded-lg hover:bg-accent/20 transition-colors font-medium text-sm"
            >
              <Copy className="w-4 h-4" />
              Copy
            </button>
          </div>
          <pre className="bg-black/40 rounded-xl p-4 overflow-x-auto text-sm text-text-secondary font-mono">
            {signature.signature}
          </pre>
        </motion.div>
      )}
    </motion.div>
  );
}
