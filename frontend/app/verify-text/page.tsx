'use client';

import { useState } from 'react';
import { motion } from 'framer-motion';
import { Loader2, Upload, CheckCircle, XCircle } from 'lucide-react';
import { api } from '@/lib/api';
import { useToast } from '@/hooks/useToast';
import { VerifyMessageRequest, VerifyMessageResponse } from '@/lib/types';

export default function VerifyTextPage() {
  const { showToast } = useToast();
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<VerifyMessageResponse | null>(null);
  const [keyFile, setKeyFile] = useState<File | null>(null);
  const [formData, setFormData] = useState<VerifyMessageRequest>({
    message: '',
    signature: '',
    public_key_pem: '',
  });

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setKeyFile(file);
    const content = await file.text();
    setFormData({ ...formData, public_key_pem: content });
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!keyFile) {
      showToast('Please select a public key file', 'error');
      return;
    }

    setLoading(true);
    setResult(null);

    try {
      const { data, error } = await api.post<VerifyMessageResponse>('/api/verify/message', formData);

      if (error) {
        showToast(error, 'error');
      } else if (data) {
        setResult(data);
        if (data.is_valid) {
          showToast('Valid signature!', 'success');
        } else {
          showToast('Invalid signature!', 'error');
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
          Verify Text
        </h1>
        <p className="text-text-secondary text-lg">
          Verify authenticity of a signed text message
        </p>
      </div>

      <form onSubmit={handleSubmit} className="space-y-6">
        <div className="glass rounded-2xl p-8 space-y-6">
          <div>
            <label className="block text-sm font-bold text-text-muted uppercase tracking-wider mb-3">
              Public Key
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
                  {keyFile ? `Selected: ${keyFile.name}` : 'Drag & drop public_key.pem here or click to browse'}
                </span>
              </div>
            </label>
          </div>

          <div>
            <label htmlFor="message" className="block text-sm font-bold text-text-muted uppercase tracking-wider mb-3">
              Original Message
            </label>
            <textarea
              id="message"
              rows={4}
              placeholder="Enter original message..."
              value={formData.message}
              onChange={(e) => setFormData({ ...formData, message: e.target.value })}
              className="w-full px-4 py-3 rounded-xl bg-black/40 border border-glass-border text-text-primary placeholder:text-text-secondary focus:outline-none focus:border-accent focus:ring-2 focus:ring-accent/20 transition-all resize-none font-mono"
            />
          </div>

          <div>
            <label htmlFor="signature" className="block text-sm font-bold text-text-muted uppercase tracking-wider mb-3">
              Signature (Hex)
            </label>
            <input
              id="signature"
              type="text"
              placeholder="Paste the signature string here..."
              value={formData.signature}
              onChange={(e) => setFormData({ ...formData, signature: e.target.value })}
              className="w-full px-4 py-3 rounded-xl bg-black/40 border border-glass-border text-text-primary placeholder:text-text-secondary focus:outline-none focus:border-accent focus:ring-2 focus:ring-accent/20 transition-all font-mono text-sm"
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
                Verifying...
              </span>
            ) : (
              'Verify Signature'
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
          <div className="flex items-center gap-4">
            {result.is_valid ? (
              <CheckCircle className="w-12 h-12 text-success flex-shrink-0" />
            ) : (
              <XCircle className="w-12 h-12 text-error flex-shrink-0" />
            )}
            <div>
              <h2 className={`text-2xl font-bold mb-2 ${result.is_valid ? 'text-success' : 'text-error'}`}>
                {result.is_valid ? 'VALID SIGNATURE' : 'INVALID SIGNATURE'}
              </h2>
              <p className="text-text-secondary">
                {result.is_valid ? 'Authentic' : result.error_message || 'Failed'}
              </p>
            </div>
          </div>
        </motion.div>
      )}
    </motion.div>
  );
}
