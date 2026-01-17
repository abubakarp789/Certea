'use client';

import { useState } from 'react';
import { motion } from 'framer-motion';
import { Download, Loader2, CheckCircle } from 'lucide-react';
import { api } from '@/lib/api';
import { useToast } from '@/hooks/useToast';
import { GenerateKeysRequest, GenerateKeysResponse } from '@/lib/types';

export default function KeyGeneratorPage() {
  const { showToast } = useToast();
  const [loading, setLoading] = useState(false);
  const [generatedKeys, setGeneratedKeys] = useState<GenerateKeysResponse | null>(null);
  const [formData, setFormData] = useState<GenerateKeysRequest>({
    passphrase: '',
    key_size: 2048,
  });

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setGeneratedKeys(null);

    try {
      // 1. Generate keys (JSON) for display
      const { data, error } = await api.post<GenerateKeysResponse>('/api/keys/generate', {
        ...formData,
        response_format: 'json'
      });

      if (error) {
        showToast(error, 'error');
      } else if (data) {
        setGeneratedKeys(data);
        showToast('Keys generated successfully!', 'success');
      }
    } catch (err) {
      showToast('Network error occurred', 'error');
    } finally {
      setLoading(false);
    }
  };

  const downloadKeys = async () => {
    if (!generatedKeys) return;

    try {
      const blob = await api.download('/api/keys/generate', {
        ...formData,
        response_format: 'zip'
      });

      if (blob) {
        const url = window.URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = 'keys.zip';
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
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="max-w-2xl mx-auto"
    >
      <div className="mb-8">
        <h1 className="text-4xl font-bold font-display text-white mb-2">
          Generate Keys
        </h1>
        <p className="text-text-secondary text-lg">
          Create a new RSA public/private key pair
        </p>
      </div>

      <form onSubmit={handleSubmit} className="space-y-6">
        <div className="glass rounded-2xl p-8 space-y-6">
          <div>
            <label htmlFor="passphrase" className="block text-sm font-bold text-text-muted uppercase tracking-wider mb-3">
              Passphrase (Optional)
            </label>
            <input
              id="passphrase"
              type="password"
              placeholder="Protect your private key..."
              value={formData.passphrase}
              onChange={(e) => setFormData({ ...formData, passphrase: e.target.value })}
              className="w-full px-4 py-3 rounded-xl bg-black/40 border border-glass-border text-text-primary placeholder:text-text-secondary focus:outline-none focus:border-accent focus:ring-2 focus:ring-accent/20 transition-all"
            />
          </div>

          <div>
            <label htmlFor="keySize" className="block text-sm font-bold text-text-muted uppercase tracking-wider mb-3">
              Key Size
            </label>
            <select
              id="keySize"
              value={formData.key_size}
              onChange={(e) => setFormData({ ...formData, key_size: parseInt(e.target.value) })}
              className="w-full px-4 py-3 rounded-xl bg-black/40 border border-glass-border text-text-primary focus:outline-none focus:border-accent focus:ring-2 focus:ring-accent/20 transition-all cursor-pointer"
            >
              <option value={2048}>2048 bits (Standard)</option>
              <option value={4096}>4096 bits (High Security)</option>
            </select>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-accent text-background font-bold py-4 px-6 rounded-xl hover:bg-accent/90 focus:outline-none focus:ring-2 focus:ring-accent focus:ring-offset-2 focus:ring-offset-background disabled:opacity-50 disabled:cursor-not-allowed transition-all hover:shadow-lg hover:shadow-accent/20"
          >
            {loading ? (
              <span className="flex items-center justify-center gap-2">
                <Loader2 className="w-5 h-5 animate-spin" />
                Generating safe primes...
              </span>
            ) : (
              'Generate Keys'
            )}
          </button>
        </div>
      </form>

      {generatedKeys && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="mt-6 glass rounded-2xl p-8 border-success/30"
        >
          <div className="flex items-start justify-between mb-4">
            <div className="flex items-center gap-3">
              <CheckCircle className="w-6 h-6 text-success" />
              <h3 className="text-xl font-bold text-white">Keys Generated!</h3>
            </div>
            <button
              onClick={downloadKeys}
              className="flex items-center gap-2 bg-success/10 text-success px-4 py-2 rounded-lg hover:bg-success/20 transition-colors font-medium"
            >
              <Download className="w-4 h-4" />
              Download Key Pair (.zip)
            </button>
          </div>
          <p className="text-text-secondary">
            The keys have been generated cryptographically. Click above to save them securely.
          </p>
        </motion.div>
      )}
    </motion.div>
  );
}
