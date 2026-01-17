'use client';

import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Loader2, RefreshCw, Download, CheckCircle, XCircle } from 'lucide-react';
import { api } from '@/lib/api';
import { useToast } from '@/hooks/useToast';
import { LogEntry } from '@/lib/types';

export default function AuditLogsPage() {
  const { showToast } = useToast();
  const [loading, setLoading] = useState(true);
  const [logs, setLogs] = useState<LogEntry[]>([]);

  const loadLogs = async () => {
    setLoading(true);
    try {
      const { data, error } = await api.get<LogEntry[]>('/api/logs');

      if (error) {
        showToast(error, 'error');
        setLogs([]);
      } else if (data) {
        setLogs(data.reverse());
      }
    } catch (err) {
      showToast('Network error occurred', 'error');
      setLogs([]);
    } finally {
      setLoading(false);
    }
  };

  const exportLogs = () => {
    const content = JSON.stringify(logs, null, 2);
    const blob = new Blob([content], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `audit_logs_${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    showToast('Logs exported successfully!', 'success');
  };

  useEffect(() => {
    loadLogs();
  }, []);

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="max-w-6xl mx-auto"
    >
      <div className="mb-8 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-4xl font-bold font-display text-white mb-2">
            Audit Logs
          </h1>
          <p className="text-text-secondary text-lg">
            History of all verification attempts
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={loadLogs}
            disabled={loading}
            className="flex items-center gap-2 bg-white/10 text-white px-4 py-3 rounded-xl hover:bg-white/20 focus:outline-none focus:ring-2 focus:ring-accent transition-all font-medium disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <button
            onClick={exportLogs}
            disabled={logs.length === 0}
            className="flex items-center gap-2 bg-accent text-background px-4 py-3 rounded-xl hover:bg-accent/90 focus:outline-none focus:ring-2 focus:ring-accent transition-all font-medium disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <Download className="w-4 h-4" />
            Export
          </button>
        </div>
      </div>

      <div className="glass rounded-2xl overflow-hidden">
        {loading ? (
          <div className="p-12 flex items-center justify-center">
            <Loader2 className="w-8 h-8 animate-spin text-accent" />
            <span className="ml-3 text-text-secondary">Loading logs...</span>
          </div>
        ) : logs.length === 0 ? (
          <div className="p-12 text-center text-text-secondary">
            No logs found
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-glass-border bg-black/20">
                  <th className="px-6 py-4 text-left text-xs font-bold text-text-muted uppercase tracking-wider">
                    Timestamp
                  </th>
                  <th className="px-6 py-4 text-left text-xs font-bold text-text-muted uppercase tracking-wider">
                    Status
                  </th>
                  <th className="px-6 py-4 text-left text-xs font-bold text-text-muted uppercase tracking-wider">
                    Message ID
                  </th>
                  <th className="px-6 py-4 text-left text-xs font-bold text-text-muted uppercase tracking-wider">
                    Signature ID
                  </th>
                </tr>
              </thead>
              <tbody>
                {logs.map((log, index) => (
                  <tr
                    key={index}
                    className="border-b border-glass-border hover:bg-white/5 transition-colors"
                  >
                    <td className="px-6 py-4 text-sm text-text-primary">
                      {new Date(log.timestamp).toLocaleString()}
                    </td>
                    <td className="px-6 py-4">
                      <div
                        className={`inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-bold ${
                          log.result
                            ? 'bg-success/10 text-success'
                            : 'bg-error/10 text-error'
                        }`}
                      >
                        {log.result ? (
                          <>
                            <CheckCircle className="w-3 h-3" />
                            Valid
                          </>
                        ) : (
                          <>
                            <XCircle className="w-3 h-3" />
                            Invalid
                          </>
                        )}
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <code className="text-sm font-mono text-accent bg-accent/10 px-2 py-1 rounded">
                        {log.message_id}
                      </code>
                    </td>
                    <td className="px-6 py-4">
                      <code className="text-sm font-mono text-text-secondary bg-black/20 px-2 py-1 rounded">
                        {log.signature_id}
                      </code>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </motion.div>
  );
}
