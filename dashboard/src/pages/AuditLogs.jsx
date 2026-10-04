import React from 'react';
import { useState, useEffect } from 'react';
import { getAuditLogs } from '../services/api';
import { useToast } from '../contexts/ToastContext';
import Card from '../components/Card';

const AuditLogs = () => {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [limit] = useState(50);
  const [offset, setOffset] = useState(0);
  const [username, setUsername] = useState('');
  const { error } = useToast();

  const fetchLogs = async () => {
    try {
      setLoading(true);
      const res = await getAuditLogs({ limit, offset, username: username || undefined });
      setLogs(res.audit_logs || []);
    } catch (err) {
      console.error('Failed to load audit logs', err);
      error(err.message || 'Failed to load audit logs');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    fetchLogs();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [offset]);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold text-[var(--color-cyber-text)]">Audit Trail</h2>
        <div className="flex items-center gap-2">
          <input
            type="text"
            placeholder="Filter by username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            className="px-3 py-2 rounded border bg-[var(--color-cyber-darker)] text-sm"
          />
          <button onClick={() => { setOffset(0); fetchLogs(); }} className="cyber-button cyber-button-secondary">Filter</button>
        </div>
      </div>

      <Card title={<span>Recent Audit Events</span>}>
        {loading ? (
          <div className="py-12 text-center text-[var(--color-cyber-muted)]">Loading audit logs...</div>
        ) : logs.length === 0 ? (
          <div className="py-12 text-center text-[var(--color-cyber-muted)]">No audit events found.</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[var(--color-cyber-border)]">
                  <th className="px-4 py-3 text-left text-xs text-[var(--color-cyber-muted)]">Time</th>
                  <th className="px-4 py-3 text-left text-xs text-[var(--color-cyber-muted)]">User</th>
                  <th className="px-4 py-3 text-left text-xs text-[var(--color-cyber-muted)]">Action</th>
                  <th className="px-4 py-3 text-left text-xs text-[var(--color-cyber-muted)]">Resource</th>
                  <th className="px-4 py-3 text-left text-xs text-[var(--color-cyber-muted)]">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--color-cyber-border)]">
                {logs.map((l) => (
                  <tr key={l.id}>
                    <td className="px-4 py-3 font-mono text-xs text-[var(--color-cyber-muted)]">{new Date(l.timestamp).toLocaleString()}</td>
                    <td className="px-4 py-3 text-xs text-[var(--color-cyber-text)]">{l.username}</td>
                    <td className="px-4 py-3 text-xs text-[var(--color-cyber-text)]">{l.action}</td>
                    <td className="px-4 py-3 text-xs text-[var(--color-cyber-text)]">{l.resource_type} {l.resource_id}</td>
                    <td className="px-4 py-3 text-xs font-mono text-[var(--color-cyber-muted)]">{JSON.stringify(l.details || {})}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
};

export default AuditLogs;
