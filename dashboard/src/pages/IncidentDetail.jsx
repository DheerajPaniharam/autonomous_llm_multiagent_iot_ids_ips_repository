import React from 'react';
import { useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { ArrowLeft, ShieldAlert, CheckCircle, Activity } from 'lucide-react';
import Card from '../components/Card';
import { getIncidentDetail, acknowledgeIncident } from '../services/api';

const stateConfig = {
  detected: 'badge-danger',
  analyzing: 'badge-warning',
  mitigating: 'badge-info',
  resolved: 'badge-success',
  closed: 'bg-[var(--color-cyber-darker)] text-[var(--color-cyber-muted)] border-[var(--color-cyber-muted)]/30',
};

const severityColors = {
  critical: 'text-[var(--color-cyber-danger)]',
  high: 'text-[var(--color-cyber-warning)]',
  medium: 'text-[var(--color-cyber-blue)]',
  low: 'text-[var(--color-cyber-muted)]',
};

const IncidentDetail = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const [incident, setIncident] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [ackLoading, setAckLoading] = useState(false);

  useEffect(() => {
    const fetchIncident = async () => {
      try {
        setLoading(true);
        const data = await getIncidentDetail(id);
        setIncident(data);
        setError(null);
      } catch (err) {
        setError(err?.message || 'Unable to load incident details');
      } finally {
        setLoading(false);
      }
    };

    if (id) {
      fetchIncident();
    }
  }, [id]);

  const handleAcknowledge = async () => {
    try {
      setAckLoading(true);
      const username = localStorage.getItem('username') || 'analyst';
      await acknowledgeIncident(id, username, 'Reviewed from incident detail view.');
      const refreshed = await getIncidentDetail(id);
      setIncident(refreshed);
    } catch (err) {
      setError(err?.message || 'Failed to acknowledge incident');
    } finally {
      setAckLoading(false);
    }
  };

  if (loading) {
    return <div className="py-12 text-center text-[var(--color-cyber-muted)]">Loading incident details...</div>;
  }

  if (error) {
    return (
      <div className="space-y-4">
        <button onClick={() => navigate('/incidents')} className="cyber-button cyber-button-secondary flex items-center gap-2">
          <ArrowLeft className="w-4 h-4" /> Back to incidents
        </button>
        <div className="py-12 text-center text-[var(--color-cyber-danger)]">{error}</div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <button onClick={() => navigate('/incidents')} className="cyber-button cyber-button-secondary flex items-center gap-2">
        <ArrowLeft className="w-4 h-4" /> Back to incidents
      </button>

      <Card title={
        <div className="flex items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-[var(--color-cyber-danger)]" />
            <span>{incident?.attack_type?.replace(/_/g, ' ').toUpperCase() || 'SECURITY INCIDENT'}</span>
          </div>
          <span className={`badge ${stateConfig[incident?.state] || 'badge-info'}`}>{incident?.state?.toUpperCase()}</span>
        </div>
      }>
        <div className="grid gap-6 lg:grid-cols-[1.2fr_0.8fr]">
          <div className="space-y-4">
            <p className="text-[var(--color-cyber-muted)]">{incident?.summary}</p>

            <div className="grid gap-3 sm:grid-cols-2">
              <div className="glass-panel p-4">
                <div className="text-xs uppercase tracking-wide text-[var(--color-cyber-muted)]">Severity</div>
                <div className={`mt-1 font-semibold ${severityColors[incident?.severity] || severityColors.low}`}>
                  {incident?.severity?.toUpperCase()}
                </div>
              </div>
              <div className="glass-panel p-4">
                <div className="text-xs uppercase tracking-wide text-[var(--color-cyber-muted)]">Related Alerts</div>
                <div className="mt-1 text-lg font-semibold text-[var(--color-cyber-text)]">{incident?.alert_count || 0}</div>
              </div>
            </div>

            <div className="glass-panel p-4">
              <div className="text-xs uppercase tracking-wide text-[var(--color-cyber-muted)]">Detection Time</div>
              <div className="mt-1 font-mono text-sm text-[var(--color-cyber-text)]">
                {incident?.detected_at ? new Date(incident.detected_at).toLocaleString() : '—'}
              </div>
            </div>
          </div>

          <div className="space-y-4">
            <div className="glass-panel p-4">
              <div className="text-xs uppercase tracking-wide text-[var(--color-cyber-muted)]">Response Plan</div>
              <pre className="mt-2 whitespace-pre-wrap text-sm text-[var(--color-cyber-text)]">
                {incident?.response_plan ? JSON.stringify(incident.response_plan, null, 2) : 'No response plan yet.'}
              </pre>
            </div>
            {incident?.state !== 'resolved' && incident?.state !== 'closed' ? (
              <button onClick={handleAcknowledge} disabled={ackLoading} className="cyber-button cyber-button-primary flex items-center gap-2">
                {ackLoading ? <span className="w-4 h-4 border-2 border-[var(--color-cyber-blue)] border-t-transparent rounded-full animate-spin" /> : <CheckCircle className="w-4 h-4" />}
                {ackLoading ? 'Updating...' : 'Acknowledge Incident'}
              </button>
            ) : (
              <div className="flex items-center gap-2 text-[var(--color-cyber-success)]">
                <CheckCircle className="w-4 h-4" /> Resolved
              </div>
            )}
          </div>
        </div>
      </Card>

      <Card title={
        <div className="flex items-center gap-2 text-[var(--color-cyber-text)]">
          <Activity className="w-5 h-5 text-[var(--color-cyber-blue)]" />
          <span>Related Alerts</span>
        </div>
      }>
        {incident?.related_alerts?.length ? (
          <div className="space-y-3">
            {incident.related_alerts.map((alert) => (
              <div key={alert.id} className="glass-panel p-4 border border-[var(--color-cyber-border)]">
                <div className="flex flex-col gap-2 md:flex-row md:justify-between">
                  <div>
                    <div className="font-semibold text-[var(--color-cyber-text)]">{alert.attack_type || 'Unknown Attack'}</div>
                    <div className="text-sm text-[var(--color-cyber-muted)]">
                      {alert.src_ip} → {alert.dst_ip} • {new Date(alert.timestamp).toLocaleString()}
                    </div>
                  </div>
                  <div className="text-sm text-[var(--color-cyber-warning)]">Score {alert.composite_score?.toFixed(2)}</div>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="text-[var(--color-cyber-muted)]">No related alerts found for this incident.</div>
        )}
      </Card>
    </div>
  );
};

export default IncidentDetail;
