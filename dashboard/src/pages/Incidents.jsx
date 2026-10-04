import React from 'react';
import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { acknowledgeIncident, getIncidents } from '../services/api';
import { subscribe } from '../services/ws';
import Card from '../components/Card';
import { ShieldAlert, CheckCircle, Filter, ArrowRight } from 'lucide-react';

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

const Incidents = () => {
  const [incidents, setIncidents] = useState([]);
  const [incidentsLoading, setIncidentsLoading] = useState(false);
  const [incidentsError, setIncidentsError] = useState(null);
  const [ackLoading, setAckLoading] = useState(null);
  const [stateFilter, setStateFilter] = useState(null);
  const navigate = useNavigate();

  const filteredIncidents = incidents;

  const fetchIncidents = useCallback(async (state = null) => {
    try {
      setIncidentsLoading(true);
      const data = await getIncidents(50, 0, state);
      const nextIncidents = Array.isArray(data?.incidents) ? data.incidents : [];
      setIncidents(nextIncidents);
      setIncidentsError(null);
    } catch (err) {
      console.error('Failed to load incidents:', err);
      setIncidentsError(err.message || 'Unable to load incidents');
    } finally {
      setIncidentsLoading(false);
    }
  }, []);

  useEffect(() => {
    const load = async () => {
      await fetchIncidents(stateFilter);
    };

    load();
    const interval = setInterval(() => {
      fetchIncidents(stateFilter);
    }, 20000);

    return () => clearInterval(interval);
  }, [stateFilter, fetchIncidents]);

  // Subscribe to real-time incident updates via WebSocket (if backend emits incident events)
  useEffect(() => {
    const unsub = subscribe('incident', (payload) => {
      try {
        // payload expected to be an incident object or array
        const incoming = Array.isArray(payload) ? payload : [payload];
        setIncidents((prev) => {
          const map = new Map(prev.map((i) => [i.id, i]));
          incoming.forEach((inc) => {
            if (!inc || !inc.id) return;
            map.set(inc.id, { ...map.get(inc.id), ...inc });
          });
          // Maintain order: newest first by detected_at
          return Array.from(map.values()).sort((a, b) => new Date(b.detected_at) - new Date(a.detected_at));
        });
      } catch (err) {
        console.error('Failed to apply websocket incident update', err);
      }
    });

    return () => {
      try { unsub(); } catch (err) { console.debug('Failed to unsubscribe websocket incident listener', err); }
    };
  }, []);

  const handleRefresh = async () => {
    await fetchIncidents(stateFilter);
  };

  const handleAcknowledge = async (id) => {
    const username = localStorage.getItem('username') || 'analyst';
    setAckLoading(id);
    try {
      await acknowledgeIncident(id, username);
      await fetchIncidents(stateFilter);
    } catch (err) {
      console.error('Failed to acknowledge incident', err);
      alert('Failed to acknowledge incident. You might not have sufficient permissions.');
    } finally {
      setAckLoading(null);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold text-[var(--color-cyber-text)]">Security Incidents</h2>
        <button
          onClick={handleRefresh}
          className="cyber-button cyber-button-secondary"
          title="Refresh incidents"
        >
          Refresh
        </button>
      </div>

      {/* Filter */}
      <div className="glass-panel p-4">
        <div className="flex flex-wrap items-center gap-4">
          <div className="flex items-center gap-2">
            <Filter className="w-4 h-4 text-[var(--color-cyber-muted)]" />
            <span className="text-sm text-[var(--color-cyber-muted)]">Filter by state:</span>
          </div>
          <div className="flex gap-2">
            {[
              { value: null, label: 'All States' },
              { value: 'detected', label: 'Detected' },
              { value: 'analyzing', label: 'Analyzing' },
              { value: 'mitigating', label: 'Mitigating' },
              { value: 'resolved', label: 'Resolved' },
              { value: 'closed', label: 'Closed' },
            ].map(({ value, label }) => (
              <button
                key={value || 'all'}
                onClick={() => setStateFilter(value)}
                className={`px-4 py-2 text-sm rounded-lg border transition-all ${
                  stateFilter === value
                    ? 'bg-[var(--color-cyber-blue)]/20 border-[var(--color-cyber-blue)]/50 text-[var(--color-cyber-blue)]'
                    : 'border-[var(--color-cyber-border)] hover:border-[var(--color-cyber-blue)]/30 text-[var(--color-cyber-text)]'
                }`}
              >
                {label}
              </button>
            ))}
          </div>
        </div>
      </div>

      <Card title={
        <div className="flex items-center gap-2 text-[var(--color-cyber-text)]">
          <ShieldAlert className="w-5 h-5 text-[var(--color-cyber-danger)]" />
          <span>Incidents {stateFilter && `(${stateFilter})`}</span>
        </div>
      }>
        {incidentsLoading ? (
          <div className="py-12 text-center text-[var(--color-cyber-muted)]">Fetching incident reports...</div>
        ) : incidentsError ? (
          <div className="py-12 text-center text-[var(--color-cyber-danger)]">Unable to load incidents: {incidentsError}</div>
        ) : filteredIncidents.length === 0 ? (
          <div className="py-12 text-center text-[var(--color-cyber-muted)]">
            {stateFilter ? `No incidents in ${stateFilter} state` : 'No incidents recorded. System is secure.'}
          </div>
        ) : (
          <div className="grid gap-4">
            {filteredIncidents.map((incident) => (
              <div key={incident.id} className="glass-panel p-5 border border-[var(--color-cyber-border)] hover:border-[var(--color-cyber-blue)]/30 transition-colors">
                <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
                  
                  <div className="space-y-1 flex-1">
                    <div className="flex items-center gap-3">
                      <h4 className="text-lg font-semibold text-[var(--color-cyber-text)]">
                        {(incident.attack_type || 'Unknown Attack').replace(/_/g, ' ').toUpperCase()}
                      </h4>
                      <span className={`badge ${stateConfig[incident.state] || 'badge-info'}`}>
                        {incident.state.toUpperCase()}
                      </span>
                    </div>
                    <div className="text-sm text-[var(--color-cyber-muted)]">
                      Severity: <span className={`font-medium ${severityColors[incident.severity] || severityColors.low}`}>
                        {incident.severity?.toUpperCase() || 'UNKNOWN'}
                      </span>
                    </div>
                    <div className="text-xs font-mono text-[var(--color-cyber-muted)]">
                      Detected: {new Date(incident.detected_at).toLocaleString()}
                    </div>
                  </div>

                  <div className="flex-shrink-0 flex items-center gap-2">
                    <button
                      onClick={() => navigate(`/incidents/${incident.id}`)}
                      className="cyber-button cyber-button-secondary flex items-center gap-2"
                    >
                      <span>View Details</span>
                      <ArrowRight className="w-4 h-4" />
                    </button>
                    {incident.state !== 'resolved' && incident.state !== 'closed' ? (
                      <button
                        onClick={() => handleAcknowledge(incident.id)}
                        disabled={ackLoading === incident.id}
                        className="cyber-button cyber-button-primary flex items-center gap-2"
                      >
                        {ackLoading === incident.id ? (
                          <span className="w-4 h-4 border-2 border-[var(--color-cyber-blue)] border-t-transparent rounded-full animate-spin"></span>
                        ) : (
                          <CheckCircle className="w-4 h-4" />
                        )}
                        Acknowledge
                      </button>
                    ) : (
                      <div className="text-xs text-[var(--color-cyber-success)] flex items-center gap-1">
                        <CheckCircle className="w-4 h-4" />
                        Resolved by {incident.response_plan?.acknowledged_by || 'System'}
                      </div>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
};

export default Incidents;
