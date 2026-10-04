import React from 'react';
import { useState, useEffect, useCallback } from 'react';
import { Filter, Download } from 'lucide-react';
import { useToast } from '../contexts/ToastContext';
import AlertsTable from '../components/AlertsTable';
import { getAlerts } from '../services/api';

const PAGE_LIMIT = 50;

const Alerts = () => {
  const [severity, setSeverity] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [alertsLoading, setAlertsLoading] = useState(false);
  const [alertsError, setAlertsError] = useState(null);
  const [hasMoreAlerts, setHasMoreAlerts] = useState(false);
  const [exporting, setExporting] = useState(false);
  const { success, error } = useToast();

  const loadAlerts = useCallback(async (currentSeverity, offset = 0, append = false) => {
    try {
      setAlertsLoading(true);
      const response = await getAlerts(PAGE_LIMIT, offset, currentSeverity);
      const nextAlerts = Array.isArray(response)
        ? response
        : Array.isArray(response.alerts)
        ? response.alerts
        : Array.isArray(response.items)
        ? response.items
        : [];
      const total = typeof response.total === 'number' ? response.total : nextAlerts.length;

      setHasMoreAlerts(offset + nextAlerts.length < total || nextAlerts.length === PAGE_LIMIT);
      setAlerts((prev) => (append ? [...prev, ...nextAlerts] : nextAlerts));
      setAlertsError(null);
    } catch (err) {
      console.error('Failed to load alerts:', err);
      setAlertsError(err.message || 'Unable to load alerts');
    } finally {
      setAlertsLoading(false);
    }
  }, []);

  useEffect(() => {
    const load = async () => {
      await loadAlerts(severity, 0, false);
    };

    load();
  }, [severity, loadAlerts]);

  const loadMoreAlerts = useCallback(async () => {
    if (alertsLoading || !hasMoreAlerts) return;
    const nextOffset = alerts.length;
    await loadAlerts(severity, nextOffset, true);
  }, [alertsLoading, alerts.length, hasMoreAlerts, loadAlerts, severity]);

  const handleExportAlerts = useCallback(async () => {
    try {
      setExporting(true);
      const response = await getAlerts(1000, 0, severity);
      const payload = Array.isArray(response)
        ? response
        : response.alerts || [];

      const headers = ['Timestamp', 'Source IP', 'Destination IP', 'Attack Type', 'Score', 'Severity', 'LLM Analysis'];
      const rows = payload.map((alert) => [
        new Date(alert.timestamp).toLocaleString(),
        alert.src_ip,
        alert.dst_ip,
        alert.attack_type || '—',
        alert.composite_score?.toFixed(4) || '—',
        alert.severity || '—',
        alert.llm_analysis || '—',
      ]);

      const csvContent = [
        headers.join(','),
        ...rows.map((row) => row.map((cell) => `"${String(cell).replace(/"/g, '""')}"`).join(',')),
      ].join('\n');

      const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
      const link = document.createElement('a');
      const url = URL.createObjectURL(blob);
      link.setAttribute('href', url);
      link.setAttribute('download', `alerts-${new Date().toISOString().split('T')[0]}.csv`);
      link.click();

      success(`Exported ${payload.length} alerts to CSV`, 'Export Successful');
    } catch (err) {
      console.error('Export failed:', err);
      error(err.message || 'Export failed', 'Export Failed');
    } finally {
      setExporting(false);
    }
  }, [severity, success, error]);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold text-[var(--color-cyber-text)]">Attack Alerts</h2>
        <button
          onClick={handleExportAlerts}
          disabled={exporting}
          className="cyber-button cyber-button-secondary flex items-center gap-2"
          title="Export alerts to CSV"
        >
          <Download className="w-4 h-4" />
          {exporting ? 'Exporting...' : 'Export'}
        </button>
      </div>

      <div className="glass-panel p-4">
        <div className="flex flex-wrap items-center gap-4">
          <div className="flex items-center gap-2">
            <Filter className="w-4 h-4 text-[var(--color-cyber-muted)]" />
            <span className="text-sm text-[var(--color-cyber-muted)]">Filter by severity:</span>
          </div>
          <div className="flex gap-2">
            {[
              { value: null, label: 'All', color: 'text-[var(--color-cyber-text)]' },
              { value: 'medium', label: 'Medium', color: 'text-[var(--color-cyber-warning)]' },
              { value: 'high', label: 'High', color: 'text-orange-400' },
              { value: 'critical', label: 'Critical', color: 'text-[var(--color-cyber-danger)]' },
            ].map(({ value, label, color }) => (
              <button
                key={value || 'all'}
                onClick={() => setSeverity(value)}
                className={`px-4 py-2 text-sm rounded-lg border transition-all ${
                  severity === value
                    ? 'bg-[var(--color-cyber-blue)]/20 border-[var(--color-cyber-blue)]/50 text-[var(--color-cyber-blue)]'
                    : `border-[var(--color-cyber-border)] hover:border-[var(--color-cyber-blue)]/30 ${color}`
                }`}
              >
                {label}
              </button>
            ))}
          </div>
        </div>
        <p className="text-xs text-[var(--color-cyber-muted)] mt-3">
          💡 Tip: Click on any alert row to see detailed analysis including LLM insights and scoring breakdown
        </p>
      </div>

      <AlertsTable
        isDashboard={false}
        severityFilter={severity}
        alertsOverride={alerts}
        alertsLoadingOverride={alertsLoading}
        alertsErrorOverride={alertsError}
        hasMoreAlertsOverride={hasMoreAlerts}
        loadMoreAlertsOverride={loadMoreAlerts}
      />
    </div>
  );
};

export default Alerts;
