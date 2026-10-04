import React from 'react';
import { useState, memo, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { X } from 'lucide-react';
import { useDashboard } from '../contexts/DashboardContext';

// Severity badge styling
const severityConfig = {
  critical: {
    label: 'CRITICAL',
    className: 'badge bg-[var(--color-cyber-danger)]/20 text-[var(--color-cyber-danger)] border-[var(--color-cyber-danger)]/50',
  },
  high: {
    label: 'HIGH',
    className: 'badge bg-orange-500/20 text-orange-400 border-orange-500/50',
  },
  medium: {
    label: 'MEDIUM',
    className: 'badge bg-[var(--color-cyber-warning)]/20 text-[var(--color-cyber-warning)] border-[var(--color-cyber-warning)]/50',
  },
  low: {
    label: 'LOW',
    className: 'badge bg-[var(--color-cyber-blue)]/10 text-[var(--color-cyber-blue)] border-[var(--color-cyber-blue)]/30',
  },
};

const SeverityBadge = ({ severity }) => {
  const key = (severity || 'low').toLowerCase();
  const config = severityConfig[key] || severityConfig.low;
  return <span className={config.className}>{config.label}</span>;
};

const formatTimestamp = (ts) => {
  if (!ts) return '—';
  try {
    return new Date(ts).toLocaleString();
  } catch {
    return ts;
  }
};

// Detail panel overlay
const DetailPanel = memo(({ alert, onClose }) => {
  if (!alert) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="glass-panel w-full max-w-2xl max-h-[80vh] overflow-y-auto mx-4">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-[var(--color-cyber-border)] bg-[var(--color-cyber-card-hover)]/30">
          <h3 className="text-lg font-semibold text-[var(--color-cyber-text)]">
            Attack Event Detail
          </h3>
          <button
            onClick={onClose}
            className="cyber-button p-1.5 hover:text-[var(--color-cyber-danger)] transition-colors"
            aria-label="Close detail panel"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 space-y-4">
          <div className="flex items-center gap-3">
            <SeverityBadge severity={alert.severity} />
            <span className="text-[var(--color-cyber-muted)] text-sm">
              {formatTimestamp(alert.timestamp)}
            </span>
          </div>

          <div className="grid grid-cols-2 gap-4">
            {[
              ['Source IP', alert.src_ip],
              ['Destination IP', alert.dst_ip],
              ['Attack Type', alert.attack_type],
              ['Composite Score', typeof alert.composite_score === 'number' ? alert.composite_score.toFixed(4) : alert.composite_score],
              ['Source Port', alert.src_port],
              ['Destination Port', alert.dst_port],
              ['Protocol', alert.protocol],
              ['Device ID', alert.device_id],
            ].map(([label, value]) => (
              <div key={label} className="space-y-1">
                <p className="text-xs text-[var(--color-cyber-muted)] uppercase tracking-wider">{label}</p>
                <p className="text-sm text-[var(--color-cyber-text)] font-mono">{value ?? '—'}</p>
              </div>
            ))}
          </div>

          {/* Full raw payload */}
          <div className="space-y-1">
            <p className="text-xs text-[var(--color-cyber-muted)] uppercase tracking-wider">Full Payload</p>
            <pre className="text-xs text-[var(--color-cyber-text)] font-mono bg-[var(--color-cyber-darker)] border border-[var(--color-cyber-border)] rounded-lg p-4 overflow-x-auto whitespace-pre-wrap break-all">
              {JSON.stringify(alert, null, 2)}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
});

const COLUMNS = [
  { key: 'timestamp', label: 'Timestamp' },
  { key: 'src_ip', label: 'Source IP' },
  { key: 'dst_ip', label: 'Destination IP' },
  { key: 'attack_type', label: 'Attack Type' },
  { key: 'composite_score', label: 'Score' },
  { key: 'severity', label: 'Severity' },
];

const AlertsTable = ({
  isDashboard = false,
  severityFilter = null,
  alertsOverride = null,
  alertsLoadingOverride = null,
  alertsErrorOverride = null,
  hasMoreAlertsOverride = null,
  loadMoreAlertsOverride = null,
}) => {
  const {
    alerts: contextAlerts,
    alertsLoading: contextAlertsLoading,
    alertsError: contextAlertsError,
    wsConnected,
    hasMoreAlerts: contextHasMoreAlerts,
    loadMoreAlerts: contextLoadMoreAlerts,
  } = useDashboard();
  const [selectedAlert, setSelectedAlert] = useState(null);
  const navigate = useNavigate();

  const allAlerts = alertsOverride ?? contextAlerts;
  const alertsLoading = alertsLoadingOverride ?? contextAlertsLoading;
  const alertsError = alertsErrorOverride ?? contextAlertsError;
  const hasMoreAlerts = hasMoreAlertsOverride ?? contextHasMoreAlerts;
  const loadMoreAlertsFn = loadMoreAlertsOverride ?? contextLoadMoreAlerts;

  const filteredAlerts = useMemo(() => {
    return (severityFilter
      ? allAlerts.filter((alert) => alert.severity === severityFilter)
      : allAlerts
    )
      .slice()
      .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
  }, [allAlerts, severityFilter]);

  const displayedAlerts = isDashboard ? filteredAlerts.slice(0, 10) : filteredAlerts.slice(0, 50);

  return (
    <>
      <div className="glass-panel overflow-hidden">
        {/* Header */}
        <div className="px-6 py-4 border-b border-[var(--color-cyber-border)] bg-[var(--color-cyber-card-hover)]/30">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h3 className="text-lg font-medium text-[var(--color-cyber-text)]">Recent Alerts</h3>
              <p className="text-xs text-[var(--color-cyber-muted)] mt-1">
                {isDashboard ? `${displayedAlerts.length} shown` : `${filteredAlerts.length} alerts`}
                {severityFilter && ` (${severityFilter})`} · {wsConnected ? 'Live' : 'Offline'} feed
              </p>
            </div>
            <div className="flex items-center gap-3">
              <span className={`inline-flex items-center rounded-full px-2.5 py-1 text-xs font-semibold ${wsConnected ? 'bg-[var(--color-cyber-neon)]/15 text-[var(--color-cyber-neon)]' : 'bg-[var(--color-cyber-warning)]/15 text-[var(--color-cyber-warning)]'}`}>
                <span className={`inline-block h-2.5 w-2.5 rounded-full ${wsConnected ? 'bg-[var(--color-cyber-neon)]' : 'bg-[var(--color-cyber-warning)]'}`} />
                <span className="ml-2">{wsConnected ? 'Realtime' : 'Disconnected'}</span>
              </span>
              {alertsLoading && !filteredAlerts.length && (
                <div className="h-4 w-4 border-2 border-[var(--color-cyber-blue)] border-t-transparent rounded-full animate-spin" />
              )}
            </div>
          </div>
        </div>

        {/* Error */}
        {alertsError && (
          <div className="mx-6 mt-4 px-4 py-3 rounded-lg bg-[var(--color-cyber-danger)]/10 border border-[var(--color-cyber-danger)]/30 text-[var(--color-cyber-danger)] text-sm">
            {alertsError}
          </div>
        )}

        {/* Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[var(--color-cyber-border)]">
                {COLUMNS.map((col) => (
                  <th
                    key={col.key}
                    className="px-6 py-3 text-left text-xs font-medium text-[var(--color-cyber-muted)] uppercase tracking-wider"
                  >
                    {col.label}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--color-cyber-border)]">
              {filteredAlerts.length === 0 && !alertsLoading && (
                <tr>
                  <td
                    colSpan={COLUMNS.length}
                    className="px-6 py-8 text-center text-[var(--color-cyber-muted)]"
                  >
                    No alerts found
                  </td>
                </tr>
              )}
              {displayedAlerts.map((alert, idx) => (
                <tr
                  key={alert.id ?? idx}
                  onClick={() => setSelectedAlert(alert)}
                  className="cursor-pointer transition-colors hover:bg-[var(--color-cyber-card-hover)]/60 hover:shadow-[inset_0_0_0_1px_rgba(0,240,255,0.1)]"
                >
                  <td className="px-6 py-3 font-mono text-xs text-[var(--color-cyber-muted)] whitespace-nowrap">
                    {formatTimestamp(alert.timestamp)}
                  </td>
                  <td className="px-6 py-3 font-mono text-xs text-[var(--color-cyber-text)]">
                    {alert.src_ip ?? '—'}
                  </td>
                  <td className="px-6 py-3 font-mono text-xs text-[var(--color-cyber-text)]">
                    {alert.dst_ip ?? '—'}
                  </td>
                  <td className="px-6 py-3 text-xs text-[var(--color-cyber-blue)]">
                    {alert.attack_type ?? '—'}
                  </td>
                  <td className="px-6 py-3 font-mono text-xs text-[var(--color-cyber-text)]">
                    {typeof alert.composite_score === 'number'
                      ? alert.composite_score.toFixed(4)
                      : alert.composite_score ?? '—'}
                  </td>
                  <td className="px-6 py-3">
                    <SeverityBadge severity={alert.severity} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="mt-4 px-6 py-4 border-t border-[var(--color-cyber-border)] bg-[var(--color-cyber-card-hover)]/20">
          {isDashboard ? (
            <button
              type="button"
              onClick={() => navigate('/alerts')}
              className="cyber-button cyber-button-secondary"
            >
              View all alerts
            </button>
          ) : (
            <button
              type="button"
              onClick={loadMoreAlertsFn}
              disabled={!hasMoreAlerts || alertsLoading}
              className="cyber-button cyber-button-secondary"
            >
              {alertsLoading ? 'Loading...' : hasMoreAlerts ? 'Load more alerts' : 'All alerts loaded'}
            </button>
          )}
        </div>
      </div>

      <DetailPanel alert={selectedAlert} onClose={() => setSelectedAlert(null)} />
    </>
  );
};

export default memo(AlertsTable);
