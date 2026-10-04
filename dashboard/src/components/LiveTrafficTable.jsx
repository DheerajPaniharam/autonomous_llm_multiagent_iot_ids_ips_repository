import React from 'react';
import { memo, useMemo } from 'react';
import { useDashboard } from '../contexts/DashboardContext';

const formatTimestamp = (ts) => {
  if (!ts) return '—';
  try {
    return new Date(ts).toLocaleString();
  } catch {
    return ts;
  }
};

const LiveTrafficTable = () => {
  const { liveTraffic, liveTrafficLoading, liveTrafficError, wsConnected } = useDashboard();

  const lastTrafficAt = useMemo(() => {
    return liveTraffic.length > 0
      ? liveTraffic[0]?.timestamp
      : null;
  }, [liveTraffic]);

  return (
    <div className="glass-panel overflow-hidden">
      <div className="px-6 py-4 border-b border-[var(--color-cyber-border)] bg-[var(--color-cyber-card-hover)]/30">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 className="text-lg font-medium text-[var(--color-cyber-text)]">Live Traffic Flows</h3>
            <p className="text-xs text-[var(--color-cyber-muted)] mt-1">
              {liveTraffic.length} recent flows · {wsConnected ? 'Connected' : 'Disconnected'}
            </p>
          </div>
          <div className="flex items-center gap-3">
            <span className={`inline-flex items-center rounded-full px-2.5 py-1 text-xs font-semibold ${wsConnected ? 'bg-[var(--color-cyber-neon)]/15 text-[var(--color-cyber-neon)]' : 'bg-[var(--color-cyber-warning)]/15 text-[var(--color-cyber-warning)]'}`}>
              <span className={`inline-block h-2.5 w-2.5 rounded-full ${wsConnected ? 'bg-[var(--color-cyber-neon)]' : 'bg-[var(--color-cyber-warning)]'}`} />
              <span className="ml-2">{wsConnected ? 'Live' : 'Offline'}</span>
            </span>
            {lastTrafficAt && (
              <span className="text-xs text-[var(--color-cyber-muted)]">Updated {formatTimestamp(lastTrafficAt)}</span>
            )}
            {liveTrafficLoading && !liveTraffic.length && (
              <div className="h-4 w-4 border-2 border-[var(--color-cyber-blue)] border-t-transparent rounded-full animate-spin" />
            )}
          </div>
        </div>
      </div>

      {liveTrafficError && (
        <div className="mx-6 mt-4 px-4 py-3 rounded-lg bg-[var(--color-cyber-danger)]/10 border border-[var(--color-cyber-danger)]/30 text-[var(--color-cyber-danger)] text-sm">
          {liveTrafficError}
        </div>
      )}

      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-[var(--color-cyber-border)]">
              <th className="px-6 py-3 text-left text-xs font-medium text-[var(--color-cyber-muted)] uppercase tracking-wider">Timestamp</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-[var(--color-cyber-muted)] uppercase tracking-wider">Source</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-[var(--color-cyber-muted)] uppercase tracking-wider">Destination</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-[var(--color-cyber-muted)] uppercase tracking-wider">Proto</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-[var(--color-cyber-muted)] uppercase tracking-wider">Pkt/s</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-[var(--color-cyber-muted)] uppercase tracking-wider">Bytes/s</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[var(--color-cyber-border)]">
            {liveTraffic.length === 0 && !liveTrafficLoading && (
              <tr>
                <td colSpan={6} className="px-6 py-8 text-center text-[var(--color-cyber-muted)]">
                  No live traffic flows available
                </td>
              </tr>
            )}
            {liveTraffic.map((flow, idx) => (
              <tr key={`${flow.flow_id}-${idx}`} className="hover:bg-[var(--color-cyber-card-hover)]/60 transition-colors">
                <td className="px-6 py-3 font-mono text-xs text-[var(--color-cyber-muted)] whitespace-nowrap">{formatTimestamp(flow.timestamp)}</td>
                <td className="px-6 py-3 text-xs text-[var(--color-cyber-text)]">{flow.src_ip}:{flow.src_port ?? '—'}</td>
                <td className="px-6 py-3 text-xs text-[var(--color-cyber-text)]">{flow.dst_ip}:{flow.dst_port ?? '—'}</td>
                <td className="px-6 py-3 text-xs text-[var(--color-cyber-blue)]">{flow.protocol ?? '—'}</td>
                <td className="px-6 py-3 font-mono text-xs text-[var(--color-cyber-text)]">{flow.packet_rate?.toFixed?.(1) ?? '—'}</td>
                <td className="px-6 py-3 font-mono text-xs text-[var(--color-cyber-text)]">{flow.byte_rate?.toFixed?.(0) ?? '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default memo(LiveTrafficTable);
