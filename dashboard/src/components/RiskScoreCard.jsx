import React from 'react';
import { useMemo, memo } from 'react';
import { useDashboard } from '../contexts/DashboardContext';

// Determine colour and label based on composite_score thresholds
const getScoreStyle = (score) => {
  if (score >= 0.9) {
    return {
      color: 'var(--color-cyber-danger)',
      label: 'CRITICAL',
      bgClass: 'bg-[var(--color-cyber-danger)]/10 border-[var(--color-cyber-danger)]/40',
    };
  }
  if (score >= 0.65) {
    return {
      color: 'var(--color-cyber-warning)',
      label: 'ELEVATED',
      bgClass: 'bg-[var(--color-cyber-warning)]/10 border-[var(--color-cyber-warning)]/40',
    };
  }
  return {
    color: 'var(--color-cyber-neon)',
    label: 'NORMAL',
    bgClass: 'bg-[var(--color-cyber-neon)]/10 border-[var(--color-cyber-neon)]/40',
  };
};

const RiskScoreCard = () => {
  const { alerts, alertsLoading, alertsError } = useDashboard();

  const topScore = useMemo(() => {
    if (!alerts?.length) return null;
    const fiveMinutesAgo = Date.now() - 5 * 60 * 1000;
    const recent = alerts.filter((alert) => {
      const ts = alert.timestamp ? new Date(alert.timestamp).getTime() : 0;
      return ts >= fiveMinutesAgo;
    });

    if (recent.length === 0) return null;

    return recent.reduce((max, alert) => {
      const score = typeof alert.composite_score === 'number' ? alert.composite_score : 0;
      return score > max ? score : max;
    }, 0);
  }, [alerts]);

  const loading = alertsLoading && alerts.length === 0;
  const error = alertsError;
  const style = topScore !== null ? getScoreStyle(topScore) : null;

  return (
    <div className="glass-panel overflow-hidden">
      {/* Header */}
      <div className="px-6 py-4 border-b border-[var(--color-cyber-border)] bg-[var(--color-cyber-card-hover)]/30 flex items-center justify-between">
        <h3 className="text-lg font-medium text-[var(--color-cyber-text)]">Risk Score</h3>
        {loading && topScore === null && !error && (
          <div className="h-4 w-4 border-2 border-[var(--color-cyber-blue)] border-t-transparent rounded-full animate-spin" />
        )}
      </div>

      {/* Error */}
      {error && (
        <div className="mx-6 mt-4 px-4 py-3 rounded-lg bg-[var(--color-cyber-danger)]/10 border border-[var(--color-cyber-danger)]/30 text-[var(--color-cyber-danger)] text-sm">
          {error}
        </div>
      )}

      {/* Body */}
      <div className="p-6 flex flex-col items-center justify-center gap-3">
        {!error && topScore === null && !loading && (
          <p className="text-[var(--color-cyber-muted)] text-sm">No recent threats</p>
        )}

        {!error && topScore !== null && style && (
          <>
            {/* Score ring / display */}
            <div
              className={`flex flex-col items-center justify-center w-32 h-32 rounded-full border-2 ${style.bgClass}`}
              style={{ borderColor: style.color }}
            >
              <span
                className="text-3xl font-bold font-mono tabular-nums"
                style={{ color: style.color }}
              >
                {topScore.toFixed(2)}
              </span>
              <span
                className="text-xs font-semibold tracking-widest mt-1"
                style={{ color: style.color }}
              >
                {style.label}
              </span>
            </div>

            <p className="text-xs text-[var(--color-cyber-muted)] text-center">
              Highest composite score in the last 5 minutes
            </p>
          </>
        )}
      </div>
    </div>
  );
};

export default memo(RiskScoreCard);
