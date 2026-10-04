import React from 'react';
import { useMemo, memo } from 'react';
import { useDashboard } from '../contexts/DashboardContext';

// Resolve a field value to a boolean "ok" status
const resolveOk = (value) => {
  if (value === 'ok' || value === true) return true;
  if (value === 'unavailable' || value === false) return false;
  if (value && typeof value === 'object') {
    // e.g. { status: 'error', reason: '...' }
    if (value.status === 'error') return false;
    if (value.status === 'ok') return true;
  }
  return false;
};

// Dot indicator
const StatusDot = ({ ok }) => (
  <span
    className="inline-block w-2.5 h-2.5 rounded-full flex-shrink-0"
    style={{
      backgroundColor: ok
        ? 'var(--color-cyber-neon)'
        : 'var(--color-cyber-danger)',
      boxShadow: ok
        ? '0 0 6px var(--color-cyber-neon)'
        : '0 0 6px var(--color-cyber-danger)',
    }}
    aria-label={ok ? 'ok' : 'error'}
  />
);

// Single row for a service
const HealthRow = ({ label, ok, detail }) => (
  <div className="flex items-center justify-between py-2 border-b border-[var(--color-cyber-border)] last:border-0">
    <div className="flex items-center gap-2">
      <StatusDot ok={ok} />
      <span className="text-sm text-[var(--color-cyber-text)]">{label}</span>
    </div>
    <div className="flex items-center gap-2">
      <span
        className="text-xs font-mono"
        style={{ color: ok ? 'var(--color-cyber-neon)' : 'var(--color-cyber-danger)' }}
      >
        {ok ? 'OK' : 'ERROR'}
      </span>
      {detail && (
        <span className="text-xs text-[var(--color-cyber-muted)] max-w-[160px] truncate" title={detail}>
          {detail}
        </span>
      )}
    </div>
  </div>
);

// Merge legacy detailed agent keys into the current five-pipeline contract.
const getMergedAgentStatus = (agents, key, members) => {
  const directStatus = agents?.[key];
  const legacyStatuses = members
    .map((member) => agents?.[member])
    .filter((value) => value !== undefined);

  const statuses = directStatus !== undefined ? [directStatus] : legacyStatuses;

  // For the merged pipeline, all child members must be healthy for the group to be healthy.
  const ok = statuses.length > 0 ? statuses.every((status) => resolveOk(status)) : false;
  return { key, label: `Agent (${key})`, ok };
};

// Build a flat list of display rows from the health response
const buildRows = (health) => {
  const rows = [];

  // database
  const db = health.database;
  if (db !== undefined) {
    const ok = resolveOk(db);
    const detail = db && typeof db === 'object' && db.reason ? db.reason : undefined;
    rows.push({ key: 'database', label: 'Database', ok, detail });
  }

  // ml_models — show supervised/LightGBM and IF statuses.
  const ml = health.ml_models;
  if (ml && typeof ml === 'object') {
    const lightgbmVal = ml.lightgbm !== undefined ? ml.lightgbm : ml.supervised;
    if (lightgbmVal !== undefined) {
      rows.push({
        key: 'ml_lightgbm',
        label: 'ML Model (LightGBM)',
        ok: resolveOk(lightgbmVal),
        detail: undefined,
      });
    }
    if (Object.prototype.hasOwnProperty.call(ml, 'if')) {
      rows.push({
        key: 'ml_if',
        label: 'ML Model (IF)',
        ok: resolveOk(ml.if),
        detail: undefined,
      });
    }
  }

  // ollama
  const ollama = health.ollama;
  if (ollama !== undefined) {
    rows.push({ key: 'ollama', label: 'Ollama', ok: resolveOk(ollama), detail: undefined });
  }

  // agents — always render the full current five-agent contract.
  const agents = health.agents;
  if (agents && typeof agents === 'object') {
    const legacyGroups = [
      getMergedAgentStatus(agents, 'traffic', ['traffic']),
      getMergedAgentStatus(agents, 'analysis', ['analysis', 'detection', 'anomaly']),
      getMergedAgentStatus(agents, 'orchestrator', ['orchestrator', 'risk']),
      getMergedAgentStatus(agents, 'response', ['response', 'prevention', 'healing']),
      getMergedAgentStatus(agents, 'observability', ['observability', 'logging', 'reporting']),
    ];

    rows.push(
      ...legacyGroups.map((group) => ({
        key: `agent_${group.key}`,
        label: group.label,
        ok: group.ok,
        detail: undefined,
      }))
    );
  }

  return rows;
};

const SystemHealth = () => {
  const { health, healthLoading, healthError } = useDashboard();
  const loading = healthLoading && !health;
  const error = healthError;
  const rows = useMemo(() => (health ? buildRows(health) : []), [health]);

  // Overall status badge
  const overallOk = health?.status === 'healthy';

  return (
    <div className="glass-panel overflow-hidden">
      {/* Header */}
      <div className="px-6 py-4 border-b border-[var(--color-cyber-border)] bg-[var(--color-cyber-card-hover)]/30 flex items-center justify-between">
        <h3 className="text-lg font-medium text-[var(--color-cyber-text)]">System Health</h3>
        <div className="flex items-center gap-2">
          {loading && !health && !error && (
            <div className="h-4 w-4 border-2 border-[var(--color-cyber-blue)] border-t-transparent rounded-full animate-spin" />
          )}
          {health && (
            <span
              className="text-xs font-semibold px-2 py-0.5 rounded border"
              style={{
                color: overallOk ? 'var(--color-cyber-neon)' : 'var(--color-cyber-warning)',
                borderColor: overallOk ? 'var(--color-cyber-neon)' : 'var(--color-cyber-warning)',
                backgroundColor: overallOk
                  ? 'rgba(57,255,20,0.08)'
                  : 'rgba(255,176,0,0.08)',
              }}
            >
              {health.status?.toUpperCase() ?? 'UNKNOWN'}
            </span>
          )}
        </div>
      </div>

      {/* Error */}
      {error && (
        <div className="mx-6 mt-4 px-4 py-3 rounded-lg bg-[var(--color-cyber-danger)]/10 border border-[var(--color-cyber-danger)]/30 text-[var(--color-cyber-danger)] text-sm">
          {error}
        </div>
      )}

      {/* Rows */}
      {!error && (
        <div className="px-6 py-2">
          {rows.length === 0 && !loading && (
            <p className="text-[var(--color-cyber-muted)] text-sm py-4 text-center">
              No health data available
            </p>
          )}
          {rows.map((row) => (
            <HealthRow key={row.key} label={row.label} ok={row.ok} detail={row.detail} />
          ))}
        </div>
      )}
    </div>
  );
};

export default memo(SystemHealth);
