import React from 'react';
import { useMemo, memo } from 'react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from 'recharts';
import { useDashboard } from '../contexts/DashboardContext';

// Palette for attack types — cycles through cyber theme colors
const ATTACK_COLORS = [
  'var(--color-cyber-blue)',
  'var(--color-cyber-purple)',
  'var(--color-cyber-neon)',
  'var(--color-cyber-warning)',
  'var(--color-cyber-danger)',
  '#a78bfa', // violet-400
  '#34d399', // emerald-400
  '#f472b6', // pink-400
];

/**
 * Returns an ISO hour-bucket string like "2024-01-15 14:00"
 */
const toHourBucket = (ts) => {
  const d = new Date(ts);
  const yyyy = d.getFullYear();
  const mm = String(d.getMonth() + 1).padStart(2, '0');
  const dd = String(d.getDate()).padStart(2, '0');
  const hh = String(d.getHours()).padStart(2, '0');
  return `${yyyy}-${mm}-${dd} ${hh}:00`;
};

/**
 * Builds chart data from raw alerts.
 * Returns { chartData, attackTypes } where chartData is an array of
 * { hour, [attackType]: count, ... } objects sorted by hour ascending.
 */
const buildChartData = (alerts) => {
  const now = Date.now();
  const cutoff = now - 24 * 60 * 60 * 1000;

  // Filter to last 24 hours
  const recent = alerts.filter((a) => {
    const t = new Date(a.timestamp).getTime();
    return !isNaN(t) && t >= cutoff;
  });

  // Collect unique attack types
  const attackTypeSet = new Set();
  recent.forEach((a) => {
    if (a.attack_type) attackTypeSet.add(a.attack_type);
  });
  const attackTypes = Array.from(attackTypeSet).sort();

  // Group by hour bucket
  const bucketMap = {};
  recent.forEach((a) => {
    const bucket = toHourBucket(a.timestamp);
    if (!bucketMap[bucket]) {
      bucketMap[bucket] = { hour: bucket };
    }
    const type = a.attack_type || 'unknown';
    bucketMap[bucket][type] = (bucketMap[bucket][type] || 0) + 1;
  });

  // Sort buckets chronologically
  const chartData = Object.values(bucketMap).sort((a, b) =>
    a.hour.localeCompare(b.hour)
  );

  return { chartData, attackTypes };
};

const AttackChart = () => {
  const { alerts, alertsLoading, alertsError } = useDashboard();

  const { chartData, attackTypes } = useMemo(() => buildChartData(alerts), [alerts]);
  const loading = alertsLoading && alerts.length === 0;
  const error = alertsError;

  return (
    <div className="glass-panel overflow-hidden">
      {/* Header */}
      <div className="px-6 py-4 border-b border-[var(--color-cyber-border)] bg-[var(--color-cyber-card-hover)]/30 flex items-center justify-between">
        <h3 className="text-lg font-medium text-[var(--color-cyber-text)]">
          Attacks by Type — Last 24 Hours
        </h3>
        {loading && !chartData.length && (
          <div className="h-4 w-4 border-2 border-[var(--color-cyber-blue)] border-t-transparent rounded-full animate-spin" />
        )}
      </div>

      <div className="p-6">
        {/* Error */}
        {error && (
          <div className="mb-4 px-4 py-3 rounded-lg bg-[var(--color-cyber-danger)]/10 border border-[var(--color-cyber-danger)]/30 text-[var(--color-cyber-danger)] text-sm">
            {error}
          </div>
        )}

        {/* Empty state */}
        {!loading && !error && chartData.length === 0 && (
          <div className="flex items-center justify-center h-64 text-[var(--color-cyber-muted)]">
            No attack data in the last 24 hours
          </div>
        )}

        {/* Chart */}
        {chartData.length > 0 && (
          <div className="h-80">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={chartData}
                margin={{ top: 20, right: 30, left: 0, bottom: 60 }}
              >
                <CartesianGrid strokeDasharray="3 3" vertical={false} />
                <XAxis
                  dataKey="hour"
                  tick={{ fontSize: 11 }}
                  angle={-35}
                  textAnchor="end"
                  interval="preserveStartEnd"
                />
                <YAxis allowDecimals={false} />
                <Tooltip
                  cursor={{ fill: 'rgba(255,255,255,0.05)' }}
                  contentStyle={{
                    backgroundColor: 'rgba(19, 26, 40, 0.95)',
                    border: '1px solid var(--color-cyber-border)',
                    borderRadius: '0.5rem',
                    backdropFilter: 'blur(8px)',
                  }}
                  labelStyle={{ color: 'var(--color-cyber-text)', marginBottom: 4 }}
                  itemStyle={{ color: 'var(--color-cyber-muted)' }}
                />
                <Legend
                  wrapperStyle={{ paddingTop: 16, fontSize: 12 }}
                />
                {attackTypes.map((type, idx) => (
                  <Bar
                    key={type}
                    dataKey={type}
                    name={type}
                    stackId="attacks"
                    fill={ATTACK_COLORS[idx % ATTACK_COLORS.length]}
                    radius={idx === attackTypes.length - 1 ? [4, 4, 0, 0] : [0, 0, 0, 0]}
                  />
                ))}
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}
      </div>
    </div>
  );
};

export default memo(AttackChart);
