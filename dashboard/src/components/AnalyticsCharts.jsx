import React from 'react';
import { useMemo, memo } from 'react';
import {
  PieChart, Pie, Cell, Legend, Tooltip as RechartsTooltip, ResponsiveContainer,
} from 'recharts';
import Card from './Card';

const COLORS = [
  'var(--color-cyber-danger)',
  'var(--color-cyber-warning)',
  'var(--color-cyber-blue)',
  'var(--color-cyber-neon)',
  'var(--color-cyber-purple)',
];

const ChartPlaceholder = () => (
  <div className="flex h-full min-h-[300px] w-full items-center justify-center rounded-xl border border-dashed border-[var(--color-cyber-muted)] bg-[rgba(255,255,255,0.03)]">
    <p className="text-[var(--color-cyber-muted)]">Loading chart data…</p>
  </div>
);

const AttackDistributionChart = memo(({ attacks, ready }) => {
  const data = useMemo(() => {
    if (!attacks || attacks.length === 0) return [];
    const distribution = {};
    attacks.forEach(attack => {
      const type = attack.attack_type || 'Unknown';
      distribution[type] = (distribution[type] || 0) + 1;
    });
    return Object.entries(distribution)
      .map(([name, value]) => ({ name, value }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 5);
  }, [attacks]);

  return (
    <Card title="Attack Type Distribution (Top 5)">
      <div className="h-[300px] w-full">
        {ready && data.length > 0 ? (
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={data}
                cx="50%"
                cy="50%"
                labelLine={false}
                label={({ name, value }) => `${name}: ${value}`}
                outerRadius={100}
                fill="#8884d8"
                dataKey="value"
              >
                {data.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                ))}
              </Pie>
              <RechartsTooltip formatter={(value) => `${value} attacks`} />
              <Legend />
            </PieChart>
          </ResponsiveContainer>
        ) : (
          <ChartPlaceholder />
        )}
      </div>
    </Card>
  );
});

const SeverityTimelineChart = memo(({ attacks, ready }) => {
  const data = useMemo(() => {
    if (!attacks || attacks.length === 0) return [];
    const now = attacks.reduce(
      (latest, attack) => Math.max(latest, Date.parse(attack.timestamp) || 0),
      0,
    );
    if (!now) return [];
    const timeRanges = [
      { label: '1h', min: now - 60 * 60 * 1000 },
      { label: '2h', min: now - 2 * 60 * 60 * 1000 },
      { label: '4h', min: now - 4 * 60 * 60 * 1000 },
      { label: '24h', min: now - 24 * 60 * 60 * 1000 },
    ];

    return timeRanges.map(({ label, min }) => {
      const inRange = attacks.filter(a => new Date(a.timestamp).getTime() > min);
      const critical = inRange.filter(a => a.composite_score >= 0.9).length;
      const high = inRange.filter(a => a.composite_score >= 0.75 && a.composite_score < 0.9).length;
      const medium = inRange.filter(a => a.composite_score >= 0.65 && a.composite_score < 0.75).length;

      return {
        time: label,
        critical,
        high,
        medium,
        total: inRange.length,
      };
    });
  }, [attacks]);

  return (
    <Card title="Threat Activity Timeline">
      <div className="h-[300px] w-full">
        {ready && data.length > 0 ? (
          <div className="space-y-3">
            {data.map(({ time, critical, high, medium, total }) => (
              <div key={time}>
                <div className="flex justify-between items-center mb-1">
                  <span className="text-sm text-[var(--color-cyber-muted)]">Last {time}</span>
                  <span className="text-xs font-mono text-[var(--color-cyber-text)]">{total} threats</span>
                </div>
                <div className="flex gap-1 h-6 rounded bg-[var(--color-cyber-darker)]/50 overflow-hidden">
                  {critical > 0 && (
                    <div
                      className="bg-[var(--color-cyber-danger)] flex items-center justify-center text-[10px] text-white font-bold"
                      style={{ width: `${(critical / total) * 100}%` }}
                      title={`Critical: ${critical}`}
                    >
                      {critical > 0 && critical}
                    </div>
                  )}
                  {high > 0 && (
                    <div
                      className="bg-[var(--color-cyber-warning)] flex items-center justify-center text-[10px] text-white font-bold"
                      style={{ width: `${(high / total) * 100}%` }}
                      title={`High: ${high}`}
                    >
                      {high > 0 && high}
                    </div>
                  )}
                  {medium > 0 && (
                    <div
                      className="bg-[var(--color-cyber-blue)] flex items-center justify-center text-[10px] text-white font-bold"
                      style={{ width: `${(medium / total) * 100}%` }}
                      title={`Medium: ${medium}`}
                    >
                      {medium > 0 && medium}
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        ) : (
          <ChartPlaceholder />
        )}
      </div>
    </Card>
  );
});

const RiskDistributionChart = memo(({ alerts }) => {
  const data = useMemo(() => {
    if (!alerts || alerts.length === 0) return [];
    const bins = [
      { range: '0.0-0.2', min: 0, max: 0.2, count: 0 },
      { range: '0.2-0.4', min: 0.2, max: 0.4, count: 0 },
      { range: '0.4-0.6', min: 0.4, max: 0.6, count: 0 },
      { range: '0.6-0.8', min: 0.6, max: 0.8, count: 0 },
      { range: '0.8-1.0', min: 0.8, max: 1.0, count: 0 },
    ];

    alerts.forEach(alert => {
      const score = alert.composite_score || 0;
      bins.forEach(bin => {
        if (score >= bin.min && score < bin.max) {
          bin.count++;
        }
      });
    });

    return bins.map(({ range, count }) => ({ name: range, count }));
  }, [alerts]);

  return (
    <Card title="Risk Score Distribution">
      <div className="space-y-3">
        {data.map(({ name, count }) => (
          <div key={name}>
            <div className="flex justify-between items-center mb-1">
              <span className="text-xs text-[var(--color-cyber-muted)]">{name}</span>
              <span className="text-xs font-mono text-[var(--color-cyber-text)]">{count}</span>
            </div>
            <div className="h-2 w-full rounded bg-[var(--color-cyber-darker)] overflow-hidden">
              <div
                className={`h-full transition-all ${
                  parseFloat(name) >= 0.75 ? 'bg-[var(--color-cyber-danger)]' :
                  parseFloat(name) >= 0.5 ? 'bg-[var(--color-cyber-warning)]' :
                  'bg-[var(--color-cyber-blue)]'
                }`}
                style={{ width: `${Math.min((count / Math.max(...data.map(d => d.count))) * 100, 100)}%` }}
              />
            </div>
          </div>
        ))}
      </div>
    </Card>
  );
});

export { AttackDistributionChart, SeverityTimelineChart, RiskDistributionChart };
