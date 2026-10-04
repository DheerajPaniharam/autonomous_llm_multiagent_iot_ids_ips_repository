import React from 'react';
import { useMemo, memo, useState, useEffect } from 'react';
import { 
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, ResponsiveContainer,
  LineChart, Line, Legend
} from 'recharts';
import { 
  ShieldCheck, 
  Activity, 
  Zap,
  ServerCrash
} from 'lucide-react';
import { useDashboard } from '../contexts/DashboardContext';
import Card from '../components/Card';
import AlertsTable from '../components/AlertsTable';
import AttackChart from '../components/AttackChart';
import LiveTrafficTable from '../components/LiveTrafficTable';
import RiskScoreCard from '../components/RiskScoreCard';
import SystemHealth from '../components/SystemHealth';

const StatCard = memo(({ title, value, icon: Icon, colorClass, hoverGlowClass }) => (
  <div className="glass-panel p-6 flex items-center gap-4 transition-all duration-300 hover:-translate-y-1 hover:shadow-[0_8px_30px_rgb(0_0_0_/_0.3),_0_0_20px_var(--glow-color,transparent)]"
       style={{ '--glow-color': hoverGlowClass }}>
    <div className={`p-3 rounded-xl ${colorClass} flex items-center justify-center`}>
      <Icon className="w-6 h-6" />
    </div>
    <div>
      <p className="text-[var(--color-cyber-muted)] text-xs font-semibold uppercase tracking-wider">{title}</p>
      <p className="text-2xl font-bold text-[var(--color-cyber-text)] mt-0.5 tracking-tight font-mono">{value}</p>
    </div>
  </div>
));

const ChartPlaceholder = () => (
  <div className="flex h-full min-h-[300px] w-full items-center justify-center rounded-xl border border-dashed border-[var(--color-cyber-muted)] bg-[rgba(255,255,255,0.03)]">
    <p className="text-[var(--color-cyber-muted)]">Loading chart data…</p>
  </div>
);

const LatencyChart = memo(({ data, ready }) => (
  <Card title="ML Pipeline Latency (ms)">
    <div className="h-[320px] w-full">
      {ready ? (
        <ResponsiveContainer width="100%" height={320}>
          <BarChart data={data} margin={{ top: 20, right: 30, left: 0, bottom: 5 }}>
            <CartesianGrid strokeDasharray="3 3" vertical={false} />
            <XAxis dataKey="name" />
            <YAxis />
            <RechartsTooltip cursor={{ fill: 'rgba(255,255,255,0.05)' }} />
            <Legend />
            <Bar dataKey="LightGBM" name="LightGBM (Detection)" fill="var(--color-cyber-blue)" radius={[4, 4, 0, 0]} />
            <Bar dataKey="IF" name="Isolation Forest (Anomaly)" fill="var(--color-cyber-purple)" radius={[4, 4, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      ) : (
        <ChartPlaceholder />
      )}
    </div>
  </Card>
));

const QueueDepthChart = memo(({ data, ready }) => (
  <Card title="Agent Queue Depths">
    <div className="h-[320px] w-full">
      {ready ? (
        <ResponsiveContainer width="100%" height={320}>
          <LineChart data={data} margin={{ top: 20, right: 30, left: 0, bottom: 5 }}>
            <CartesianGrid strokeDasharray="3 3" vertical={false} />
            <XAxis dataKey="name" />
            <YAxis />
            <RechartsTooltip />
            <Line
              type="monotone"
              dataKey="depth"
              stroke="var(--color-cyber-neon)"
              strokeWidth={3}
              dot={{ r: 4, fill: 'var(--color-cyber-dark)', strokeWidth: 2 }}
              activeDot={{ r: 6 }}
            />
          </LineChart>
        </ResponsiveContainer>
      ) : (
        <ChartPlaceholder />
      )}
    </div>
  </Card>
));

const ThroughputChart = memo(({ data, ready }) => (
  <Card title="Agent Throughput (Events Processed)">
    <div className="h-[320px] w-full">
      {ready ? (
        <ResponsiveContainer width="100%" height={320}>
          <BarChart data={data} margin={{ top: 20, right: 30, left: 0, bottom: 5 }}>
            <CartesianGrid strokeDasharray="3 3" vertical={false} />
            <XAxis dataKey="name" />
            <YAxis />
            <RechartsTooltip cursor={{ fill: 'rgba(255,255,255,0.05)' }} />
            <Bar dataKey="processed" name="Events Processed" fill="var(--color-cyber-neon)" radius={[4, 4, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      ) : (
        <ChartPlaceholder />
      )}
    </div>
  </Card>
));

const NetworkThroughputChart = memo(({ data, ready }) => (
  <Card title="Live Network Throughput">
    <div className="h-[320px] w-full">
      {ready ? (
        <ResponsiveContainer width="100%" height={320}>
          <LineChart data={data} margin={{ top: 20, right: 30, left: 0, bottom: 5 }}>
            <CartesianGrid strokeDasharray="3 3" vertical={false} />
            <XAxis dataKey="time" />
            <YAxis yAxisId="left" orientation="left" stroke="var(--color-cyber-blue)" label={{ value: 'kbps', angle: -90, position: 'insideLeft' }} />
            <YAxis yAxisId="right" orientation="right" stroke="var(--color-cyber-warning)" label={{ value: 'pps', angle: 90, position: 'insideRight' }} />
            <RechartsTooltip />
            <Legend />
            <Line
              yAxisId="left"
              type="monotone"
              dataKey="kbps"
              name="Throughput (kbps)"
              stroke="var(--color-cyber-blue)"
              strokeWidth={3}
              dot={false}
            />
            <Line
              yAxisId="right"
              type="monotone"
              dataKey="pps"
              name="Throughput (pps)"
              stroke="var(--color-cyber-warning)"
              strokeWidth={2}
              dot={false}
            />
          </LineChart>
        </ResponsiveContainer>
      ) : (
        <ChartPlaceholder />
      )}
    </div>
  </Card>
));

const Dashboard = () => {
  if (import.meta.env.DEV) {
    console.count("Dashboard Render");
  }
  const { metrics } = useDashboard();

  const [networkHistory, setNetworkHistory] = useState([]);

  useEffect(() => {
    if (metrics?.network_throughput) {
      const newPoint = {
        time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
        kbps: metrics.network_throughput.kbps ?? 0,
        pps: metrics.network_throughput.pps ?? 0,
      };
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setNetworkHistory((prev) => {
        const next = [...prev, newPoint];
        if (next.length > 20) {
          next.shift();
        }
        return next;
      });
    }
  }, [metrics?.network_throughput]);

  const queueData = useMemo(() => {
    if (!metrics?.queue_depths) return [];
    return [
      { name: 'Traffic', depth: 0 },
      { name: 'Analysis', depth: (metrics.queue_depths.detection ?? 0) + (metrics.queue_depths.anomaly ?? 0) },
      { name: 'Orchestrator', depth: metrics.queue_depths.orchestrator ?? metrics.queue_depths.risk ?? 0 },
      { name: 'Response', depth: (metrics.queue_depths.prevention ?? 0) + (metrics.queue_depths.healing ?? 0) },
      { name: 'Observability', depth: metrics.queue_depths.logging ?? 0 },
    ];
  }, [metrics?.queue_depths]);

  const latencyData = useMemo(() => {
    if (!metrics?.ml_latency_ms) return [];
    return [
      { name: 'p50', LightGBM: metrics.ml_latency_ms?.lightgbm_p50 ?? 0, IF: metrics.ml_latency_ms?.if_p50 ?? 0 },
      { name: 'p95', LightGBM: metrics.ml_latency_ms?.lightgbm_p95 ?? 0, IF: metrics.ml_latency_ms?.if_p95 ?? 0 },
      { name: 'p99', LightGBM: metrics.ml_latency_ms?.lightgbm_p99 ?? 0, IF: metrics.ml_latency_ms?.if_p99 ?? 0 },
    ];
  }, [metrics]);

  const throughputData = useMemo(() => {
    if (!metrics?.agent_throughput) return [];
    return [
      { name: 'Traffic', processed: metrics.agent_throughput.TrafficAgent ?? 0 },
      { name: 'Analysis', processed: metrics.agent_throughput.AnalysisAgent ?? 0 },
      { name: 'Orchestrator', processed: metrics.agent_throughput.LLMOrchestrator ?? 0 },
      { name: 'Response', processed: metrics.agent_throughput.ResponseAgent ?? 0 },
      { name: 'Observability', processed: metrics.agent_throughput.ObservabilityAgent ?? 0 },
    ];
  }, [metrics]);

  const chartReady = useMemo(
    () => metrics !== null,
    [metrics]
  );

  // Show loading screen while fetching initial metrics
  if (!metrics) {
    return (
      <div className="flex h-screen items-center justify-center bg-gradient-to-b from-[var(--color-cyber-dark)] to-[var(--color-cyber-darker)]">
        <div className="flex flex-col items-center space-y-6">
          <div className="relative flex items-center justify-center w-16 h-16">
            <div className="absolute inset-0 rounded-full border-2 border-[var(--color-cyber-blue)]/20 animate-pulse"></div>
            <div className="h-12 w-12 border-4 border-[var(--color-cyber-blue)] border-t-[var(--color-cyber-neon)] rounded-full animate-spin"></div>
          </div>
          <div className="text-center">
            <p className="text-lg font-semibold text-[var(--color-cyber-text)]">Loading Dashboard</p>
            <p className="mt-2 text-sm text-[var(--color-cyber-muted)]">Initializing security gateway...</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold text-[var(--color-cyber-text)]">Overview</h2>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatCard 
          title="Events Processed" 
          value={metrics?.total_events_processed ? metrics.total_events_processed.toLocaleString() : '0'} 
          icon={Activity} 
          colorClass="bg-[var(--color-cyber-blue)]/10 text-[var(--color-cyber-blue)] border border-[var(--color-cyber-blue)]/20"
          hoverGlowClass="rgba(0,240,255,0.08)"
        />
        <StatCard 
          title="Active Incidents" 
          value={metrics?.active_incidents ?? '0'} 
          icon={ServerCrash} 
          colorClass="bg-[var(--color-cyber-danger)]/10 text-[var(--color-cyber-danger)] border border-[var(--color-cyber-danger)]/20"
          hoverGlowClass="rgba(255,0,60,0.08)"
        />
        <StatCard 
          title="Mitigations Applied" 
          value={metrics?.total_mitigations_applied ?? '0'} 
          icon={ShieldCheck} 
          colorClass="bg-[var(--color-cyber-neon)]/10 text-[var(--color-cyber-neon)] border border-[var(--color-cyber-neon)]/20"
          hoverGlowClass="rgba(57,255,20,0.08)"
        />
        <StatCard 
          title="Packet Drops" 
          value={metrics?.packet_drops ?? '0'} 
          icon={Zap} 
          colorClass="bg-[var(--color-cyber-warning)]/10 text-[var(--color-cyber-warning)] border border-[var(--color-cyber-warning)]/20"
          hoverGlowClass="rgba(255,176,0,0.08)"
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <LatencyChart data={latencyData} ready={chartReady} />
        <QueueDepthChart data={queueData} ready={chartReady} />
        <ThroughputChart data={throughputData} ready={chartReady} />
        <NetworkThroughputChart data={networkHistory} ready={chartReady} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-1">
          <RiskScoreCard />
        </div>
        <div className="lg:col-span-2">
          <SystemHealth />
        </div>
      </div>

      <div>
        <AttackChart />
      </div>

      <div>
        <LiveTrafficTable />
      </div>

      <div>
        <AlertsTable isDashboard={true} />
      </div>
    </div>
  );
};

export default Dashboard;
