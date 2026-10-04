import React from 'react';
import { useState } from 'react';
import { getReports, getReport } from '../services/api';
import Card from '../components/Card';
import { FileText, Download, Loader2, RefreshCw } from 'lucide-react';

const REPORT_TYPES = [
  { value: 'daily',   label: 'Daily Report' },
  { value: 'weekly',  label: 'Weekly Report' },
  { value: 'monthly', label: 'Monthly Report' },
];

const StatRow = ({ label, value }) => (
  <div className="flex justify-between items-center py-2 border-b border-[var(--color-cyber-border)] last:border-0">
    <span className="text-sm text-[var(--color-cyber-muted)]">{label}</span>
    <span className="text-sm font-semibold text-[var(--color-cyber-text)]">{value ?? '—'}</span>
  </div>
);

const Reports = () => {
  const [reportType, setReportType] = useState('daily');
  const [year, setYear]   = useState(new Date().getFullYear());
  const [month, setMonth] = useState(new Date().getMonth() + 1);
  const [report, setReport]   = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState('');

  const handleGenerate = async () => {
    setLoading(true);
    setError('');
    setReport(null);
    try {
      const params = { type: reportType };
      if (reportType === 'monthly') {
        params.year  = year;
        params.month = month;
      }
      // getReports returns metadata; then fetch full report by id
      const listData = await getReports(params);
      if (listData.reports && listData.reports.length > 0) {
        const meta = listData.reports[0];
        const full = await getReport(meta.id);
        setReport(full);
      } else {
        setError('No report data returned.');
      }
    } catch (err) {
      console.error('Report generation failed', err);
      setError(err?.response?.data?.detail || 'Failed to generate report.');
    } finally {
      setLoading(false);
    }
  };

  const handleDownloadCSV = async () => {
    if (!report) return;
    try {
      const blob = await getReport(report.id, 'csv');
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${report.id}.csv`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Download failed', err);
    }
  };

  return (
    <div className="space-y-6">
      {/* Controls */}
      <Card title={
        <div className="flex items-center gap-2">
          <FileText className="w-5 h-5 text-[var(--color-cyber-blue)]" />
          <span>Generate Security Report</span>
        </div>
      }>
        <div className="flex flex-wrap gap-4 items-end">
          {/* Report type */}
          <div className="flex flex-col gap-1">
            <label className="text-xs text-[var(--color-cyber-muted)] uppercase tracking-wider">Type</label>
            <select
              value={reportType}
              onChange={e => setReportType(e.target.value)}
              className="cyber-input min-w-[160px]"
            >
              {REPORT_TYPES.map(t => (
                <option key={t.value} value={t.value}>{t.label}</option>
              ))}
            </select>
          </div>

          {/* Year / Month — only for monthly */}
          {reportType === 'monthly' && (
            <>
              <div className="flex flex-col gap-1">
                <label className="text-xs text-[var(--color-cyber-muted)] uppercase tracking-wider">Year</label>
                <input
                  type="number" min="2020" max="2100"
                  value={year} onChange={e => setYear(Number(e.target.value))}
                  className="cyber-input w-24"
                />
              </div>
              <div className="flex flex-col gap-1">
                <label className="text-xs text-[var(--color-cyber-muted)] uppercase tracking-wider">Month</label>
                <input
                  type="number" min="1" max="12"
                  value={month} onChange={e => setMonth(Number(e.target.value))}
                  className="cyber-input w-20"
                />
              </div>
            </>
          )}

          <button
            onClick={handleGenerate}
            disabled={loading}
            className="cyber-button cyber-button-primary flex items-center gap-2"
          >
            {loading
              ? <Loader2 className="w-4 h-4 animate-spin" />
              : <RefreshCw className="w-4 h-4" />
            }
            {loading ? 'Generating…' : 'Generate'}
          </button>
        </div>

        {error && (
          <p className="mt-4 text-sm text-[var(--color-cyber-danger)]">{error}</p>
        )}
      </Card>

      {/* Report output */}
      {report && (
        <Card title={
          <div className="flex items-center justify-between w-full">
            <span className="capitalize">{report.report_type} Report — {report.period_start} → {report.period_end}</span>
            <button
              onClick={handleDownloadCSV}
              className="cyber-button flex items-center gap-1 text-xs px-3 py-1"
            >
              <Download className="w-3 h-3" />
              Download JSON
            </button>
          </div>
        }>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
            {/* Summary */}
            <div>
              <h4 className="text-xs uppercase tracking-wider text-[var(--color-cyber-muted)] mb-3">Summary</h4>
              <StatRow label="Total Events"      value={report.total_events?.toLocaleString()} />
              <StatRow label="Total Mitigations" value={report.total_mitigations?.toLocaleString()} />
              <StatRow label="Generated At"      value={new Date(report.generated_at).toLocaleString()} />
            </div>

            {/* Attack breakdown */}
            <div>
              <h4 className="text-xs uppercase tracking-wider text-[var(--color-cyber-muted)] mb-3">Attack Breakdown</h4>
              {report.attack_counts && Object.keys(report.attack_counts).length > 0
                ? Object.entries(report.attack_counts)
                    .sort(([, a], [, b]) => b - a)
                    .map(([type, count]) => (
                      <StatRow key={type} label={type} value={count.toLocaleString()} />
                    ))
                : <p className="text-sm text-[var(--color-cyber-muted)]">No attacks recorded in this period.</p>
              }
            </div>

            {/* MTTD */}
            <div>
              <h4 className="text-xs uppercase tracking-wider text-[var(--color-cyber-muted)] mb-3">Mean Time to Detect (s)</h4>
              {report.mttd_by_type && Object.keys(report.mttd_by_type).length > 0
                ? Object.entries(report.mttd_by_type).map(([type, val]) => (
                    <StatRow key={type} label={type} value={Number(val).toFixed(2)} />
                  ))
                : <p className="text-sm text-[var(--color-cyber-muted)]">No data.</p>
              }
            </div>

            {/* MTTR */}
            <div>
              <h4 className="text-xs uppercase tracking-wider text-[var(--color-cyber-muted)] mb-3">Mean Time to Respond (s)</h4>
              {report.mttr_by_type && Object.keys(report.mttr_by_type).length > 0
                ? Object.entries(report.mttr_by_type).map(([type, val]) => (
                    <StatRow key={type} label={type} value={Number(val).toFixed(2)} />
                  ))
                : <p className="text-sm text-[var(--color-cyber-muted)]">No data.</p>
              }
            </div>
          </div>
        </Card>
      )}
    </div>
  );
};

export default Reports;
