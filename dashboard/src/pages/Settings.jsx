import React from 'react';
import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { getConfig, updateConfig } from '../services/api';
import Card from '../components/Card';
import { Settings as SettingsIcon, Save, Loader2 } from 'lucide-react';

const Settings = () => {
  const [config, setConfig] = useState(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState('');

  const userRole = localStorage.getItem('userRole') || 'admin';
  const isAdmin = userRole === 'admin';
  const navigate = useNavigate();

  useEffect(() => {
    const fetchConfig = async () => {
      try {
        const data = await getConfig();
        setConfig(data);
      } catch (err) {
        console.error("Failed to fetch config", err);
      } finally {
        setLoading(false);
      }
    };
    fetchConfig();
  }, []);

  const handleSave = async (e) => {
    e.preventDefault();
    if (!isAdmin) return;
    // Client-side validation
    if (typeof config.detection_threshold !== 'number' || config.detection_threshold < 0 || config.detection_threshold > 1) {
      setMessage('Detection threshold must be a number between 0 and 1');
      return;
    }
    if (typeof config.anomaly_threshold !== 'number' || config.anomaly_threshold < 0 || config.anomaly_threshold > 1) {
      setMessage('Anomaly threshold must be a number between 0 and 1');
      return;
    }
    if (typeof config.composite_threshold !== 'number' || config.composite_threshold < 0 || config.composite_threshold > 1) {
      setMessage('Composite threshold must be a number between 0 and 1');
      return;
    }

    const prevConfig = { ...config };

    setSaving(true);
    setMessage('');
    try {
      await updateConfig(config);
      setMessage('Configuration updated successfully.');
    } catch (err) {
      console.error("Failed to update config", err);
      setMessage('Failed to update configuration. Rolling back changes.');
      // roll back UI state
      setConfig(prevConfig);
    } finally {
      setSaving(false);
      setTimeout(() => setMessage(''), 3000);
    }
  };

  const handleChange = (e) => {
    const { name, value, type, checked } = e.target;
    setConfig(prev => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : type === 'number' ? parseFloat(value) : value
    }));
  };

  if (loading) return <div className="p-8 text-center text-[var(--color-cyber-muted)]">Loading system configuration...</div>;
  if (!config) return <div className="p-8 text-center text-[var(--color-cyber-danger)]">Failed to load configuration.</div>;

  return (
    <Card title={
      <div className="flex items-center gap-2 text-[var(--color-cyber-text)]">
        <SettingsIcon className="w-5 h-5 text-[var(--color-cyber-blue)]" />
        <span>System Parameters</span>
      </div>
    }>
      {!isAdmin && (
        <div className="mb-6 p-4 rounded-lg bg-[var(--color-cyber-warning)]/10 text-[var(--color-cyber-warning)] border border-[var(--color-cyber-warning)]/30 text-sm">
          You are viewing this page in read-only mode. Only administrators can modify system parameters.
        </div>
      )}

      {message && (
        <div className={`mb-6 p-4 rounded-lg text-sm border ${message.includes('success') ? 'bg-[var(--color-cyber-neon)]/10 text-[var(--color-cyber-neon)] border-[var(--color-cyber-neon)]/30' : 'bg-[var(--color-cyber-danger)]/10 text-[var(--color-cyber-danger)] border-[var(--color-cyber-danger)]/30'}`}>
          {message}
        </div>
      )}

      <form onSubmit={handleSave} className="space-y-8">
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
          {/* ML Thresholds */}
          <div className="space-y-4">
            <h4 className="text-sm uppercase tracking-wider text-[var(--color-cyber-muted)] font-semibold border-b border-[var(--color-cyber-border)] pb-2">ML Thresholds</h4>
            
            <div>
              <label className="block text-sm text-[var(--color-cyber-text)] mb-1">Detection Threshold (LightGBM)</label>
              <input 
                type="number" step="0.01" min="0" max="1" name="detection_threshold"
                value={config.detection_threshold} onChange={handleChange} disabled={!isAdmin}
                className="cyber-input"
              />
            </div>
            
            <div>
              <label className="block text-sm text-[var(--color-cyber-text)] mb-1">Anomaly Threshold (IF)</label>
              <input 
                type="number" step="0.01" min="0" max="1" name="anomaly_threshold"
                value={config.anomaly_threshold} onChange={handleChange} disabled={!isAdmin}
                className="cyber-input"
              />
            </div>

            <div>
              <label className="block text-sm text-[var(--color-cyber-text)] mb-1">Composite Risk Threshold</label>
              <input 
                type="number" step="0.01" min="0" max="1" name="composite_threshold"
                value={config.composite_threshold} onChange={handleChange} disabled={!isAdmin}
                className="cyber-input"
              />
            </div>
          </div>

          {/* System Settings */}
          <div className="space-y-4">
            <h4 className="text-sm uppercase tracking-wider text-[var(--color-cyber-muted)] font-semibold border-b border-[var(--color-cyber-border)] pb-2">System Operations</h4>
            
            <div className="flex items-center justify-between p-3 rounded-lg bg-[var(--color-cyber-darker)] border border-[var(--color-cyber-border)]">
              <label className="text-sm text-[var(--color-cyber-text)]">Privacy Mode</label>
              <input 
                type="checkbox" name="privacy_mode"
                checked={config.privacy_mode} onChange={handleChange} disabled={!isAdmin}
                className="w-4 h-4 accent-[var(--color-cyber-blue)]"
              />
            </div>

            <div className="flex items-center justify-between p-3 rounded-lg bg-[var(--color-cyber-darker)] border border-[var(--color-cyber-border)]">
              <label className="text-sm text-[var(--color-cyber-text)]">Signature Updates Enabled</label>
              <input 
                type="checkbox" name="signature_updates_enabled"
                checked={config.signature_updates_enabled} onChange={handleChange} disabled={!isAdmin}
                className="w-4 h-4 accent-[var(--color-cyber-blue)]"
              />
            </div>

            <div className="flex items-center justify-between p-3 rounded-lg bg-[var(--color-cyber-darker)] border border-[var(--color-cyber-border)]">
              <label className="text-sm text-[var(--color-cyber-text)]">Threat Intel Enabled</label>
              <input 
                type="checkbox" name="threat_intel_enabled"
                checked={config.threat_intel_enabled} onChange={handleChange} disabled={!isAdmin}
                className="w-4 h-4 accent-[var(--color-cyber-blue)]"
              />
            </div>
          </div>
        </div>

        {isAdmin && (
          <div className="flex justify-end border-t border-[var(--color-cyber-border)] pt-6">
            <button 
              type="submit" disabled={saving}
              className="cyber-button cyber-button-primary flex items-center gap-2"
            >
              {saving ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
              Apply Configuration
            </button>
          </div>
        )}
          <div className="mt-4 text-sm">
            <button onClick={() => navigate('/audit-logs')} className="text-xs text-[var(--color-cyber-blue)] underline">View configuration audit trail</button>
          </div>
      </form>
    </Card>
  );
};

export default Settings;
