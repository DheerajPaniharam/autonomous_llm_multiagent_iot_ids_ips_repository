import React from 'react';
import { useState, useEffect } from 'react';
import { getDevices, isolateDevice, releaseDevice } from '../services/api';
import { useToast } from '../contexts/ToastContext';
import Card from '../components/Card';
import { Server, ShieldCheck, Lock, Unlock, RefreshCw } from 'lucide-react';

const Devices = () => {
  const [devices, setDevices] = useState([]);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState(null);
  const [isolatedOnly, setIsolatedOnly] = useState(false);
  const { success, error } = useToast();

  const fetchDevices = async (isolated = false) => {
    try {
      setLoading(true);
      const data = await getDevices(50, 0, isolated || null);
      setDevices(data.devices);
    } catch (err) {
      console.error("Failed to fetch devices", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    fetchDevices(isolatedOnly);
  }, [isolatedOnly]);

  const handleIsolateDevice = async (deviceId) => {
    setActionLoading(deviceId);
    try {
      await isolateDevice(deviceId);
      await fetchDevices(isolatedOnly);
      success(`Device ${deviceId} has been isolated from the network`, 'Device Isolated');
    } catch (err) {
      console.error("Failed to isolate device", err);
      error(err.message, 'Isolation Failed');
    } finally {
      setActionLoading(null);
    }
  };

  const handleReleaseDevice = async (deviceId) => {
    setActionLoading(deviceId);
    try {
      await releaseDevice(deviceId);
      await fetchDevices(isolatedOnly);
      success(`Device ${deviceId} has been released and reconnected to the network`, 'Device Released');
    } catch (err) {
      console.error("Failed to release device", err);
      error(err.message, 'Release Failed');
    } finally {
      setActionLoading(null);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold text-[var(--color-cyber-text)]">IoT Device Inventory</h2>
        <button
          onClick={() => fetchDevices(isolatedOnly)}
          className="cyber-button cyber-button-secondary flex items-center gap-2"
          title="Refresh device list"
        >
          <RefreshCw className="w-4 h-4" />
          Refresh
        </button>
      </div>

      {/* Filter */}
      <div className="glass-panel p-4">
        <div className="flex items-center gap-3">
          <input
            type="checkbox"
            id="isolatedFilter"
            checked={isolatedOnly}
            onChange={(e) => setIsolatedOnly(e.target.checked)}
            className="w-4 h-4 cursor-pointer"
          />
          <label htmlFor="isolatedFilter" className="text-sm text-[var(--color-cyber-text)] cursor-pointer">
            Show only isolated devices ({devices.filter(d => d.is_isolated).length})
          </label>
        </div>
      </div>

      <Card title={
        <div className="flex items-center gap-2 text-[var(--color-cyber-text)]">
          <Server className="w-5 h-5 text-[var(--color-cyber-blue)]" />
          <span>Network Devices {isolatedOnly && '(Isolated)'}</span>
        </div>
      }>
        {loading ? (
          <div className="py-12 text-center text-[var(--color-cyber-muted)]">Scanning network for devices...</div>
        ) : devices.length === 0 ? (
          <div className="py-12 text-center text-[var(--color-cyber-muted)]">
            {isolatedOnly ? 'No isolated devices found.' : 'No devices found in the network.'}
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {devices.map((device) => (
              <div
                key={device.device_id}
                className={`glass-panel p-5 border transition-all ${
                  device.is_isolated
                    ? 'border-[var(--color-cyber-danger)]/50 bg-[var(--color-cyber-danger)]/5'
                    : 'border-[var(--color-cyber-border)]'
                }`}
              >
                <div className="flex justify-between items-start mb-4">
                  <div className={`p-2 rounded-lg ${device.is_isolated ? 'bg-[var(--color-cyber-danger)]/20' : 'bg-[var(--color-cyber-darker)]'}`}>
                    <Server className={`w-6 h-6 ${device.is_isolated ? 'text-[var(--color-cyber-danger)]' : 'text-[var(--color-cyber-muted)]'}`} />
                  </div>
                  {device.is_isolated ? (
                    <span className="badge badge-danger flex items-center gap-1">
                      <Lock className="w-3 h-3" /> Isolated
                    </span>
                  ) : (
                    <span className="badge badge-success flex items-center gap-1">
                      <ShieldCheck className="w-3 h-3" /> Active
                    </span>
                  )}
                </div>

                <h4
                  className="text-lg font-medium text-[var(--color-cyber-text)] truncate"
                  title={device.device_id}
                >
                  {device.device_id}
                </h4>
                <p className="text-sm font-mono text-[var(--color-cyber-blue)] mt-1">{device.ip_address}</p>

                <div className="mt-4 pt-4 border-t border-[var(--color-cyber-border)] text-xs text-[var(--color-cyber-muted)]">
                  <div className="flex justify-between mb-3">
                    <span>Last Seen:</span>
                    <span className="font-mono">
                      {new Date(device.last_seen).toLocaleString()}
                    </span>
                  </div>

                  {/* Action Button */}
                  <div className="pt-3 border-t border-[var(--color-cyber-border)]">
                    {device.is_isolated ? (
                      <button
                        onClick={() => handleReleaseDevice(device.device_id)}
                        disabled={actionLoading === device.device_id}
                        className="w-full cyber-button cyber-button-secondary py-2 flex items-center justify-center gap-2 text-xs"
                        title="Release device from isolation"
                      >
                        {actionLoading === device.device_id ? (
                          <span className="w-3 h-3 border border-[var(--color-cyber-blue)] border-t-transparent rounded-full animate-spin" />
                        ) : (
                          <Unlock className="w-3 h-3" />
                        )}
                        {actionLoading === device.device_id ? 'Releasing...' : 'Release Device'}
                      </button>
                    ) : (
                      <button
                        onClick={() => handleIsolateDevice(device.device_id)}
                        disabled={actionLoading === device.device_id}
                        className="w-full cyber-button cyber-button-danger py-2 flex items-center justify-center gap-2 text-xs"
                        title="Isolate device from network"
                      >
                        {actionLoading === device.device_id ? (
                          <span className="w-3 h-3 border border-[var(--color-cyber-danger)] border-t-transparent rounded-full animate-spin" />
                        ) : (
                          <Lock className="w-3 h-3" />
                        )}
                        {actionLoading === device.device_id ? 'Isolating...' : 'Isolate Device'}
                      </button>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
};

export default Devices;
