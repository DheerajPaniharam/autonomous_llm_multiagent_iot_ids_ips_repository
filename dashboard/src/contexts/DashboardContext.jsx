import React, { createContext, useContext, useState, useEffect, useCallback, useMemo, useRef } from 'react';
import { getMetrics, getAlerts, getLiveTraffic, getHealth, getIncidents } from '../services/api';
import { subscribe } from '../services/ws';
import { isAuthenticated } from '../utils/auth';
import { deepEqual } from '../utils/deepEqual';

// Centralized context for all dashboard data
const DashboardContext = createContext(null);

// Refresh intervals (milliseconds)
const INTERVALS = {
  METRICS: 30000,    // 30 seconds
  ALERTS: 15000,     // 15 seconds
  HEALTH: 60000,     // 60 seconds
  LIVE_TRAFFIC: null // WebSocket only (no polling)
};

// Alert pagination defaults
const ALERTS_LIMIT = 50;
const LIVE_TRAFFIC_LIMIT = 50;

export const DashboardProvider = ({ children }) => {
  // Metrics state
  const [metrics, setMetrics] = useState(null);
  const [metricsLoading, setMetricsLoading] = useState(true);
  const [metricsError, setMetricsError] = useState(null);

  const metricsRef = useRef(null);
  useEffect(() => {
    metricsRef.current = metrics;
  }, [metrics]);

  // Alerts state
  const [alerts, setAlerts] = useState([]);
  const [alertsLoading, setAlertsLoading] = useState(true);
  const [alertsError, setAlertsError] = useState(null);
  const [alertsTotal, setAlertsTotal] = useState(0);
  const [alertsOffset, setAlertsOffset] = useState(0);

  // Live traffic state
  const [liveTraffic, setLiveTraffic] = useState([]);
  const [liveTrafficLoading, setLiveTrafficLoading] = useState(true);
  const [liveTrafficError, setLiveTrafficError] = useState(null);

  // Health state
  const [health, setHealth] = useState(null);
  const [healthLoading, setHealthLoading] = useState(true);
  const [healthError, setHealthError] = useState(null);

  // Authentication state
  const [authenticated, setAuthenticated] = useState(isAuthenticated());

  // Incidents state
  const [incidents, setIncidents] = useState([]);
  const [incidentsLoading, setIncidentsLoading] = useState(true);
  const [incidentsError, setIncidentsError] = useState(null);

  // Global connection status
  const [wsConnected, setWsConnected] = useState(false);
  const wsConnectedRef = useRef(false);

  // ==================
  // Buffers for batched updates (prevent excessive rerenders)
  // ==================
  const flowBuffer = useRef([]);
  const metricsBuffer = useRef(null);
  const alertBuffer = useRef([]);

  // Track which features are actively subscribed
  const wsSubscriptions = useRef({});
  const disconnectFallbackTimer = useRef(null);

  // ==================
  // Metrics Fetching
  // ==================

  const fetchMetrics = useCallback(async () => {
    try {
      setMetricsLoading(true);
      const data = await getMetrics();
      // Only update if data actually changed (prevents unnecessary rerenders)
      setMetrics((prev) => {
        if (prev && deepEqual(prev, data)) {
          if (import.meta.env.DEV) {
            console.log('[DashboardContext] Metrics unchanged, skipping update');
          }
          return prev;
        }
        if (import.meta.env.DEV) {
          console.log('[DashboardContext] Metrics updated');
          console.count("Metrics State Update");
        }
        return data;
      });
      setMetricsError(null);
    } catch (err) {
      console.error('[DashboardContext] Metrics fetch failed:', err);
      setMetricsError(err.message);
    } finally {
      setMetricsLoading(false);
    }
  }, []);

  // ==================
  // Alerts Fetching
  // ==================

  const mergeAlerts = useCallback((previous, incoming) => {
    const normalized = Array.isArray(incoming) ? incoming : [incoming];
    const seen = new Set();
    const combined = [...normalized, ...previous];
    const deduped = [];

    combined.forEach((alert, idx) => {
      const key = alert?.id ?? alert?.flow_id ?? `fallback-${alert?.timestamp ?? idx}-${idx}`;
      if (seen.has(key)) return;
      seen.add(key);
      deduped.push(alert);
    });

    return deduped.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
  }, []);

  const fetchAlerts = useCallback(async (limit = ALERTS_LIMIT, offset = 0, append = false) => {
    try {
      setAlertsLoading(true);
      const data = await getAlerts(limit, offset);
      const newAlerts = Array.isArray(data)
        ? data
        : Array.isArray(data.alerts)
        ? data.alerts
        : Array.isArray(data.items)
        ? data.items
        : [];
      setAlertsTotal(typeof data.total === 'number' ? data.total : newAlerts.length);

      if (append && offset > 0) {
        setAlerts((prev) => {
          const merged = mergeAlerts(prev, newAlerts);
          if (deepEqual(prev, merged)) return prev;
          if (import.meta.env.DEV) {
            console.count("Alert State Update");
          }
          return merged;
        });
        setAlertsOffset((prevOffset) => prevOffset + newAlerts.length);
      } else {
        setAlerts((prev) => {
          const nextVal = (offset === 0)
            ? mergeAlerts(newAlerts, prev)
            : newAlerts;
          if (deepEqual(prev, nextVal)) return prev;
          if (import.meta.env.DEV) {
            console.count("Alert State Update");
          }
          return nextVal;
        });
        setAlertsOffset((prevOffset) => Math.max(prevOffset, offset + newAlerts.length));
      }

      setAlertsError(null);
    } catch (err) {
      console.error('[DashboardContext] Alerts fetch failed:', err);
      setAlertsError(err.message);
    } finally {
      setAlertsLoading(false);
    }
  }, [mergeAlerts]);

  const loadMoreAlerts = useCallback(async () => {
    if (alertsLoading || alerts.length >= alertsTotal) return;
    const nextOffset = alertsOffset;
    await fetchAlerts(ALERTS_LIMIT, nextOffset, true);
  }, [alerts.length, alertsLoading, alertsOffset, alertsTotal, fetchAlerts]);

  // ==================
  // Live Traffic Fetching
  // ==================

  const fetchLiveTraffic = useCallback(async (limit = LIVE_TRAFFIC_LIMIT) => {
    try {
      setLiveTrafficLoading(true);
      const data = await getLiveTraffic(limit);
      const nextFlows = Array.isArray(data) ? data : data.flows || [];
      setLiveTraffic((prev) => {
        if (deepEqual(prev, nextFlows)) return prev;
        if (import.meta.env.DEV) {
          console.count("Flow State Update");
        }
        return nextFlows;
      });
      setLiveTrafficError(null);
    } catch (err) {
      console.error('[DashboardContext] Live traffic fetch failed:', err);
      setLiveTrafficError(err.message);
    } finally {
      setLiveTrafficLoading(false);
    }
  }, []);

  // ==================
  // Health Fetching
  // ==================

  const fetchHealth = useCallback(async () => {
    try {
      setHealthLoading(true);
      const data = await getHealth();
      setHealth(data);
      setHealthError(null);
    } catch (err) {
      console.error('[DashboardContext] Health fetch failed:', err);
      setHealthError(err.message);
    } finally {
      setHealthLoading(false);
    }
  }, []);

  // ==================
  // Incidents Fetching
  // ==================

  const fetchIncidents = useCallback(async () => {
    try {
      setIncidentsLoading(true);
      const data = await getIncidents(50);
      setIncidents(Array.isArray(data?.incidents) ? data.incidents : []);
      setIncidentsError(null);
    } catch (err) {
      console.error('[DashboardContext] Incidents fetch failed:', err);
      setIncidentsError(err.message);
    } finally {
      setIncidentsLoading(false);
    }
  }, []);

  // ==================
  // WebSocket Subscriptions
  // ==================

  const subscribeToWsUpdates = useCallback(() => {
    if (import.meta.env.DEV) {
      console.count('[DashboardContext] WebSocket subscriptions initialized');
    }

    // Subscribe to metrics updates via WebSocket
    wsSubscriptions.current.metrics = subscribe('metrics', (payload) => {
      if (payload) {
        // Buffer metrics and compare before update
        metricsBuffer.current = payload;
      }
    });

    // Subscribe to alert updates via WebSocket
    wsSubscriptions.current.alerts = subscribe('alert', (payload) => {
      if (payload) {
        // Buffer alert to be merged in batch
        alertBuffer.current.push(payload);
      }
    });

    // Subscribe to live traffic via WebSocket (primary source)
    // CRITICAL: Buffer flows instead of updating state directly
    wsSubscriptions.current.flow = subscribe('flow', (payload) => {
      if (payload) {
        if (import.meta.env.DEV) {
          console.count('FLOW_EVENT');
        }
        // Push to buffer instead of direct setState
        flowBuffer.current.push(payload);
      }
    });

    // Subscribe to batch live traffic via WebSocket
    wsSubscriptions.current.flow_batch = subscribe('flow_batch', (payload) => {
      if (Array.isArray(payload)) {
        if (import.meta.env.DEV) {
          payload.forEach(() => console.count('FLOW_EVENT'));
        }
        flowBuffer.current.push(...payload);
      }
    });

    // Subscribe to initial snapshot payload from backend
    wsSubscriptions.current.snapshot = subscribe('snapshot', (payload) => {
      if (Array.isArray(payload)) {
        const sliced = payload.slice(0, LIVE_TRAFFIC_LIMIT);
        setLiveTraffic((prev) => {
          if (deepEqual(prev, sliced)) return prev;
          if (import.meta.env.DEV) {
            console.count("Flow State Update");
          }
          return sliced;
        });
      }
    });

    // Subscribe to connection status
    wsSubscriptions.current.status = subscribe('status', (payload) => {
      if (payload && payload.connected !== undefined) {
        setWsConnected((prev) => {
          return prev === payload.connected
            ? prev
            : payload.connected;
        });
        wsConnectedRef.current = payload.connected;

        if (payload.connected) {
          if (disconnectFallbackTimer.current) {
            clearTimeout(disconnectFallbackTimer.current);
            disconnectFallbackTimer.current = null;
          }
        } else {
          if (!disconnectFallbackTimer.current) {
            disconnectFallbackTimer.current = setTimeout(() => {
              if (!wsConnectedRef.current) {
                fetchLiveTraffic(LIVE_TRAFFIC_LIMIT);
              }
              disconnectFallbackTimer.current = null;
            }, 5000);
          }
        }
      }
    });
  }, [fetchLiveTraffic]);

  const unsubscribeFromWsUpdates = useCallback(() => {
    Object.values(wsSubscriptions.current).forEach((unsub) => {
      if (typeof unsub === 'function') {
        unsub();
      }
    });
    wsSubscriptions.current = {};
  }, []);

  // ==================
  // Effect: Initial Load & Polling
  // ==================

  useEffect(() => {
    if (!authenticated) {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setMetricsLoading(false);
      setAlertsLoading(false);
      setLiveTrafficLoading(false);
      setHealthLoading(false);
      setIncidentsLoading(false);
      return;
    }

    // Initial mount and shared data orchestration

    // Initial loads
    fetchMetrics();
    fetchAlerts(ALERTS_LIMIT, 0);
    fetchHealth();
    fetchIncidents();

    // Fallback: if websocket is not connected within a few seconds, load live traffic once
    const liveTrafficFallbackTimer = setTimeout(() => {
      if (!wsConnectedRef.current) {
        fetchLiveTraffic(LIVE_TRAFFIC_LIMIT);
      }
    }, 4000);

    // Subscribe to WebSocket updates
    subscribeToWsUpdates();

    // Setup polling intervals for shared dashboard data
    const metricsInterval = setInterval(fetchMetrics, INTERVALS.METRICS);
    const alertsInterval = setInterval(() => {
      if (!wsConnectedRef.current) {
        fetchAlerts(ALERTS_LIMIT, 0);
      }
    }, INTERVALS.ALERTS);
    const healthInterval = setInterval(fetchHealth, INTERVALS.HEALTH);

    // Cleanup on unmount
    return () => {
      // Cleanup on unmount
      clearInterval(metricsInterval);
      clearInterval(alertsInterval);
      clearInterval(healthInterval);
      clearTimeout(liveTrafficFallbackTimer);
      if (disconnectFallbackTimer.current) {
        clearTimeout(disconnectFallbackTimer.current);
      }
      unsubscribeFromWsUpdates();
    };
  }, [authenticated, fetchMetrics, fetchAlerts, fetchLiveTraffic, fetchHealth, fetchIncidents, subscribeToWsUpdates, unsubscribeFromWsUpdates]);

  // ==================
  // Effect: Batched Buffer Flush (1000ms interval)
  // ==================
  // This effect flushes buffered WebSocket updates in batches to prevent excessive rerenders

  useEffect(() => {
    if (!authenticated) return;

    const flushInterval = setInterval(() => {
      let updated = false;

      // Flush metrics buffer
      if (metricsBuffer.current !== null) {
        const nextMetrics = metricsBuffer.current;
        metricsBuffer.current = null;
        if (metricsRef.current && deepEqual(metricsRef.current, nextMetrics)) {
          // No change, skip update
        } else {
          setMetrics(nextMetrics);
          if (import.meta.env.DEV) {
            console.count("Metrics State Update");
          }
          updated = true;
        }
      }

      // Flush alerts buffer
      if (alertBuffer.current.length > 0) {
        const incomingAlerts = alertBuffer.current;
        alertBuffer.current = [];
        setAlerts((prev) => {
          const merged = mergeAlerts(prev, incomingAlerts);
          if (deepEqual(prev, merged)) {
            return prev;
          }
          if (import.meta.env.DEV) {
            console.count("Alert State Update");
          }
          return merged;
        });
        updated = true;
      }

      // Flush flows buffer
      if (flowBuffer.current.length > 0) {
        const incomingFlows = flowBuffer.current;
        flowBuffer.current = [];
        setLiveTraffic((prev) => {
          // Deduplicate by flow_id: new flows take precedence
          const flowMap = new Map();
          
          // Add buffered flows first (newest)
          incomingFlows.forEach((flow) => {
            if (flow && flow.flow_id) {
              flowMap.set(flow.flow_id, flow);
            }
          });
          
          // Add existing flows (older)
          prev.forEach((flow) => {
            if (flow && flow.flow_id && !flowMap.has(flow.flow_id)) {
              flowMap.set(flow.flow_id, flow);
            }
          });

          // Convert to array, sort by most recent, keep limit
          const merged = Array.from(flowMap.values()).slice(0, LIVE_TRAFFIC_LIMIT);
          
          if (deepEqual(prev, merged)) {
            return prev;
          }

          if (import.meta.env.DEV) {
            console.count("Flow State Update");
          }

          return merged;
        });
        updated = true;
      }

      if (updated && import.meta.env.DEV) {
        console.count('[DashboardContext] Batch flush executed');
      }
    }, 1000); // Flush every 1 second

    return () => clearInterval(flushInterval);
  }, [authenticated, mergeAlerts]);

  useEffect(() => {
    if (import.meta.env.DEV) {
      console.count("DashboardProvider Render");
    }
  });

  useEffect(() => {
    const updateAuth = () => {
      setAuthenticated(isAuthenticated());
    };

    window.addEventListener('authchange', updateAuth);
    return () => {
      window.removeEventListener('authchange', updateAuth);
    };
  }, []);

  // ==================
  // Context Value
  // ==================

  const hasMoreAlerts = alertsTotal > alerts.length;

  const value = useMemo(() => ({
    // Metrics
    metrics,
    metricsLoading,
    metricsError,
    refetchMetrics: fetchMetrics,

    // Alerts
    alerts,
    alertsLoading,
    alertsError,
    alertsTotal,
    alertsOffset,
    hasMoreAlerts,
    refetchAlerts: fetchAlerts,
    loadMoreAlerts,

    // Live Traffic
    liveTraffic,
    liveTrafficLoading,
    liveTrafficError,
    refetchLiveTraffic: fetchLiveTraffic,

    // Health
    health,
    healthLoading,
    healthError,
    refetchHealth: fetchHealth,

    // Incidents
    incidents,
    incidentsLoading,
    incidentsError,
    refetchIncidents: fetchIncidents,

    // Connection
    wsConnected,

    // Pagination helpers
    ALERTS_LIMIT,
    LIVE_TRAFFIC_LIMIT,
  }), [
    metrics,
    metricsLoading,
    metricsError,
    fetchMetrics,
    alerts,
    alertsLoading,
    alertsError,
    alertsTotal,
    alertsOffset,
    fetchAlerts,
    loadMoreAlerts,
    liveTraffic,
    liveTrafficLoading,
    liveTrafficError,
    fetchLiveTraffic,
    health,
    healthLoading,
    healthError,
    fetchHealth,
    incidents,
    incidentsLoading,
    incidentsError,
    fetchIncidents,
    wsConnected,
    hasMoreAlerts,
  ]);

  return (
    <DashboardContext.Provider value={value}>
      {children}
    </DashboardContext.Provider>
  );
};

// Hook to use dashboard context
// eslint-disable-next-line react-refresh/only-export-components
export const useDashboard = () => {
  const context = useContext(DashboardContext);
  if (!context) {
    throw new Error('useDashboard must be used within DashboardProvider');
  }
  return context;
};
