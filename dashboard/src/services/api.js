import axios from 'axios';
import { getToken, clearAuth, setToken } from '../utils/auth';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

const api = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request Interceptor: Attach JWT token
api.interceptors.request.use(
  (config) => {
    const token = getToken();
    if (token) {
      config.headers['Authorization'] = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

let authLogoutInitiated = false;

const handleAuthExpiration = () => {
  if (authLogoutInitiated) return;
  authLogoutInitiated = true;
  console.warn('[AUTH] JWT expired');
  clearAuth();
  window.alert('Your session has expired. Please log in again.');
  console.warn('[AUTH] Redirecting to login');
  const loginPath = '/login';
  if (window.location.pathname !== loginPath) {
    window.location.assign(loginPath);
  } else {
    window.location.reload();
  }
};

// Response Interceptor: Handle 401s globally
api.interceptors.response.use(
  (response) => response,
  (error) => {
    const status = error?.response?.status;
    if (status === 401) {
      handleAuthExpiration();
    }
    return Promise.reject(error);
  }
);

// --- Auth Endpoints ---
export const login = async (username, password) => {
  const formData = new URLSearchParams();
  formData.append('username', username);
  formData.append('password', password);

  const response = await api.post('/auth/token', formData, {
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    }
  });

  if (response.data.access_token) {
    setToken(response.data.access_token);
  }

  return response.data;
};

// --- Logout Helper ---
export const logout = () => {
  clearAuth();
};

// --- Metrics Endpoints ---
export const getMetrics = async () => {
  const response = await api.get('/api/v1/metrics');
  return response.data;
};

export const getLiveTraffic = async (limit = 50) => {
  const response = await api.get(`/api/v1/live-traffic?limit=${limit}`);
  return response.data;
};

// --- Alerts Endpoints ---
export const getAlerts = async (limit = 50, offset = 0, severity = null) => {
  let url = `/api/v1/alerts?limit=${limit}&offset=${offset}`;
  if (severity) url += `&severity=${severity}`;
  const response = await api.get(url);
  return response.data;
};

// --- Incidents Endpoints ---
export const getIncidents = async (limit = 50, offset = 0, state = null) => {
  let url = `/api/v1/incidents?limit=${limit}&offset=${offset}`;
  if (state) url += `&state=${state}`;
  const response = await api.get(url);
  return response.data;
};

export const getIncidentDetail = async (incidentId) => {
  const response = await api.get(`/api/v1/incidents/${incidentId}`);
  return response.data;
};

export const acknowledgeIncident = async (incidentId, acknowledgedBy, notes = '') => {
  const response = await api.post(`/api/v1/incidents/${incidentId}/acknowledge`, {
    acknowledged_by: acknowledgedBy,
    notes: notes
  });
  return response.data;
};

// --- Devices Endpoints ---
export const getDevices = async (limit = 50, offset = 0, isIsolated = null) => {
  let url = `/api/v1/devices?limit=${limit}&offset=${offset}`;
  if (isIsolated !== null) url += `&is_isolated=${isIsolated}`;
  const response = await api.get(url);
  return response.data;
};

// --- Config Endpoints ---
export const getConfig = async () => {
  const response = await api.get('/api/v1/config');
  return response.data;
};

export const updateConfig = async (configData) => {
  const response = await api.put('/api/v1/config', configData);
  return response.data;
};

// --- Health Endpoints ---
export const getHealth = async () => {
  const response = await api.get('/health');
  return response.data;
};

// --- Reports Endpoints ---
export const getReports = async (params = {}) => {
  const query = new URLSearchParams();
  if (params.type)  query.append('type',  params.type);
  if (params.year)  query.append('year',  params.year);
  if (params.month) query.append('month', params.month);
  const qs = query.toString();
  const response = await api.get(`/api/v1/reports${qs ? '?' + qs : ''}`);
  return response.data;
};

export const getReport = async (reportId, format = 'json') => {
  // If requesting CSV, return raw blob so callers can trigger a download
  if (format === 'csv') {
    const response = await api.get(`/api/v1/reports/${reportId}?format=${format}`, { responseType: 'blob' });
    return response.data;
  }
  const response = await api.get(`/api/v1/reports/${reportId}?format=${format}`);
  return response.data;
};

// --- Audit Logs ---
export const getAuditLogs = async (params = {}) => {
  const query = new URLSearchParams();
  if (params.limit) query.append('limit', String(params.limit));
  if (params.offset) query.append('offset', String(params.offset));
  if (params.username) query.append('username', params.username);
  if (params.action) query.append('action', params.action);
  if (params.resource_type) query.append('resource_type', params.resource_type);
  if (params.resource_id) query.append('resource_id', params.resource_id);
  if (params.start_time) query.append('start_time', params.start_time);
  if (params.end_time) query.append('end_time', params.end_time);

  const qs = query.toString();
  const response = await api.get(`/api/v1/audit-logs${qs ? '?' + qs : ''}`);
  return response.data;
};

// --- Device Control Endpoints ---
export const isolateDevice = async (deviceId) => {
  const response = await api.post(`/api/v1/devices/${deviceId}/isolate`);
  return response.data;
};

export const releaseDevice = async (deviceId) => {
  const response = await api.post(`/api/v1/devices/${deviceId}/release`);
  return response.data;
};

export default api;
