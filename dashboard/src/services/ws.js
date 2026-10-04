import { getToken, clearAuth } from '../utils/auth';

const listeners = new Map();
let socket = null;
let reconnectTimer = null;
let shouldReconnect = true;
let authFailure = false;
let reconnectAttempts = 0;

const getSavedToken = () => {
  return getToken();
};

const buildWebSocketUrl = () => {
  const base = import.meta.env.VITE_API_URL || 'http://localhost:8000';
  let url;
  try {
    url = new URL(base);
  } catch {
    return 'ws://localhost:8000/api/v1/ws/live-traffic';
  }
  const protocol = url.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${protocol}//${url.host}/api/v1/ws/live-traffic`;
  const token = getSavedToken();
  return token ? `${wsUrl}?token=${encodeURIComponent(token)}` : wsUrl;
};

const dispatch = (type, payload) => {
  const typed = listeners.get(type);
  if (typed) {
    typed.forEach((handler) => {
      try {
        handler(payload);
      } catch (error) {
        console.error('WebSocket listener error', error);
      }
    });
  }
  const all = listeners.get('*');
  if (all) {
    all.forEach((handler) => {
      try {
        handler(type, payload);
      } catch (error) {
        console.error('WebSocket listener error', error);
      }
    });
  }
};

const getWebSocketClient = () => socket;

const handleAuthFailure = (reason) => {
  if (authFailure) return;
  authFailure = true;
  console.warn('[AUTH] Clearing session');
  clearAuth();
  dispatch('status', { connected: false, authFailed: true, reason });
  disconnect();
};

const isAuthClose = (event) => {
  if (!event) return false;
  if (event.code === 1008) return true;
  if ([4001, 4002, 4003, 4004].includes(event.code)) return true;
  if (event.reason && /auth|token|jwt|unauthorized|unauthenticated/i.test(event.reason)) return true;
  return false;
};

const connect = () => {
  if (socket) return;
  shouldReconnect = true;
  const token = getSavedToken();
  if (!token) {
    console.warn('[AUTH] JWT expired');
    handleAuthFailure('missing_token');
    return;
  }
  if (authFailure) {
    authFailure = false;
  }

  const url = buildWebSocketUrl();
  socket = new WebSocket(url);

  socket.onopen = () => {
    if (reconnectTimer) {
      clearTimeout(reconnectTimer);
      reconnectTimer = null;
    }
    reconnectAttempts = 0;
    console.info('WebSocket connected to', url);
    console.log('WebSocket connected');
    dispatch('status', { connected: true, url });
  };

  socket.onmessage = (event) => {
    let data;
    try {
      data = JSON.parse(event.data);
    } catch {
      return;
    }

    const envelope = data && data.type && data.payload ? data : { type: 'flow', payload: data };
    dispatch(envelope.type, envelope.payload);
  };

  socket.onclose = (event) => {
    socket = null;
    console.info('WebSocket disconnected', event.code, event.reason);
    dispatch('status', { connected: false });
    if (isAuthClose(event)) {
      handleAuthFailure('websocket_auth_failure');
      return;
    }
    if (!shouldReconnect) return;
    const backoff = Math.min(1000 * 2 ** reconnectAttempts, 30000);
    reconnectAttempts += 1;
    reconnectTimer = setTimeout(connect, backoff || 1000);
  };

  socket.onerror = () => {
    // Let onclose handle reconnect attempts.
  };
};

const disconnect = () => {
  shouldReconnect = false;
  if (reconnectTimer) {
    clearTimeout(reconnectTimer);
    reconnectTimer = null;
  }
  if (socket) {
    try {
      socket.close();
    } catch (error) {
      console.error('Error closing websocket', error);
    }
    socket = null;
    reconnectAttempts = 0;
  }
};

const subscribe = (type, callback) => {
  if (!listeners.has(type)) {
    listeners.set(type, new Set());
  }
  listeners.get(type).add(callback);
  connect();

  return () => {
    const set = listeners.get(type);
    if (!set) return;
    set.delete(callback);
    if (set.size === 0) {
      listeners.delete(type);
    }
    if (listeners.size === 0) {
      disconnect();
    }
  };
};

export { buildWebSocketUrl, connect, disconnect, getWebSocketClient, subscribe };
