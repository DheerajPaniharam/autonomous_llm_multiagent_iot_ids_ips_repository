const TOKEN_KEY = 'token';
const WS_TOKEN_KEY = 'wsToken';

const dispatchAuthChange = () => {
  if (typeof window === 'undefined') return;
  window.dispatchEvent(new Event('authchange'));
};

export const getToken = () => {
  if (typeof localStorage === 'undefined') return null;
  return localStorage.getItem(TOKEN_KEY) || localStorage.getItem(WS_TOKEN_KEY);
};

export const setToken = (token) => {
  if (typeof localStorage === 'undefined') return;
  localStorage.setItem(TOKEN_KEY, token);
  localStorage.setItem(WS_TOKEN_KEY, token);
  dispatchAuthChange();
};

export const clearAuth = () => {
  if (typeof localStorage === 'undefined') return;
  console.warn('[AUTH] Clearing session');
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(WS_TOKEN_KEY);
  dispatchAuthChange();
};

export const isAuthenticated = () => Boolean(getToken());
