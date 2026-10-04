import React from 'react';
import { useState } from 'react';
import { useNavigate, Navigate } from 'react-router-dom';
import { login } from '../services/api';
import { isAuthenticated } from '../utils/auth';

const Login = () => {
  const navigate = useNavigate();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);

  if (isAuthenticated()) {
    return <Navigate to="/" replace />;
  }

  const handleSubmit = async (event) => {
    event.preventDefault();
    setError(null);
    setLoading(true);

    try {
      await login(username, password);
      navigate('/');
    } catch (err) {
      console.error('[Login] Login failed:', err);
      setError('Invalid username or password.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-[var(--color-cyber-dark)] px-4 py-10">
      <div className="w-full max-w-md glass-panel border border-[var(--color-cyber-border)]/40 p-8 shadow-xl">
        <div className="mb-8 text-center">
          <p className="text-sm uppercase tracking-widest text-[var(--color-cyber-muted)]">Secure Gateway Access</p>
          <h1 className="mt-3 text-3xl font-bold text-[var(--color-cyber-text)]">Admin Login</h1>
          <p className="mt-2 text-sm text-[var(--color-cyber-muted)]">Authenticate to access the IoT IDS/IPS dashboard.</p>
        </div>

        {error && (
          <div className="mb-4 rounded-lg bg-[rgba(255,0,60,0.12)] border border-[var(--color-cyber-danger)]/30 px-4 py-3 text-[var(--color-cyber-danger)]">
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-5">
          <div>
            <label className="block text-sm font-semibold text-[var(--color-cyber-muted)] mb-2" htmlFor="username">
              Username
            </label>
            <input
              id="username"
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
              required
              className="w-full rounded-xl border border-[var(--color-cyber-border)] bg-[var(--color-cyber-card)] px-4 py-3 text-[var(--color-cyber-text)] focus:border-[var(--color-cyber-blue)] focus:outline-none"
            />
          </div>

          <div>
            <label className="block text-sm font-semibold text-[var(--color-cyber-muted)] mb-2" htmlFor="password">
              Password
            </label>
            <input
              id="password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
              required
              className="w-full rounded-xl border border-[var(--color-cyber-border)] bg-[var(--color-cyber-card)] px-4 py-3 text-[var(--color-cyber-text)] focus:border-[var(--color-cyber-blue)] focus:outline-none"
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full rounded-xl bg-[var(--color-cyber-blue)] px-4 py-3 text-sm font-semibold text-white transition hover:bg-[var(--color-cyber-neon)] disabled:cursor-not-allowed disabled:opacity-60"
          >
            {loading ? 'Signing in…' : 'Sign in'}
          </button>
        </form>
      </div>
    </div>
  );
};

export default Login;
