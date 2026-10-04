import React from 'react';
import { createContext, useContext, useState, useCallback } from 'react';

const ToastContext = createContext(null);

export const ToastProvider = ({ children }) => {
  const [toasts, setToasts] = useState([]);

  const showToast = useCallback(({
    type = 'info',
    title = '',
    message = '',
    duration = 4000,
  }) => {
    const id = `toast-${Date.now()}-${Math.random()}`;

    setToasts(prev => [...prev, {
      id,
      type,
      title,
      message,
      duration,
    }]);

    return id;
  }, []);

  const removeToast = useCallback((id) => {
    setToasts(prev => prev.filter(t => t.id !== id));
  }, []);

  const success = useCallback((message, title = 'Success') => {
    return showToast({ type: 'success', title, message });
  }, [showToast]);

  const error = useCallback((message, title = 'Error') => {
    return showToast({ type: 'error', title, message });
  }, [showToast]);

  const warning = useCallback((message, title = 'Warning') => {
    return showToast({ type: 'warning', title, message });
  }, [showToast]);

  const info = useCallback((message, title = 'Info') => {
    return showToast({ type: 'info', title, message });
  }, [showToast]);

  const value = {
    toasts,
    showToast,
    removeToast,
    success,
    error,
    warning,
    info,
  };

  return (
    <ToastContext.Provider value={value}>
      {children}
    </ToastContext.Provider>
  );
};

// eslint-disable-next-line react-refresh/only-export-components
export const useToast = () => {
  const context = useContext(ToastContext);
  if (!context) {
    throw new Error('useToast must be used within ToastProvider');
  }
  return context;
};

export default ToastContext;
