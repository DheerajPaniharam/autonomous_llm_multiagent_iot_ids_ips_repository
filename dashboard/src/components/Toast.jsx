import React from 'react';
import { useEffect } from 'react';
import { X, CheckCircle, AlertCircle, Info } from 'lucide-react';

const Toast = ({ id, type = 'info', title, message, onClose, duration = 4000 }) => {
  useEffect(() => {
    if (duration) {
      const timer = setTimeout(() => onClose(id), duration);
      return () => clearTimeout(timer);
    }
  }, [id, duration, onClose]);

  const typeConfig = {
    success: {
      icon: CheckCircle,
      bgColor: 'bg-[var(--color-cyber-neon)]/15',
      borderColor: 'border-[var(--color-cyber-neon)]/50',
      textColor: 'text-[var(--color-cyber-neon)]',
    },
    error: {
      icon: AlertCircle,
      bgColor: 'bg-[var(--color-cyber-danger)]/15',
      borderColor: 'border-[var(--color-cyber-danger)]/50',
      textColor: 'text-[var(--color-cyber-danger)]',
    },
    warning: {
      icon: AlertCircle,
      bgColor: 'bg-[var(--color-cyber-warning)]/15',
      borderColor: 'border-[var(--color-cyber-warning)]/50',
      textColor: 'text-[var(--color-cyber-warning)]',
    },
    info: {
      icon: Info,
      bgColor: 'bg-[var(--color-cyber-blue)]/15',
      borderColor: 'border-[var(--color-cyber-blue)]/50',
      textColor: 'text-[var(--color-cyber-blue)]',
    },
  };

  const config = typeConfig[type] || typeConfig.info;
  const Icon = config.icon;

  return (
    <div
      className={`
        glass-panel border ${config.borderColor} ${config.bgColor} px-6 py-4
        flex items-start gap-4 animate-in fade-in slide-in-from-top-2 duration-300
        max-w-md shadow-xl
      `}
      role="alert"
    >
      <Icon className={`w-5 h-5 flex-shrink-0 mt-0.5 ${config.textColor}`} />
      <div className="flex-1">
        {title && (
          <p className={`font-semibold text-sm ${config.textColor}`}>{title}</p>
        )}
        <p className="text-sm text-[var(--color-cyber-text)] mt-1">{message}</p>
      </div>
      <button
        onClick={() => onClose(id)}
        className="text-[var(--color-cyber-muted)] hover:text-[var(--color-cyber-text)] transition-colors flex-shrink-0"
        aria-label="Close notification"
      >
        <X className="w-4 h-4" />
      </button>
    </div>
  );
};

export default Toast;
