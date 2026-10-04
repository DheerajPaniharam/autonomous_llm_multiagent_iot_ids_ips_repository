import React from 'react';
const Card = ({ children, title, className = '', interactive = false }) => {
  const panelClass = interactive ? 'glass-panel-interactive' : 'glass-panel';
  return (
    <div className={`${panelClass} overflow-hidden ${className}`}>
      {title && (
        <div className="px-6 py-4 border-b border-[var(--color-cyber-border)]/40 bg-[var(--color-cyber-card-hover)]/20">
          <h3 className="text-base font-semibold tracking-wide text-[var(--color-cyber-text)]">{title}</h3>
        </div>
      )}
      <div className="p-6">
        {children}
      </div>
    </div>
  );
};

export default Card;
