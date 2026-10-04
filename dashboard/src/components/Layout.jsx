import React from 'react';
import { useState } from 'react';
import { Outlet, NavLink, useLocation } from 'react-router-dom';
import { 
  ShieldAlert, 
  LayoutDashboard, 
  Activity, 
  Server, 
  Settings, 
  Menu,
  X,
  UserCircle,
  FileText,
  ClipboardList,
  LogOut
} from 'lucide-react';
import { logout } from '../services/api';

const Layout = () => {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const location = useLocation();

  const username = localStorage.getItem('username') || 'admin';
  const role = localStorage.getItem('userRole') || 'admin';

  const navItems = [
    { name: 'Dashboard', path: '/', icon: LayoutDashboard },
    { name: 'Alerts', path: '/alerts', icon: Activity },
    { name: 'Incidents', path: '/incidents', icon: ShieldAlert },
    { name: 'Devices', path: '/devices', icon: Server },
    { name: 'Reports', path: '/reports', icon: FileText },
    { name: 'Audit Logs', path: '/audit-logs', icon: ClipboardList },
    { name: 'Settings', path: '/settings', icon: Settings },
  ];

  const getPageTitle = () => {
    const item = navItems.find(i => i.path === location.pathname);
    return item ? item.name : 'Dashboard';
  };

  return (
    <div className="flex h-screen overflow-hidden bg-[var(--color-cyber-dark)]">
      {/* Mobile sidebar overlay */}
      {sidebarOpen && (
        <div 
          className="fixed inset-0 z-20 bg-black/60 backdrop-blur-sm lg:hidden transition-opacity duration-300"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* Sidebar */}
      <div 
        className={`fixed inset-y-0 left-0 z-30 w-64 glass-panel rounded-none border-t-0 border-b-0 border-l-0 transform transition-transform duration-300 ease-in-out lg:translate-x-0 lg:static lg:inset-0 flex flex-col ${sidebarOpen ? 'translate-x-0' : '-translate-x-full'}`}
      >
        {/* Sidebar Header / Brand */}
        <div className="flex items-center justify-between h-16 px-6 border-b border-[var(--color-cyber-border)]/40 bg-[var(--color-cyber-card-hover)]/10">
          <div className="flex items-center gap-3">
            <div className="relative flex items-center justify-center w-9 h-9 rounded-lg bg-[var(--color-cyber-blue)]/10 border border-[var(--color-cyber-blue)]/30 shadow-[0_0_15px_rgba(0,240,255,0.1)]">
              <ShieldAlert className="w-5 h-5 text-[var(--color-cyber-blue)]" />
            </div>
            <span className="text-lg font-bold tracking-wider text-[var(--color-cyber-text)]">
              GATEWAY <span className="text-[var(--color-cyber-blue)]">IDS</span>
            </span>
          </div>
          <button className="lg:hidden text-[var(--color-cyber-muted)] hover:text-white transition-colors" onClick={() => setSidebarOpen(false)}>
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Navigation list */}
        <div className="flex-1 px-3 py-6 space-y-1.5 overflow-y-auto">
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.name}
                to={item.path}
                className={({ isActive }) => 
                  `flex items-center gap-3 px-4 py-3 rounded-lg font-medium transition-all duration-200 border-l-4 ${
                    isActive 
                      ? 'bg-gradient-to-r from-[var(--color-cyber-blue)]/15 to-transparent text-[var(--color-cyber-blue)] border-[var(--color-cyber-blue)] shadow-[inset_4px_0_12px_rgba(0,240,255,0.05)]' 
                      : 'text-[var(--color-cyber-muted)] border-transparent hover:text-[var(--color-cyber-text)] hover:bg-[var(--color-cyber-card-hover)]/40'
                  }`
                }
              >
                <Icon className="w-4.5 h-4.5" />
                <span className="text-sm tracking-wide">{item.name}</span>
              </NavLink>
            );
          })}
        </div>

        {/* Sidebar Footer Info */}
        <div className="p-4 border-t border-[var(--color-cyber-border)]/40 bg-[var(--color-cyber-card-hover)]/5">
          <div className="flex items-center gap-2 text-xs text-[var(--color-cyber-muted)]">
            <span className="w-2 h-2 rounded-full bg-[var(--color-cyber-neon)] animate-ping"></span>
            <span>Agent Engine Running</span>
          </div>
        </div>
      </div>

      {/* Main Content Pane */}
      <div className="flex flex-col flex-1 w-0 overflow-hidden">
        {/* Topbar */}
        <div className="relative z-10 flex flex-shrink-0 h-16 glass-panel rounded-none border-t-0 border-x-0 border-b border-[var(--color-cyber-border)]/40 shadow-sm bg-[var(--color-cyber-card)]/50">
          <button 
            className="px-4 text-[var(--color-cyber-muted)] focus:outline-none hover:text-white lg:hidden"
            onClick={() => setSidebarOpen(true)}
          >
            <Menu className="w-6 h-6" />
          </button>
          
          <div className="flex items-center justify-between flex-1 px-6 sm:px-8">
            <h2 className="text-lg font-bold tracking-wide text-[var(--color-cyber-text)]">
              {getPageTitle()}
            </h2>
            
            <div className="flex items-center gap-4">
              <button
                type="button"
                onClick={() => {
                  logout();
                  window.location.assign('/login');
                }}
                className="flex items-center gap-2 rounded-full border border-[var(--color-cyber-border)]/50 bg-[var(--color-cyber-card-hover)]/40 px-3 py-2 text-sm font-semibold text-[var(--color-cyber-muted)] transition hover:border-[var(--color-cyber-blue)] hover:text-[var(--color-cyber-text)]"
              >
                <LogOut className="w-4 h-4" />
                Sign out
              </button>
              <div className="flex items-center gap-3 pl-4 border-l border-[var(--color-cyber-border)]/60">
                <div className="flex flex-col items-end">
                  <span className="text-sm font-semibold text-[var(--color-cyber-text)]">{username}</span>
                  <span className="text-[10px] uppercase tracking-wider text-[var(--color-cyber-muted)]">{role}</span>
                </div>
                <div className="relative">
                  <UserCircle className="w-8 h-8 text-[var(--color-cyber-blue)] ring-2 ring-[var(--color-cyber-blue)]/20 rounded-full" />
                  <span className="absolute bottom-0 right-0 w-2.5 h-2.5 bg-[var(--color-cyber-neon)] border-2 border-[var(--color-cyber-dark)] rounded-full shadow-[0_0_6px_var(--color-cyber-neon)]"></span>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Main Workspace */}
        <main className="flex-1 relative z-0 overflow-y-auto focus:outline-none p-6 sm:p-8 bg-gradient-to-b from-[var(--color-cyber-dark)] to-[var(--color-cyber-darker)]">
          <Outlet />
        </main>
      </div>
    </div>
  );
};

export default Layout;
