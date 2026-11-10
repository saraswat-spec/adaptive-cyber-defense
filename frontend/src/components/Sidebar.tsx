import React from 'react';
import {
  LayoutDashboard,
  Activity,
  AlertOctagon,
  Flame,
  Sliders,
  BarChart3,
  TerminalSquare
} from 'lucide-react';

export type NavView = 'dashboard' | 'monitor' | 'alerts' | 'simulation' | 'adaptive' | 'models';

interface SidebarProps {
  currentView: NavView;
  onSelectView: (view: NavView) => void;
  unresolvedAlertsCount?: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentView,
  onSelectView,
  unresolvedAlertsCount = 0
}) => {
  const navItems = [
    {
      id: 'dashboard' as NavView,
      label: 'Executive SOC',
      icon: LayoutDashboard,
      badge: null
    },
    {
      id: 'monitor' as NavView,
      label: 'Traffic Monitor',
      icon: Activity,
      badge: null
    },
    {
      id: 'alerts' as NavView,
      label: 'Incident Triage',
      icon: AlertOctagon,
      badge: unresolvedAlertsCount > 0 ? unresolvedAlertsCount : null,
      badgeColor: 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
    },
    {
      id: 'simulation' as NavView,
      label: 'Attack Lab',
      icon: Flame,
      badge: 'RED TEAM',
      badgeColor: 'bg-purple-500/20 text-purple-400 border border-purple-500/30'
    },
    {
      id: 'adaptive' as NavView,
      label: 'Adaptive Config',
      icon: Sliders,
      badge: null
    },
    {
      id: 'models' as NavView,
      label: 'Model Analytics',
      icon: BarChart3,
      badge: 'AI/ML',
      badgeColor: 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
    }
  ];

  return (
    <aside className="w-64 border-r border-slate-800 bg-[#0a0d14] flex flex-col justify-between p-4 shrink-0">
      <div>
        {/* Navigation Category Label */}
        <p className="text-[11px] font-mono tracking-wider text-slate-500 uppercase px-3 mb-2">
          Operations
        </p>
        <nav className="space-y-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = currentView === item.id;
            return (
              <button
                key={item.id}
                onClick={() => onSelectView(item.id)}
                className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-xs font-medium transition-all ${
                  isActive
                    ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 shadow-[0_0_12px_rgba(6,182,212,0.15)] font-semibold'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900 border border-transparent'
                }`}
              >
                <div className="flex items-center gap-3">
                  <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-500'}`} />
                  <span>{item.label}</span>
                </div>
                {item.badge && (
                  <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${item.badgeColor || 'bg-slate-800 text-slate-300'}`}>
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Bottom Node Environment Status */}
      <div className="p-3 rounded-lg border border-slate-800/80 bg-slate-950/60 text-xs font-mono">
        <div className="flex items-center justify-between text-slate-400 mb-1">
          <span className="flex items-center gap-1.5">
            <TerminalSquare className="w-3.5 h-3.5 text-cyan-400" />
            <span>Agent Node</span>
          </span>
          <span className="text-[10px] text-emerald-400">ONLINE</span>
        </div>
        <div className="text-[10px] text-slate-500 space-y-0.5">
          <p>Engine: Hybrid ML (Iso+RF)</p>
          <p>Ingestion: Dual Provenance</p>
        </div>
      </div>
    </aside>
  );
};
