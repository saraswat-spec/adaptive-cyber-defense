import React, { useState, useEffect } from 'react';
import { Shield, Activity, Radio, AlertTriangle, Clock } from 'lucide-react';

interface NavbarProps {
  threatLevel?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  activeAlertsCount?: number;
}

export const Navbar: React.FC<NavbarProps> = ({
  threatLevel = 'LOW',
  activeAlertsCount = 0
}) => {
  const [timeStr, setTimeStr] = useState<string>('');

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setTimeStr(now.toTimeString().split(' ')[0] + ' UTC');
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  const getThreatBadge = () => {
    switch (threatLevel) {
      case 'CRITICAL':
        return 'bg-red-500/20 text-red-400 border-red-500/40 animate-pulse';
      case 'HIGH':
        return 'bg-rose-500/20 text-rose-400 border-rose-500/40';
      case 'MEDIUM':
        return 'bg-amber-500/20 text-amber-400 border-amber-500/40';
      default:
        return 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40';
    }
  };

  return (
    <header className="h-16 border-b border-slate-800 bg-slate-950/80 backdrop-blur-md px-6 flex items-center justify-between sticky top-0 z-40">
      {/* Brand & System Title */}
      <div className="flex items-center gap-3">
        <div className="relative flex items-center justify-center w-10 h-10 rounded-lg bg-cyan-950/60 border border-cyan-500/40 shadow-[0_0_15px_rgba(6,182,212,0.25)]">
          <Shield className="w-5 h-5 text-cyan-400" />
          <span className="absolute -top-1 -right-1 w-2.5 h-2.5 bg-emerald-500 rounded-full border-2 border-slate-950 animate-ping" />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-sm font-bold tracking-wider text-slate-100 uppercase">
              Adaptive Cyberattack Detection & Prevention
            </h1>
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
              MINI-SOC
            </span>
          </div>
          <p className="text-xs text-slate-400 flex items-center gap-1.5">
            <Radio className="w-3 h-3 text-emerald-400 animate-pulse" />
            <span>Behavioral Network Anomaly Engine</span>
          </p>
        </div>
      </div>

      {/* Real-time Status Badges */}
      <div className="flex items-center gap-4">
        {/* Threat Level */}
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg border bg-slate-900/80">
          <span className="text-xs text-slate-400 uppercase tracking-wider font-mono">SOC THREAT:</span>
          <span className={`text-xs font-mono font-bold px-2 py-0.5 rounded border ${getThreatBadge()}`}>
            {threatLevel}
          </span>
        </div>

        {/* Active Incidents */}
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-slate-800 bg-slate-900/80 text-xs font-mono text-slate-300">
          <AlertTriangle className={`w-3.5 h-3.5 ${activeAlertsCount > 0 ? 'text-amber-400 animate-bounce' : 'text-slate-500'}`} />
          <span>INCIDENTS: <strong className="text-slate-100">{activeAlertsCount}</strong></span>
        </div>

        {/* System Clock */}
        <div className="hidden md:flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-800 bg-slate-900/80 text-xs font-mono text-slate-400">
          <Clock className="w-3.5 h-3.5 text-cyan-400" />
          <span>{timeStr}</span>
        </div>
      </div>
    </header>
  );
};
