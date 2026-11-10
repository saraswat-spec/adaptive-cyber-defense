import React from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer } from 'recharts';
import { ShieldAlert, ShieldCheck } from 'lucide-react';

interface ThreatGaugeProps {
  score: number;
  level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}

export const ThreatGauge: React.FC<ThreatGaugeProps> = ({ score, level }) => {
  // Semi-circle gauge data
  const clampedScore = Math.min(100, Math.max(0, score));
  const data = [
    { name: 'Threat Score', value: clampedScore },
    { name: 'Remaining', value: 100 - clampedScore }
  ];

  const getColor = () => {
    if (clampedScore >= 80) return '#f43f5e'; // Critical red
    if (clampedScore >= 60) return '#fb7185'; // High rose
    if (clampedScore >= 35) return '#f59e0b'; // Medium amber
    return '#10b981'; // Low emerald
  };

  const getStatusText = () => {
    switch (level) {
      case 'CRITICAL':
        return 'CRITICAL ATTACK DETECTED';
      case 'HIGH':
        return 'ELEVATED SUSPICION';
      case 'MEDIUM':
        return 'MODERATE ANOMALY';
      default:
        return 'NORMAL PERIMETER BEHAVIOUR';
    }
  };

  return (
    <div className="relative flex flex-col items-center justify-center p-4">
      <div className="w-56 h-32 relative">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={data}
              cx="50%"
              cy="95%"
              startAngle={180}
              endAngle={0}
              innerRadius={65}
              outerRadius={85}
              paddingAngle={2}
              dataKey="value"
            >
              <Cell fill={getColor()} />
              <Cell fill="#1e293b" />
            </Pie>
          </PieChart>
        </ResponsiveContainer>

        {/* Center Score Overlay */}
        <div className="absolute inset-0 flex flex-col items-center justify-end pb-2">
          <span className="text-3xl font-extrabold font-mono tracking-tight" style={{ color: getColor() }}>
            {score.toFixed(0)}
          </span>
          <span className="text-[10px] font-mono uppercase text-slate-400">RISK INDEX / 100</span>
        </div>
      </div>

      {/* Description Pill */}
      <div className="mt-3 flex items-center gap-2 px-3 py-1 rounded-full border border-slate-800 bg-slate-900/60">
        {score >= 60 ? (
          <ShieldAlert className="w-3.5 h-3.5 text-rose-400 animate-pulse" />
        ) : (
          <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
        )}
        <span className="text-xs font-mono font-medium tracking-wide text-slate-300">
          {getStatusText()}
        </span>
      </div>
    </div>
  );
};
