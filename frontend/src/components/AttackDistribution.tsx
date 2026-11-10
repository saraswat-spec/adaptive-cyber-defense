import React from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from 'recharts';

interface AttackDistributionProps {
  distribution: Record<string, number>;
}

const COLORS: Record<string, string> = {
  DoS_DDoS: '#f43f5e',
  PortScan: '#f59e0b',
  BruteForce: '#ec4899',
  WebAttack: '#eab308',
  Infiltration: '#a855f7',
  Benign: '#10b981',
  'Rule Triggered': '#38bdf8'
};

export const AttackDistribution: React.FC<AttackDistributionProps> = ({ distribution }) => {
  const data = Object.entries(distribution)
    .filter(([_, count]) => count > 0)
    .map(([name, value]) => ({ name, value }));

  if (data.length === 0) {
    return (
      <div className="flex items-center justify-center h-48 text-xs font-mono text-slate-500">
        NO INCIDENT ANOMALIES RECORDED
      </div>
    );
  }

  return (
    <div className="w-full h-56">
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={data}
            cx="50%"
            cy="50%"
            innerRadius={45}
            outerRadius={70}
            paddingAngle={3}
            dataKey="value"
          >
            {data.map((entry, index) => (
              <Cell
                key={`cell-${index}`}
                fill={COLORS[entry.name] || '#06b6d4'}
              />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{
              backgroundColor: '#0a0d14',
              borderColor: '#1e293b',
              borderRadius: '8px',
              fontSize: '11px',
              fontFamily: 'monospace'
            }}
          />
          <Legend
            layout="vertical"
            align="right"
            verticalAlign="middle"
            iconType="circle"
            formatter={(value) => (
              <span className="text-[11px] font-mono text-slate-300">
                {value}
              </span>
            )}
          />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
};
