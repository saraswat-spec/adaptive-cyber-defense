import React from 'react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Legend
} from 'recharts';

interface TrafficPoint {
  time: string;
  observedPPS: number;
  simulatedPPS: number;
}

interface TrafficVolumeChartProps {
  data: TrafficPoint[];
}

export const TrafficVolumeChart: React.FC<TrafficVolumeChartProps> = ({ data }) => {
  return (
    <div className="w-full h-64">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={data} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
          <defs>
            <linearGradient id="colorObserved" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.4} />
              <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.0} />
            </linearGradient>
            <linearGradient id="colorSimulated" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#8b5cf6" stopOpacity={0.4} />
              <stop offset="95%" stopColor="#8b5cf6" stopOpacity={0.0} />
            </linearGradient>
          </defs>
          <XAxis
            dataKey="time"
            stroke="#475569"
            fontSize={10}
            tickLine={false}
            fontFamily="monospace"
          />
          <YAxis
            stroke="#475569"
            fontSize={10}
            tickLine={false}
            fontFamily="monospace"
            tickFormatter={(v) => `${v} pps`}
          />
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
            verticalAlign="top"
            height={36}
            iconType="circle"
            formatter={(value) => (
              <span className="text-xs font-mono text-slate-300 mr-4">
                {value === 'observedPPS' ? 'Observed Traffic (Live)' : 'Simulated Traffic (Lab)'}
              </span>
            )}
          />
          <Area
            type="monotone"
            dataKey="observedPPS"
            stroke="#06b6d4"
            strokeWidth={2}
            fillOpacity={1}
            fill="url(#colorObserved)"
            name="observedPPS"
          />
          <Area
            type="monotone"
            dataKey="simulatedPPS"
            stroke="#8b5cf6"
            strokeWidth={2}
            fillOpacity={1}
            fill="url(#colorSimulated)"
            name="simulatedPPS"
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
};
