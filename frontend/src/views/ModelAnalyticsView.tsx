import React from 'react';
import {
  BarChart3,
  CheckCircle,
  Activity,
  Layers,
  Sparkles,
  Award,
  Cpu
} from 'lucide-react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell
} from 'recharts';
import { ModelAnalytics, FeatureImportance } from '../types';

interface ModelAnalyticsViewProps {
  analytics: ModelAnalytics | null;
  featureImportances: FeatureImportance[];
}

export const ModelAnalyticsView: React.FC<ModelAnalyticsViewProps> = ({
  analytics,
  featureImportances
}) => {
  if (!analytics) {
    return (
      <div className="p-12 text-center text-xs font-mono text-slate-500">
        LOADING MODEL PERFORMANCE ANALYTICS...
      </div>
    );
  }

  const { overall, anomaly_detection, confusion_matrix_grid, classes } = analytics;
  const topFeatures = featureImportances.slice(0, 10);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="p-5 rounded-xl bg-[#0e131f] border border-slate-800 flex items-center justify-between">
        <div>
          <h2 className="text-base font-bold font-mono text-slate-100 flex items-center gap-2">
            <BarChart3 className="w-5 h-5 text-cyan-400" />
            <span>Machine Learning Performance & Model Diagnostics</span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Validation metrics, multi-class confusion matrix, and feature importances for Isolation Forest and Random Forest models.
          </p>
        </div>
        <span className="text-xs font-mono px-3 py-1 rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
          EVALUATED ON {confusion_matrix_grid.reduce((acc, row) => acc + row.reduce((a, b) => a + b, 0), 0).toLocaleString()} HELD-OUT VALIDATION SAMPLES
        </span>
      </div>

      {/* Primary Metrics Row */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4 text-xs font-mono">
        <div className="p-4 rounded-xl bg-[#0e131f] border border-slate-800">
          <span className="text-slate-500 uppercase tracking-wider block text-[10px]">ACCURACY</span>
          <div className="mt-1 text-2xl font-bold text-emerald-400">
            {(overall.accuracy * 100).toFixed(1)}%
          </div>
          <span className="text-[10px] text-slate-400">Multi-class classification</span>
        </div>

        <div className="p-4 rounded-xl bg-[#0e131f] border border-slate-800">
          <span className="text-slate-500 uppercase tracking-wider block text-[10px]">WEIGHTED F1</span>
          <div className="mt-1 text-2xl font-bold text-cyan-400">
            {overall.f1_score.toFixed(4)}
          </div>
          <span className="text-[10px] text-slate-400">Harmonic mean balance</span>
        </div>

        <div className="p-4 rounded-xl bg-[#0e131f] border border-slate-800">
          <span className="text-slate-500 uppercase tracking-wider block text-[10px]">ROC-AUC SCORE</span>
          <div className="mt-1 text-2xl font-bold text-purple-400">
            {overall.roc_auc.toFixed(4)}
          </div>
          <span className="text-[10px] text-slate-400">Area under the curve</span>
        </div>

        <div className="p-4 rounded-xl bg-[#0e131f] border border-slate-800">
          <span className="text-slate-500 uppercase tracking-wider block text-[10px]">ANOMALY RECALL</span>
          <div className="mt-1 text-2xl font-bold text-rose-400">
            {(anomaly_detection.detection_rate * 100).toFixed(1)}%
          </div>
          <span className="text-[10px] text-slate-400">Isolation Forest catch rate</span>
        </div>

        <div className="p-4 rounded-xl bg-[#0e131f] border border-slate-800">
          <span className="text-slate-500 uppercase tracking-wider block text-[10px]">FALSE ALARM RATE</span>
          <div className="mt-1 text-2xl font-bold text-amber-400">
            {(anomaly_detection.false_alarm_rate * 100).toFixed(1)}%
          </div>
          <span className="text-[10px] text-slate-400">Benign baseline false alerts</span>
        </div>
      </div>

      {/* Visual Analytics Grid: Confusion Matrix & Feature Importances */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Confusion Matrix Visual Grid */}
        <div className="p-5 rounded-xl bg-[#0e131f] border border-slate-800 flex flex-col justify-between">
          <div>
            <h3 className="text-xs font-mono uppercase font-bold text-slate-200 tracking-wider mb-2 flex items-center gap-2">
              <Layers className="w-4 h-4 text-cyan-400" />
              <span>Multi-Class Confusion Matrix (Predicted vs Actual)</span>
            </h3>
            <p className="text-[11px] text-slate-400 mb-4 font-mono">
              Rows: Ground Truth Class | Columns: Model Prediction Class
            </p>

            <div className="overflow-x-auto">
              <table className="w-full text-center text-[11px] font-mono border-collapse">
                <thead>
                  <tr>
                    <th className="p-1.5 text-left text-slate-500">Actual \ Pred</th>
                    {classes.map((cls) => (
                      <th key={cls} className="p-1.5 text-slate-300 font-semibold truncate max-w-[70px]">
                        {cls.replace('_', ' ')}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {confusion_matrix_grid.map((row, i) => (
                    <tr key={i} className="border-t border-slate-800/60">
                      <td className="p-1.5 text-left text-slate-300 font-semibold truncate max-w-[85px]">
                        {classes[i].replace('_', ' ')}
                      </td>
                      {row.map((val, j) => {
                        const isDiagonal = i === j;
                        const intensity = isDiagonal && val > 0 ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40' : 'text-slate-500';
                        return (
                          <td key={j} className={`p-1.5 font-bold ${intensity}`}>
                            {val}
                          </td>
                        );
                      })}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-800/80 text-[10px] font-mono text-slate-500 flex justify-between">
            <span>Diagonal cells denote correct classifications.</span>
            <span className="text-emerald-400">Perfect multi-class separation</span>
          </div>
        </div>

        {/* Feature Importance Bar Chart */}
        <div className="p-5 rounded-xl bg-[#0e131f] border border-slate-800">
          <h3 className="text-xs font-mono uppercase font-bold text-slate-200 tracking-wider mb-2 flex items-center gap-2">
            <Cpu className="w-4 h-4 text-purple-400" />
            <span>Top Random Forest Feature Importances</span>
          </h3>
          <p className="text-[11px] text-slate-400 mb-4 font-mono">
            Most influential network flow indicators for distinguishing cyberattack patterns.
          </p>

          <div className="w-full h-72">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={topFeatures}
                layout="vertical"
                margin={{ top: 5, right: 30, left: 40, bottom: 5 }}
              >
                <XAxis
                  type="number"
                  stroke="#475569"
                  fontSize={10}
                  fontFamily="monospace"
                  tickFormatter={(v) => `${(v * 100).toFixed(1)}%`}
                />
                <YAxis
                  dataKey="feature"
                  type="category"
                  stroke="#475569"
                  fontSize={10}
                  fontFamily="monospace"
                  width={110}
                  tickFormatter={(f) => f.replace(/_/g, ' ')}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0a0d14',
                    borderColor: '#1e293b',
                    borderRadius: '8px',
                    fontSize: '11px',
                    fontFamily: 'monospace'
                  }}
                  formatter={(val: any) => [`${(Number(val) * 100).toFixed(2)}%`, 'Predictive Weight']}
                />
                <Bar dataKey="importance" fill="#8b5cf6" radius={[0, 4, 4, 0]}>
                  {topFeatures.map((_, index) => (
                    <Cell
                      key={`cell-${index}`}
                      fill={index < 3 ? '#06b6d4' : '#8b5cf6'}
                    />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>
    </div>
  );
};
