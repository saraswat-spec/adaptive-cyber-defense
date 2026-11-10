import React, { useState } from 'react';
import {
  Sliders,
  CheckCircle,
  RotateCcw,
  History,
  TrendingDown,
  Info,
  ShieldCheck,
  Cpu
} from 'lucide-react';
import { AdaptiveThreshold } from '../types';
import { api } from '../services/api';

interface AdaptiveConfigViewProps {
  thresholds: AdaptiveThreshold[];
  baselineProfile: any;
  onThresholdsUpdated: () => void;
}

export const AdaptiveConfigView: React.FC<AdaptiveConfigViewProps> = ({
  thresholds,
  baselineProfile,
  onThresholdsUpdated
}) => {
  const [sensitivity, setSensitivity] = useState<number>(1.0);
  const [confidenceFloor, setConfidenceFloor] = useState<number>(0.50);
  const [synRatio, setSynRatio] = useState<number>(0.85);
  const [portEntropy, setPortEntropy] = useState<number>(0.75);
  const [isSaving, setIsSaving] = useState<boolean>(false);
  const [message, setMessage] = useState<string | null>(null);

  const handleSaveCalibration = async () => {
    try {
      setIsSaving(true);
      setMessage(null);
      await api.calibrateThresholds({
        anomaly_sensitivity_factor: sensitivity,
        confidence_floor: confidenceFloor,
        syn_flood_ratio_threshold: synRatio,
        port_entropy_threshold: portEntropy
      });
      setMessage('Thresholds successfully calibrated and baseline tolerance adjusted!');
      onThresholdsUpdated();
    } catch (e: any) {
      setMessage(`Calibration failed: ${e.message}`);
    } finally {
      setIsSaving(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Banner */}
      <div className="p-5 rounded-xl bg-[#0e131f] border border-slate-800">
        <div className="flex items-center gap-2">
          <Sliders className="w-5 h-5 text-cyan-400" />
          <h2 className="text-base font-bold font-mono text-slate-100">
            Adaptive Baseline Tuning & False-Positive Learning
          </h2>
        </div>
        <p className="text-xs text-slate-400 mt-1 max-w-3xl">
          Detection boundaries adapt automatically based on analyst triage feedback and normal behavioral traffic shifts. Tweak sensitivity factors manually or let the feedback loop reduce false positives over time.
        </p>
      </div>

      {message && (
        <div className="p-3 rounded-lg bg-emerald-950/60 border border-emerald-500/40 text-xs font-mono text-emerald-300 flex items-center justify-between">
          <span>{message}</span>
          <button onClick={() => setMessage(null)} className="text-emerald-400 hover:text-emerald-100">
            Dismiss
          </button>
        </div>
      )}

      {/* Active Threshold Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {thresholds.map((t) => (
          <div key={t.metric_name} className="p-4 rounded-xl bg-[#0e131f] border border-slate-800">
            <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider block">
              {t.metric_name.replace(/_/g, ' ')}
            </span>
            <div className="mt-1 text-2xl font-bold font-mono text-cyan-400">
              {t.current_threshold.toFixed(4)}
            </div>
            <div className="mt-2 text-[10px] font-mono text-slate-400 space-y-0.5">
              <div className="flex justify-between">
                <span>Baseline Mean:</span>
                <span className="text-slate-200">{t.baseline_mean.toFixed(4)}</span>
              </div>
              <div className="flex justify-between">
                <span>Std Deviation (σ):</span>
                <span className="text-slate-200">{t.baseline_std.toFixed(4)}</span>
              </div>
              <div className="flex justify-between text-slate-500 pt-1">
                <span>Prior Value:</span>
                <span>{t.previous_threshold.toFixed(4)}</span>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Calibration Controls */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="p-5 rounded-xl bg-[#0e131f] border border-slate-800 space-y-5">
          <h3 className="text-xs font-mono uppercase font-bold text-slate-200 tracking-wider flex items-center gap-2">
            <Cpu className="w-4 h-4 text-cyan-400" />
            <span>Sensitivity Calibration Sliders</span>
          </h3>

          <div className="space-y-4 text-xs font-mono">
            <div>
              <div className="flex justify-between text-slate-300 mb-1">
                <span>Isolation Forest Anomaly Sensitivity:</span>
                <span className="text-cyan-400 font-bold">{sensitivity.toFixed(2)}x</span>
              </div>
              <input
                type="range"
                min="0.3"
                max="2.5"
                step="0.05"
                value={sensitivity}
                onChange={(e) => setSensitivity(parseFloat(e.target.value))}
                className="w-full accent-cyan-500"
              />
              <p className="text-[10px] text-slate-500 mt-0.5">
                Higher sensitivity catches subtle deviations; lower sensitivity minimizes false alerts.
              </p>
            </div>

            <div>
              <div className="flex justify-between text-slate-300 mb-1">
                <span>Minimum Classification Confidence Floor:</span>
                <span className="text-emerald-400 font-bold">{(confidenceFloor * 100).toFixed(0)}%</span>
              </div>
              <input
                type="range"
                min="0.1"
                max="0.9"
                step="0.05"
                value={confidenceFloor}
                onChange={(e) => setConfidenceFloor(parseFloat(e.target.value))}
                className="w-full accent-cyan-500"
              />
            </div>

            <div>
              <div className="flex justify-between text-slate-300 mb-1">
                <span>SYN Flood Flag Ratio Cutoff:</span>
                <span className="text-amber-400 font-bold">{synRatio.toFixed(2)}</span>
              </div>
              <input
                type="range"
                min="0.5"
                max="0.98"
                step="0.02"
                value={synRatio}
                onChange={(e) => setSynRatio(parseFloat(e.target.value))}
                className="w-full accent-cyan-500"
              />
            </div>

            <div>
              <div className="flex justify-between text-slate-300 mb-1">
                <span>Port Scan Entropy Cutoff:</span>
                <span className="text-purple-400 font-bold">{portEntropy.toFixed(2)}</span>
              </div>
              <input
                type="range"
                min="0.4"
                max="0.95"
                step="0.02"
                value={portEntropy}
                onChange={(e) => setPortEntropy(parseFloat(e.target.value))}
                className="w-full accent-cyan-500"
              />
            </div>
          </div>

          <button
            disabled={isSaving}
            onClick={handleSaveCalibration}
            className="w-full py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-mono text-xs font-bold transition shadow-[0_0_15px_rgba(6,182,212,0.3)] disabled:opacity-50"
          >
            {isSaving ? 'APPLYING CALIBRATION...' : 'ENFORCE CALIBRATED THRESHOLDS'}
          </button>
        </div>

        {/* Historical Recalibration Audit Log */}
        <div className="p-5 rounded-xl bg-[#0e131f] border border-slate-800 flex flex-col justify-between">
          <div>
            <h3 className="text-xs font-mono uppercase font-bold text-slate-200 tracking-wider flex items-center gap-2 mb-3">
              <History className="w-4 h-4 text-emerald-400" />
              <span>Adaptive Recalibration Audit History</span>
            </h3>

            <div className="space-y-2.5 overflow-y-auto max-h-72 pr-1 text-xs font-mono">
              {thresholds.map((t, idx) => (
                <div key={idx} className="p-3 rounded-lg bg-slate-950/70 border border-slate-800">
                  <div className="flex items-center justify-between text-slate-200 font-bold">
                    <span>{t.metric_name}</span>
                    <span className="text-cyan-400">{t.current_threshold.toFixed(4)}</span>
                  </div>
                  <p className="text-[11px] text-slate-400 mt-1">
                    {t.reason || 'Recalibrated via active learning loop'}
                  </p>
                  <div className="mt-1 text-[10px] text-slate-500 flex justify-between">
                    <span>Prior: {t.previous_threshold.toFixed(4)}</span>
                    <span>{new Date(t.updated_at).toLocaleTimeString()}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-[11px] font-mono text-slate-400 mt-4 flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            <span>Active learning continuously relaxes thresholds when false positives are triaged.</span>
          </div>
        </div>
      </div>
    </div>
  );
};
