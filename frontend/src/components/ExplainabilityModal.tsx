import React, { useState } from 'react';
import {
  X,
  ShieldAlert,
  Terminal,
  Copy,
  Check,
  ThumbsDown,
  ThumbsUp,
  Sliders,
  Sparkles,
  Cpu
} from 'lucide-react';
import { Alert } from '../types';
import { api } from '../services/api';

interface ExplainabilityModalProps {
  alert: Alert | null;
  onClose: () => void;
  onAlertUpdated: (updated: Alert) => void;
}

export const ExplainabilityModal: React.FC<ExplainabilityModalProps> = ({
  alert,
  onClose,
  onAlertUpdated
}) => {
  const [copied, setCopied] = useState(false);
  const [actionFeedback, setActionFeedback] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  if (!alert) return null;

  const handleCopyScript = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleExecuteMitigation = async (actionType: string, mode: 'SIMULATED' | 'ACTIVE') => {
    try {
      setIsSubmitting(true);
      const res = await api.executeMitigation(alert.id, actionType, mode);
      setActionFeedback(res.message);
    } catch (e: any) {
      setActionFeedback(`Mitigation error: ${e.message}`);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleFeedback = async (feedbackType: 'CONFIRMED_THREAT' | 'FALSE_POSITIVE') => {
    try {
      setIsSubmitting(true);
      const res = await api.submitAlertFeedback(alert.id, feedbackType, 'SOC Analyst triage action');
      const updated = await api.getAlertById(alert.id);
      onAlertUpdated(updated);
      setActionFeedback(
        feedbackType === 'FALSE_POSITIVE'
          ? 'Marked as False Positive: Baseline anomaly threshold adaptively tuned!'
          : 'Threat Confirmed: Threat intelligence profile updated.'
      );
    } catch (e: any) {
      setActionFeedback(`Feedback error: ${e.message}`);
    } finally {
      setIsSubmitting(false);
    }
  };

  const getSeverityColor = (level: string) => {
    switch (level) {
      case 'CRITICAL':
        return 'text-red-400 bg-red-500/10 border-red-500/30';
      case 'HIGH':
        return 'text-rose-400 bg-rose-500/10 border-rose-500/30';
      case 'MEDIUM':
        return 'text-amber-400 bg-amber-500/10 border-amber-500/30';
      default:
        return 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30';
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm animate-fadeIn">
      <div className="bg-[#0e131f] border border-slate-800 rounded-xl max-w-3xl w-full max-h-[90vh] overflow-y-auto shadow-2xl">
        {/* Header */}
        <div className="p-6 border-b border-slate-800 flex items-center justify-between sticky top-0 bg-[#0e131f]/95 backdrop-blur z-10">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-lg bg-red-500/10 border border-red-500/30">
              <ShieldAlert className="w-6 h-6 text-red-400" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-base font-bold text-slate-100 font-mono">
                  {alert.attack_type}
                </h2>
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded border uppercase font-bold ${getSeverityColor(alert.risk_level)}`}>
                  {alert.risk_level}
                </span>
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded border uppercase font-bold ${
                  alert.data_source === 'SIMULATED'
                    ? 'bg-purple-500/10 text-purple-400 border-purple-500/30'
                    : 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30'
                }`}>
                  {alert.data_source}
                </span>
              </div>
              <p className="text-xs text-slate-400 font-mono mt-0.5">
                Target: {alert.dst_ip}:{alert.dst_port} | Attacker: {alert.src_ip}:{alert.src_port} ({alert.protocol})
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content Body */}
        <div className="p-6 space-y-6">
          {/* Action Feedback Banner */}
          {actionFeedback && (
            <div className="p-3 rounded-lg bg-cyan-950/60 border border-cyan-500/40 text-xs font-mono text-cyan-200 flex items-center justify-between">
              <span>{actionFeedback}</span>
              <button
                onClick={() => setActionFeedback(null)}
                className="text-cyan-400 hover:text-cyan-100 ml-2"
              >
                Dismiss
              </button>
            </div>
          )}

          {/* Section 1: Explainable AI Narrative */}
          <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800">
            <div className="flex items-center gap-2 mb-2">
              <Sparkles className="w-4 h-4 text-cyan-400" />
              <h3 className="text-xs font-mono uppercase font-bold text-slate-200 tracking-wider">
                Explainable AI (XAI) Attribution Narrative
              </h3>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed font-sans">
              {alert.explanation?.narrative || 'Anomalous behavioral flow signature detected across network volume and protocol metrics.'}
            </p>
            <div className="mt-3 flex items-center gap-4 text-[11px] font-mono text-slate-400">
              <span>Composite Risk: <strong className="text-cyan-400">{alert.risk_score}/100</strong></span>
              <span>Model Confidence: <strong className="text-emerald-400">{(alert.confidence * 100).toFixed(0)}%</strong></span>
              <span>Anomaly Distance: <strong className="text-rose-400">{alert.explanation?.anomaly_score?.toFixed(4) || 'N/A'}</strong></span>
            </div>
          </div>

          {/* Section 2: Top Feature Deviations vs Baseline */}
          <div>
            <h3 className="text-xs font-mono uppercase font-bold text-slate-300 tracking-wider mb-3 flex items-center gap-2">
              <Sliders className="w-4 h-4 text-amber-400" />
              <span>Contributing Flow Indicators vs Normal Baseline</span>
            </h3>

            <div className="space-y-2">
              {alert.explanation?.top_features && alert.explanation.top_features.length > 0 ? (
                alert.explanation.top_features.map((feat, idx) => (
                  <div
                    key={idx}
                    className="p-3 rounded-lg bg-slate-950/70 border border-slate-800/80 flex items-center justify-between text-xs font-mono"
                  >
                    <div>
                      <div className="text-slate-200 font-semibold">{feat.label}</div>
                      <div className="text-[10px] text-slate-500">
                        Baseline Mean: {feat.baseline_mean} {feat.unit} (σ = {feat.baseline_std})
                      </div>
                    </div>
                    <div className="text-right">
                      <div className={`font-bold ${feat.direction === 'ABOVE_NORMAL' ? 'text-rose-400' : 'text-amber-400'}`}>
                        {feat.observed_value} {feat.unit}
                      </div>
                      <div className="text-[10px] text-slate-400">
                        {feat.z_score}σ deviation ({feat.direction.replace('_', ' ')})
                      </div>
                    </div>
                  </div>
                ))
              ) : (
                <div className="text-xs font-mono text-slate-500 p-2">
                  No individual extreme feature deviations recorded.
                </div>
              )}
            </div>
          </div>

          {/* Section 3: Recommended Preventive Actions */}
          <div>
            <h3 className="text-xs font-mono uppercase font-bold text-slate-300 tracking-wider mb-3 flex items-center gap-2">
              <Terminal className="w-4 h-4 text-emerald-400" />
              <span>Recommended Containment & Mitigation</span>
            </h3>

            {alert.mitigations && alert.mitigations.length > 0 ? (
              alert.mitigations.map((mit, idx) => (
                <div
                  key={idx}
                  className="p-4 rounded-lg bg-slate-950 border border-slate-800 font-mono text-xs space-y-3"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-cyan-400 font-bold uppercase">{mit.action_type.replace('_', ' ')}</span>
                    <button
                      onClick={() => handleCopyScript(mit.generated_script)}
                      className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-900 hover:bg-slate-800 text-slate-300 text-[11px] border border-slate-700 transition"
                    >
                      {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      <span>{copied ? 'Copied' : 'Copy Script'}</span>
                    </button>
                  </div>

                  <pre className="p-2.5 rounded bg-black/60 border border-slate-800/80 text-[11px] text-slate-300 overflow-x-auto whitespace-pre-wrap">
                    {mit.generated_script}
                  </pre>

                  <div className="flex items-center gap-2 pt-1">
                    <button
                      disabled={isSubmitting}
                      onClick={() => handleExecuteMitigation(mit.action_type, 'SIMULATED')}
                      className="px-3 py-1.5 rounded bg-cyan-600/20 hover:bg-cyan-600/30 text-cyan-300 border border-cyan-500/40 text-xs transition disabled:opacity-50"
                    >
                      Simulate Containment
                    </button>
                    <button
                      disabled={isSubmitting}
                      onClick={() => handleExecuteMitigation(mit.action_type, 'ACTIVE')}
                      className="px-3 py-1.5 rounded bg-red-600/20 hover:bg-red-600/30 text-red-300 border border-red-500/40 text-xs transition disabled:opacity-50"
                    >
                      Enforce Block Rule
                    </button>
                  </div>
                </div>
              ))
            ) : (
              <div className="text-xs font-mono text-slate-500">
                No active mitigation generated for this threat.
              </div>
            )}
          </div>

          {/* Section 4: Analyst Feedback Loop */}
          <div className="p-4 rounded-lg bg-slate-900/40 border border-slate-800/80 flex items-center justify-between">
            <div>
              <h4 className="text-xs font-mono font-bold text-slate-200">
                Analyst Active Learning & Threshold Triage
              </h4>
              <p className="text-[11px] text-slate-400">
                Marking False Positive tunes anomaly threshold sensitivity automatically.
              </p>
            </div>
            <div className="flex items-center gap-2">
              <button
                disabled={isSubmitting}
                onClick={() => handleFeedback('CONFIRMED_THREAT')}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/30 text-xs font-mono transition disabled:opacity-50"
              >
                <ThumbsUp className="w-3.5 h-3.5" />
                <span>Confirm Threat</span>
              </button>
              <button
                disabled={isSubmitting}
                onClick={() => handleFeedback('FALSE_POSITIVE')}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-amber-500/10 hover:bg-amber-500/20 text-amber-400 border border-amber-500/30 text-xs font-mono transition disabled:opacity-50"
              >
                <ThumbsDown className="w-3.5 h-3.5" />
                <span>False Positive</span>
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
