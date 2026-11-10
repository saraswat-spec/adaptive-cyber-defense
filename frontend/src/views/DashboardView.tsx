import React from 'react';
import {
  Activity,
  Radio,
  Flame,
  ShieldAlert,
  ArrowUpRight,
  TrendingUp,
  Cpu,
  Layers
} from 'lucide-react';
import { Alert, FlowRecord } from '../types';
import { ThreatGauge } from '../components/ThreatGauge';
import { TrafficVolumeChart } from '../components/TrafficVolumeChart';
import { AttackDistribution } from '../components/AttackDistribution';

interface DashboardViewProps {
  alerts: Alert[];
  flows: FlowRecord[];
  stats: any;
  trafficSeries: any[];
  onSelectAlert: (alert: Alert) => void;
  onNavigateToSimulation: () => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  alerts,
  flows,
  stats,
  trafficSeries,
  onSelectAlert,
  onNavigateToSimulation
}) => {
  // Compute composite risk score from latest alerts
  const latestAlert = alerts[0];
  const maxRisk = alerts.length > 0
    ? Math.max(...alerts.slice(0, 10).map((a: any) => a.risk_score ?? a.riskScore ?? 0))
    : 14.5;
  const currentRiskLevel = latestAlert ? (latestAlert.risk_level ?? (latestAlert as any).riskLevel ?? 'LOW') : 'LOW';

  // Compute attack distribution from alerts
  const attackCounts: Record<string, number> = {};
  alerts.forEach((a: any) => {
    const type = a.attack_type ?? a.attackType ?? 'Anomaly';
    attackCounts[type] = (attackCounts[type] || 0) + 1;
  });

  return (
    <div className="space-y-6">
      {/* KPI Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Captured Flows */}
        <div className="p-4 rounded-xl bg-[#0e131f] border border-slate-800">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono">
            <span>TOTAL TELEMETRY FLOWS</span>
            <Layers className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="mt-2 text-2xl font-bold font-mono text-slate-100">
            {(stats?.total_flows_captured ?? stats?.totalFlowsCaptured ?? flows.length).toLocaleString()}
          </div>
          <div className="mt-1 flex items-center gap-2 text-[11px] font-mono text-slate-400">
            <span className="text-cyan-400 font-semibold">{stats?.observed_flows_count ?? stats?.observedFlowsCount ?? 0} Observed</span>
            <span>|</span>
            <span className="text-purple-400 font-semibold">{stats?.simulated_flows_count ?? stats?.simulatedFlowsCount ?? 0} Simulated</span>
          </div>
        </div>

        {/* Current Packet Velocity */}
        <div className="p-4 rounded-xl bg-[#0e131f] border border-slate-800">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono">
            <span>PACKET VELOCITY</span>
            <Activity className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="mt-2 text-2xl font-bold font-mono text-emerald-400">
            {Number(stats?.current_packet_rate_pps ?? stats?.currentPacketRatePps ?? 0).toFixed(0)} <span className="text-sm text-slate-400 font-normal">pps</span>
          </div>
          <p className="mt-1 text-[11px] font-mono text-slate-400 flex items-center gap-1">
            <TrendingUp className="w-3 h-3 text-emerald-400" />
            <span>Bandwidth: {(Number(stats?.current_bandwidth_bps ?? stats?.currentBandwidthBps ?? 0) / 1024).toFixed(1)} KB/s</span>
          </p>
        </div>

        {/* Flagged Incidents */}
        <div className="p-4 rounded-xl bg-[#0e131f] border border-slate-800">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono">
            <span>ACTIVE INCIDENTS</span>
            <ShieldAlert className="w-4 h-4 text-rose-400" />
          </div>
          <div className="mt-2 text-2xl font-bold font-mono text-rose-400">
            {alerts.filter((a) => a.status === 'NEW').length}
          </div>
          <p className="mt-1 text-[11px] font-mono text-slate-400">
            {alerts.filter((a) => a.risk_level === 'CRITICAL').length} Critical Priority
          </p>
        </div>

        {/* Red-Team Simulation State */}
        <div className="p-4 rounded-xl bg-[#0e131f] border border-slate-800 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono">
            <span>ATTACK SIMULATION LAB</span>
            <Flame className="w-4 h-4 text-purple-400" />
          </div>
          <div className="my-2">
            <span className="text-xs font-mono text-purple-300">Synthetic Injection Active</span>
          </div>
          <button
            onClick={onNavigateToSimulation}
            className="w-full flex items-center justify-center gap-1.5 py-1.5 rounded-lg bg-purple-500/10 hover:bg-purple-500/20 text-purple-300 border border-purple-500/30 text-xs font-mono transition"
          >
            <span>Launch Attack Scenario</span>
            <ArrowUpRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Main Visuals Row: Threat Gauge + Traffic Volume */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Dynamic Threat Risk Gauge */}
        <div className="p-5 rounded-xl bg-[#0e131f] border border-slate-800 flex flex-col justify-between">
          <div>
            <h2 className="text-xs font-mono uppercase font-bold text-slate-200 tracking-wider flex items-center gap-2">
              <Cpu className="w-4 h-4 text-cyan-400" />
              <span>Dynamic Perimeter Threat Risk</span>
            </h2>
            <p className="text-[11px] text-slate-400 mt-1">
              Real-time composite score factoring anomaly distance, attack classification, and asset weight.
            </p>
          </div>

          <ThreatGauge score={maxRisk} level={currentRiskLevel} />

          <div className="p-3 rounded-lg bg-slate-950/70 border border-slate-800 text-[11px] font-mono text-slate-400 space-y-1">
            <div className="flex justify-between">
              <span>Unsupervised Anomaly Model:</span>
              <span className="text-emerald-400 font-semibold">Isolation Forest (Online)</span>
            </div>
            <div className="flex justify-between">
              <span>Supervised Attack Classifier:</span>
              <span className="text-cyan-400 font-semibold">Random Forest (Online)</span>
            </div>
          </div>
        </div>

        {/* Live Traffic Volume Chart */}
        <div className="lg:col-span-2 p-5 rounded-xl bg-[#0e131f] border border-slate-800">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-xs font-mono uppercase font-bold text-slate-200 tracking-wider flex items-center gap-2">
                <Radio className="w-4 h-4 text-emerald-400" />
                <span>Live Ingestion Telemetry (Packets / Second)</span>
              </h2>
              <p className="text-[11px] text-slate-400 mt-0.5">
                Explicit provenance tracking distinguishing Observed perimeter traffic from Attack Lab simulations.
              </p>
            </div>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 animate-pulse">
              STREAMING
            </span>
          </div>

          <TrafficVolumeChart data={trafficSeries} />
        </div>
      </div>

      {/* Second Row: Attack Distribution + Recent Incidents */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Attack Category Breakdown */}
        <div className="p-5 rounded-xl bg-[#0e131f] border border-slate-800">
          <h2 className="text-xs font-mono uppercase font-bold text-slate-200 tracking-wider mb-1">
            Attack Classification Breakdown
          </h2>
          <p className="text-[11px] text-slate-400 mb-4">
            Distribution across multi-class detection taxonomies.
          </p>
          <AttackDistribution distribution={attackCounts} />
        </div>

        {/* Recent High-Priority Incidents Feed */}
        <div className="lg:col-span-2 p-5 rounded-xl bg-[#0e131f] border border-slate-800 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-xs font-mono uppercase font-bold text-slate-200 tracking-wider flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-rose-400" />
                <span>Recent High-Priority Security Incidents</span>
              </h2>
              <span className="text-xs text-slate-400 font-mono">
                {alerts.length} Incidents Captured
              </span>
            </div>

            <div className="space-y-2 overflow-y-auto max-h-64 pr-1">
              {alerts.length > 0 ? (
                alerts.slice(0, 5).map((alert) => (
                  <div
                    key={alert.id}
                    onClick={() => onSelectAlert(alert)}
                    className="p-3 rounded-lg bg-slate-950/70 border border-slate-800/80 hover:border-cyan-500/50 hover:bg-slate-900 cursor-pointer transition flex items-center justify-between text-xs font-mono"
                  >
                    <div className="flex items-center gap-3">
                      <span className={`w-2 h-2 rounded-full ${
                        alert.risk_level === 'CRITICAL' ? 'bg-red-400 animate-ping' :
                        alert.risk_level === 'HIGH' ? 'bg-rose-400' :
                        alert.risk_level === 'MEDIUM' ? 'bg-amber-400' : 'bg-emerald-400'
                      }`} />
                      <div>
                        <div className="text-slate-200 font-semibold flex items-center gap-2">
                          <span>{alert.attack_type}</span>
                          <span className={`text-[10px] px-1.5 py-0.2 rounded uppercase ${
                            alert.data_source === 'SIMULATED'
                              ? 'bg-purple-500/20 text-purple-300'
                              : 'bg-cyan-500/20 text-cyan-300'
                          }`}>
                            {alert.data_source}
                          </span>
                        </div>
                        <div className="text-[10px] text-slate-500">
                          {alert.src_ip} &rarr; {alert.dst_ip}:{alert.dst_port} ({alert.protocol})
                        </div>
                      </div>
                    </div>

                    <div className="text-right">
                      <div className="font-bold text-rose-400">
                        Risk {alert.risk_score.toFixed(0)}/100
                      </div>
                      <div className="text-[10px] text-slate-400">
                        {new Date(alert.timestamp).toLocaleTimeString()}
                      </div>
                    </div>
                  </div>
                ))
              ) : (
                <div className="p-8 text-center text-xs font-mono text-slate-500">
                  NO CRITICAL INCIDENTS DETECTED IN MONITORING WINDOW
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
