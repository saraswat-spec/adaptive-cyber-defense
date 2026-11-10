import React, { useState } from 'react';
import {
  Flame,
  Play,
  Terminal,
  Activity,
  ShieldAlert,
  Sliders,
  CheckCircle2,
  Clock,
  Layers,
  Sparkles
} from 'lucide-react';
import { SimulationScenario, SimulationRun } from '../types';
import { api } from '../services/api';

interface SimulationLabViewProps {
  scenarios: SimulationScenario[];
  runs: SimulationRun[];
  onSimulationLaunched: () => void;
}

export const SimulationLabView: React.FC<SimulationLabViewProps> = ({
  scenarios,
  runs,
  onSimulationLaunched
}) => {
  const [selectedScenario, setSelectedScenario] = useState<string>('SYN_FLOOD');
  const [targetIp, setTargetIp] = useState<string>('10.0.0.5');
  const [targetPort, setTargetPort] = useState<number>(80);
  const [packetRate, setPacketRate] = useState<number>(2000);
  const [duration, setDuration] = useState<number>(5);
  const [isLaunching, setIsLaunching] = useState<boolean>(false);
  const [launchMessage, setLaunchMessage] = useState<string | null>(null);

  const activeScenario = scenarios.find((s) => s.id === selectedScenario) || scenarios[0];

  const handleLaunch = async () => {
    try {
      setIsLaunching(true);
      setLaunchMessage(null);
      await api.launchSimulation({
        scenario: selectedScenario,
        target_ip: targetIp,
        target_port: targetPort,
        packet_rate_pps: packetRate,
        duration_seconds: duration
      });
      setLaunchMessage(`Launched synthetic ${selectedScenario} simulation successfully! Watch the SOC dashboard.`);
      onSimulationLaunched();
    } catch (e: any) {
      setLaunchMessage(`Launch failed: ${e.message}`);
    } finally {
      setIsLaunching(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="p-5 rounded-xl bg-[#0e131f] border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-base font-bold font-mono text-slate-100">
              Red-Team Attack Simulation Laboratory
            </h2>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-500/20 text-purple-400 border border-purple-500/40 uppercase font-bold">
              Controlled Synthetic Testbed
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1 max-w-2xl">
            Inject realistic synthetic cyberattack flows to validate hybrid detection accuracy, examine Explainable AI attributions, and test dynamic threat scoring. All injected data is strictly tagged as <strong className="text-purple-400">SIMULATED</strong>.
          </p>
        </div>
      </div>

      {/* Scenario Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-5 gap-4">
        {scenarios.map((sc) => {
          const isSelected = selectedScenario === sc.id;
          return (
            <div
              key={sc.id}
              onClick={() => {
                setSelectedScenario(sc.id);
                setPacketRate(sc.default_rate_pps);
                setDuration(sc.default_duration_sec);
                if (sc.targeted_ports.length > 0) setTargetPort(sc.targeted_ports[0]);
              }}
              className={`p-4 rounded-xl border cursor-pointer transition flex flex-col justify-between ${
                isSelected
                  ? 'bg-purple-950/30 border-purple-500 shadow-[0_0_15px_rgba(168,85,247,0.25)]'
                  : 'bg-[#0e131f] border-slate-800 hover:border-slate-700'
              }`}
            >
              <div>
                <span className="text-[10px] font-mono text-purple-400 uppercase tracking-wider block mb-1">
                  {sc.category}
                </span>
                <h3 className="text-xs font-bold text-slate-100 font-mono mb-2">
                  {sc.name}
                </h3>
                <p className="text-[11px] text-slate-400 line-clamp-3">
                  {sc.description}
                </p>
              </div>

              <div className="mt-4 pt-2 border-t border-slate-800/80 flex items-center justify-between text-[10px] font-mono text-slate-500">
                <span>Rate: {sc.default_rate_pps} pps</span>
                <span className={isSelected ? 'text-purple-400 font-bold' : ''}>
                  {isSelected ? 'SELECTED' : 'SELECT'}
                </span>
              </div>
            </div>
          );
        })}
      </div>

      {/* Configuration & Launch Panel */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Custom Attack Builder Controls */}
        <div className="lg:col-span-2 p-5 rounded-xl bg-[#0e131f] border border-slate-800 space-y-4">
          <div className="flex items-center gap-2 mb-2">
            <Sliders className="w-4 h-4 text-cyan-400" />
            <h3 className="text-xs font-mono uppercase font-bold text-slate-200 tracking-wider">
              Attack Injection Parameters: {activeScenario?.name}
            </h3>
          </div>

          {launchMessage && (
            <div className="p-3 rounded-lg bg-purple-950/60 border border-purple-500/40 text-xs font-mono text-purple-200">
              {launchMessage}
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
            <div>
              <label className="text-slate-400 mb-1 block">Target Host IP:</label>
              <input
                type="text"
                value={targetIp}
                onChange={(e) => setTargetIp(e.target.value)}
                className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none focus:border-cyan-500"
              />
            </div>
            <div>
              <label className="text-slate-400 mb-1 block">Target Destination Port:</label>
              <input
                type="number"
                value={targetPort}
                onChange={(e) => setTargetPort(parseInt(e.target.value) || 80)}
                className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none focus:border-cyan-500"
              />
            </div>
          </div>

          {/* Rate & Duration Sliders */}
          <div className="space-y-4 pt-2 text-xs font-mono">
            <div>
              <div className="flex justify-between text-slate-300 mb-1">
                <span>Packet Generation Velocity:</span>
                <span className="text-emerald-400 font-bold">{packetRate} packets/sec</span>
              </div>
              <input
                type="range"
                min="100"
                max="5000"
                step="100"
                value={packetRate}
                onChange={(e) => setPacketRate(parseInt(e.target.value))}
                className="w-full accent-cyan-500"
              />
            </div>

            <div>
              <div className="flex justify-between text-slate-300 mb-1">
                <span>Attack Burst Duration:</span>
                <span className="text-cyan-400 font-bold">{duration} seconds</span>
              </div>
              <input
                type="range"
                min="1"
                max="20"
                step="1"
                value={duration}
                onChange={(e) => setDuration(parseInt(e.target.value))}
                className="w-full accent-cyan-500"
              />
            </div>
          </div>

          <button
            disabled={isLaunching}
            onClick={handleLaunch}
            className="w-full flex items-center justify-center gap-2 py-3 rounded-lg bg-purple-600 hover:bg-purple-500 text-white font-mono text-xs font-bold transition shadow-[0_0_20px_rgba(168,85,247,0.4)] disabled:opacity-50"
          >
            <Play className="w-4 h-4 fill-white" />
            <span>{isLaunching ? 'INJECTING SCENARIO...' : 'LAUNCH ATTACK SIMULATION'}</span>
          </button>
        </div>

        {/* Real-time Lab Safety & Provenance Safeguards */}
        <div className="p-5 rounded-xl bg-[#0e131f] border border-slate-800 flex flex-col justify-between text-xs font-mono">
          <div>
            <h3 className="text-xs uppercase font-bold text-slate-200 tracking-wider mb-3 flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-amber-400" />
              <span>Lab Sandbox Boundaries</span>
            </h3>
            <ul className="space-y-2.5 text-slate-400 text-[11px]">
              <li className="flex items-start gap-2">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
                <span>All flows originate with guaranteed <strong className="text-purple-300">SIMULATED</strong> data tags.</span>
              </li>
              <li className="flex items-start gap-2">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
                <span>Generates zero live socket exhaustion against external internet endpoints.</span>
              </li>
              <li className="flex items-start gap-2">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
                <span>Enables true red-team detection benchmarking for machine learning models.</span>
              </li>
            </ul>
          </div>

          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-[10px] text-slate-500 mt-4">
            Total Past Injections: <strong className="text-slate-300">{runs.length}</strong>
          </div>
        </div>
      </div>

      {/* Simulation Execution History Table */}
      <div className="rounded-xl bg-[#0e131f] border border-slate-800 overflow-hidden">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <h3 className="text-xs font-mono uppercase font-bold text-slate-200 tracking-wider flex items-center gap-2">
            <Clock className="w-4 h-4 text-cyan-400" />
            <span>Attack Simulation Run History</span>
          </h3>
          <span className="text-xs text-slate-400 font-mono">
            {runs.length} Runs Logged
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-950/80 border-b border-slate-800 text-slate-400 uppercase text-[11px]">
              <tr>
                <th className="py-3 px-4">Run ID</th>
                <th className="py-3 px-4">Scenario</th>
                <th className="py-3 px-4">Target Host</th>
                <th className="py-3 px-4 text-right">Packets Injected</th>
                <th className="py-3 px-4 text-right">Duration</th>
                <th className="py-3 px-4 text-right">Detections</th>
                <th className="py-3 px-4 text-center">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {runs.length > 0 ? (
                runs.map((r) => (
                  <tr key={r.id} className="hover:bg-slate-900/50">
                    <td className="py-2.5 px-4 text-slate-400">{r.id.slice(0, 8)}...</td>
                    <td className="py-2.5 px-4 font-bold text-purple-300">{r.scenario_name}</td>
                    <td className="py-2.5 px-4">{r.target_ip}:{r.target_port || 80}</td>
                    <td className="py-2.5 px-4 text-right text-emerald-400">{r.total_packets_injected.toLocaleString()}</td>
                    <td className="py-2.5 px-4 text-right">{r.duration_seconds}s</td>
                    <td className="py-2.5 px-4 text-right font-bold text-rose-400">{r.detected_alerts_count}</td>
                    <td className="py-2.5 px-4 text-center">
                      <span className={`text-[10px] px-2 py-0.5 rounded border uppercase font-bold ${
                        r.status === 'RUNNING'
                          ? 'bg-amber-500/20 text-amber-300 border-amber-500/40 animate-pulse'
                          : r.status === 'COMPLETED'
                          ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                          : 'bg-red-500/10 text-red-400 border-red-500/30'
                      }`}>
                        {r.status}
                      </span>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-500">
                    NO ATTACK LAB SIMULATION RUNS EXECUTED YET
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
