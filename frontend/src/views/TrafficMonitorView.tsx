import React, { useState } from 'react';
import {
  Activity,
  Filter,
  Search,
  ArrowDownUp,
  Radio,
  FileText,
  Info,
  X
} from 'lucide-react';
import { FlowRecord, DataSource } from '../types';

interface TrafficMonitorViewProps {
  flows: FlowRecord[];
  activeSourceFilter: string;
  onFilterChange: (source: string) => void;
}

export const TrafficMonitorView: React.FC<TrafficMonitorViewProps> = ({
  flows,
  activeSourceFilter,
  onFilterChange
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedFlow, setSelectedFlow] = useState<FlowRecord | null>(null);

  const getFwdPkts = (f?: FlowRecord | null): number => {
    if (!f) return 0;
    const val = f.tot_fwd_pkts ?? f.total_forward_packets ?? 0;
    const num = Number(val);
    return isNaN(num) ? 0 : num;
  };

  const getBwdPkts = (f?: FlowRecord | null): number => {
    if (!f) return 0;
    const val = f.tot_bwd_pkts ?? f.total_backward_packets ?? 0;
    const num = Number(val);
    return isNaN(num) ? 0 : num;
  };

  const getBytesPerSec = (f?: FlowRecord | null): number => {
    if (!f) return 0;
    const val = f.flow_bytes_per_sec ?? f.flow_bytes_per_second ?? 0;
    const num = Number(val);
    return isNaN(num) ? 0 : num;
  };

  const getPacketsPerSec = (f?: FlowRecord | null): number => {
    if (!f) return 0;
    const val = f.flow_packets_per_sec ?? f.flow_packets_per_second ?? 0;
    const num = Number(val);
    return isNaN(num) ? 0 : num;
  };

  const formatBandwidth = (bytesPerSec?: number | null): string => {
    const safeBytes = bytesPerSec != null && !isNaN(Number(bytesPerSec)) ? Number(bytesPerSec) : 0;
    const kb = safeBytes / 1024;
    return `${kb.toFixed(1)} KB/s`;
  };

  const formatPacketRate = (pps?: number | null): string => {
    const safePps = pps != null && !isNaN(Number(pps)) ? Number(pps) : 0;
    return `${safePps.toFixed(1)} PPS`;
  };

  const filteredFlows = flows.filter((f) => {
    const src = f.src_ip || f.source_ip || '';
    const dst = f.dst_ip || f.destination_ip || '';
    const proto = f.protocol || '';
    const attack = f.classified_attack || '';
    const term = searchTerm.toLowerCase();

    return (
      src.toLowerCase().includes(term) ||
      dst.toLowerCase().includes(term) ||
      proto.toLowerCase().includes(term) ||
      attack.toLowerCase().includes(term)
    );
  });

  return (
    <div className="space-y-6">
      {/* Header & Filter Controls */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-5 rounded-xl bg-[#0e131f] border border-slate-800">
        <div>
          <h2 className="text-base font-bold font-mono text-slate-100 flex items-center gap-2">
            <Activity className="w-5 h-5 text-cyan-400" />
            <span>Real-Time Network Flow Monitor</span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Ingestion telemetry tagged with origin provenance: Observed network traffic vs Simulated attack feeds.
          </p>
        </div>

        <div className="flex items-center gap-3">
          {/* Source Filter Buttons */}
          <div className="flex items-center p-1 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono">
            {['ALL', 'OBSERVED', 'SIMULATED', 'DATASET'].map((src) => (
              <button
                key={src}
                onClick={() => onFilterChange(src)}
                className={`px-3 py-1 rounded transition ${
                  activeSourceFilter === src
                    ? src === 'SIMULATED'
                      ? 'bg-purple-500/20 text-purple-300 border border-purple-500/40 font-bold'
                      : src === 'DATASET'
                      ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40 font-bold'
                      : src === 'OBSERVED'
                      ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-bold'
                      : 'bg-slate-800 text-slate-100 font-bold'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {src}
              </button>
            ))}
          </div>

          {/* Search Box */}
          <div className="relative">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search IP, protocol, attack..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-9 pr-4 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200 focus:outline-none focus:border-cyan-500/50 w-56 font-mono"
            />
          </div>
        </div>
      </div>

      {/* Flows Table */}
      <div className="rounded-xl bg-[#0e131f] border border-slate-800 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-950/80 border-b border-slate-800 text-slate-400 uppercase text-[11px]">
              <tr>
                <th className="py-3 px-4">Provenance</th>
                <th className="py-3 px-4">Timestamp</th>
                <th className="py-3 px-4">Source Endpoint</th>
                <th className="py-3 px-4">Destination Endpoint</th>
                <th className="py-3 px-4">Proto</th>
                <th className="py-3 px-4 text-right">Fwd/Bwd Pkts</th>
                <th className="py-3 px-4 text-right">Bandwidth</th>
                <th className="py-3 px-4 text-right">Packet Rate</th>
                <th className="py-3 px-4 text-right">Classification</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {filteredFlows.length > 0 ? (
                filteredFlows.map((flow) => (
                  <tr
                    key={flow.id}
                    onClick={() => setSelectedFlow(flow)}
                    className="hover:bg-slate-900/80 cursor-pointer transition"
                  >
                    <td className="py-2.5 px-4">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${
                        flow.data_source === 'SIMULATED'
                          ? 'bg-purple-500/10 text-purple-400 border-purple-500/30'
                          : flow.data_source === 'DATASET'
                          ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                          : 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30'
                      }`}>
                        {flow.data_source}
                      </span>
                    </td>
                    <td className="py-2.5 px-4 text-slate-400">
                      {new Date(flow.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="py-2.5 px-4 font-semibold text-slate-200">
                      {flow.src_ip || flow.source_ip}:{flow.src_port || flow.source_port}
                    </td>
                    <td className="py-2.5 px-4 text-slate-300">
                      {flow.dst_ip || flow.destination_ip}:{flow.dst_port || flow.destination_port}
                    </td>
                    <td className="py-2.5 px-4 text-slate-400">
                      {flow.protocol}
                    </td>
                    <td className="py-2.5 px-4 text-right text-slate-300">
                      {getFwdPkts(flow)} / {getBwdPkts(flow)}
                    </td>
                    <td className="py-2.5 px-4 text-right text-slate-400">
                      {formatBandwidth(getBytesPerSec(flow))}
                    </td>
                    <td className="py-2.5 px-4 text-right font-semibold text-emerald-400">
                      {formatPacketRate(getPacketsPerSec(flow))}
                    </td>
                    <td className="py-2.5 px-4 text-right">
                      {flow.classified_attack && flow.classified_attack !== 'Benign' ? (
                        <span className="text-rose-400 font-bold">
                          {flow.classified_attack}
                        </span>
                      ) : (
                        <span className="text-slate-500">Normal</span>
                      )}
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={9} className="py-12 text-center text-slate-500">
                    NO FLOW TELEMETRY MATCHING SELECTED FILTERS
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Flow Details Modal / Drawer */}
      {selectedFlow && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
          <div className="bg-[#0e131f] border border-slate-800 rounded-xl max-w-2xl w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <FileText className="w-5 h-5 text-cyan-400" />
                <h3 className="text-sm font-bold font-mono text-slate-100">
                  Network Flow Telemetry Inspector
                </h3>
              </div>
              <button
                onClick={() => setSelectedFlow(null)}
                className="text-slate-400 hover:text-slate-200"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="grid grid-cols-2 gap-4 text-xs font-mono">
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                <span className="text-slate-500">DATA PROVENANCE:</span>
                <p className="text-slate-100 font-bold mt-0.5">{selectedFlow.data_source}</p>
              </div>
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                <span className="text-slate-500">FLOW DURATION:</span>
                <p className="text-slate-100 font-bold mt-0.5">{Number(selectedFlow.flow_duration || 0).toFixed(3)}s</p>
              </div>
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                <span className="text-slate-500">SOURCE:</span>
                <p className="text-slate-100 font-bold mt-0.5">{selectedFlow.src_ip || selectedFlow.source_ip}:{selectedFlow.src_port || selectedFlow.source_port}</p>
              </div>
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                <span className="text-slate-500">DESTINATION:</span>
                <p className="text-slate-100 font-bold mt-0.5">{selectedFlow.dst_ip || selectedFlow.destination_ip}:{selectedFlow.dst_port || selectedFlow.destination_port}</p>
              </div>
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                <span className="text-slate-500">PACKET VELOCITY:</span>
                <p className="text-emerald-400 font-bold mt-0.5">{formatPacketRate(getPacketsPerSec(selectedFlow))}</p>
              </div>
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                <span className="text-slate-500">ESTIMATED RISK:</span>
                <p className="text-rose-400 font-bold mt-0.5">{Number(selectedFlow.risk_score || 0).toFixed(1)}/100</p>
              </div>
            </div>

            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono space-y-1">
              <div className="flex justify-between text-slate-400">
                <span>Forward Transmitted Packets:</span>
                <span className="text-slate-200">{getFwdPkts(selectedFlow)}</span>
              </div>
              <div className="flex justify-between text-slate-400">
                <span>Backward Received Packets:</span>
                <span className="text-slate-200">{getBwdPkts(selectedFlow)}</span>
              </div>
              <div className="flex justify-between text-slate-400">
                <span>Bandwidth Throughput:</span>
                <span className="text-slate-200">{formatBandwidth(getBytesPerSec(selectedFlow))}</span>
              </div>
              <div className="flex justify-between text-slate-400">
                <span>ML Classification:</span>
                <span className="text-cyan-400 font-semibold">{selectedFlow.classified_attack || 'Benign'}</span>
              </div>
            </div>

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setSelectedFlow(null)}
                className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono transition"
              >
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
