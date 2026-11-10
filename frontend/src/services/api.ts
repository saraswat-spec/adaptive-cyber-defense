import {
  FlowRecord,
  Alert,
  SimulationScenario,
  SimulationRun,
  AdaptiveThreshold,
  ModelAnalytics,
  FeatureImportance
} from '../types';

// In production (Netlify), VITE_API_BASE_URL can point directly to the deployed Java backend.
// In local development, leaving it unset defaults to '/api/v1', seamlessly routing through the Vite proxy.
const API_BASE = (import.meta.env.VITE_API_BASE_URL ? import.meta.env.VITE_API_BASE_URL.replace(/\/$/, '') : '') + '/api/v1';

export const api = {
  // Telemetry & Flows
  async getFlows(limit = 50, offset = 0, source = 'ALL'): Promise<FlowRecord[]> {
    const res = await fetch(`${API_BASE}/telemetry/flows?limit=${limit}&offset=${offset}&source=${source}`);
    if (!res.ok) throw new Error('Failed to fetch flows');
    return res.json();
  },

  async getStats() {
    const res = await fetch(`${API_BASE}/telemetry/stats`);
    if (!res.ok) throw new Error('Failed to fetch telemetry stats');
    return res.json();
  },

  // Alerts
  async getAlerts(status?: string, severity?: string, source = 'ALL'): Promise<Alert[]> {
    const params = new URLSearchParams();
    if (status) params.append('status', status);
    if (severity) params.append('severity', severity);
    if (source && source !== 'ALL') params.append('source', source);
    params.append('limit', '60');

    const res = await fetch(`${API_BASE}/alerts?${params.toString()}`);
    if (!res.ok) throw new Error('Failed to fetch alerts');
    return res.json();
  },

  async getAlertById(id: string): Promise<Alert> {
    const res = await fetch(`${API_BASE}/alerts/${id}`);
    if (!res.ok) throw new Error('Failed to fetch alert details');
    return res.json();
  },

  async updateAlertStatus(id: string, status: string): Promise<Alert> {
    const res = await fetch(`${API_BASE}/alerts/${id}/status`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status })
    });
    if (!res.ok) throw new Error('Failed to update alert status');
    return res.json();
  },

  async submitAlertFeedback(id: string, feedbackType: string, notes?: string) {
    const res = await fetch(`${API_BASE}/alerts/${id}/feedback`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        feedback_type: feedbackType,
        analyst_notes: notes,
        adjust_threshold: true
      })
    });
    if (!res.ok) throw new Error('Failed to submit feedback');
    return res.json();
  },

  async executeMitigation(id: string, actionType: string, mode: 'SIMULATED' | 'ACTIVE' = 'SIMULATED') {
    const res = await fetch(`${API_BASE}/alerts/${id}/mitigate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        action_type: actionType,
        execution_mode: mode
      })
    });
    if (!res.ok) throw new Error('Failed to execute mitigation');
    return res.json();
  },

  // Simulation Lab
  async getScenarios(): Promise<SimulationScenario[]> {
    const res = await fetch(`${API_BASE}/simulation/scenarios`);
    if (!res.ok) throw new Error('Failed to fetch simulation scenarios');
    return res.json();
  },

  async launchSimulation(params: {
    scenario: string;
    target_ip: string;
    target_port?: number;
    packet_rate_pps: number;
    duration_seconds: number;
  }): Promise<SimulationRun> {
    const res = await fetch(`${API_BASE}/simulation/execute`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(params)
    });
    if (!res.ok) throw new Error('Failed to launch attack simulation');
    return res.json();
  },

  async getSimulationRuns(): Promise<SimulationRun[]> {
    const res = await fetch(`${API_BASE}/simulation/runs`);
    if (!res.ok) throw new Error('Failed to fetch simulation runs');
    return res.json();
  },

  // Model Analytics
  async getModelAnalytics(): Promise<ModelAnalytics> {
    const res = await fetch(`${API_BASE}/models/analytics`);
    if (!res.ok) throw new Error('Failed to fetch model analytics');
    return res.json();
  },

  async getFeatureImportances(): Promise<FeatureImportance[]> {
    const res = await fetch(`${API_BASE}/models/features`);
    if (!res.ok) throw new Error('Failed to fetch feature importances');
    return res.json();
  },

  // Adaptive Baseline
  async getBaseline() {
    const res = await fetch(`${API_BASE}/adaptive/baseline`);
    if (!res.ok) throw new Error('Failed to fetch baseline profile');
    return res.json();
  },

  async getThresholds(): Promise<AdaptiveThreshold[]> {
    const res = await fetch(`${API_BASE}/adaptive/thresholds`);
    if (!res.ok) throw new Error('Failed to fetch adaptive thresholds');
    return res.json();
  },

  async calibrateThresholds(params: {
    anomaly_sensitivity_factor: number;
    confidence_floor: number;
    syn_flood_ratio_threshold?: number;
    port_entropy_threshold?: number;
  }) {
    const res = await fetch(`${API_BASE}/adaptive/thresholds`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(params)
    });
    if (!res.ok) throw new Error('Failed to calibrate thresholds');
    return res.json();
  }
};
