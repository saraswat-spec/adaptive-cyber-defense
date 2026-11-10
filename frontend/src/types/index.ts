export type DataSource = 'OBSERVED' | 'SIMULATED' | 'DATASET';
export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type AlertStatus = 'NEW' | 'INVESTIGATING' | 'RESOLVED' | 'FALSE_POSITIVE';
export type Protocol = 'TCP' | 'UDP' | 'ICMP' | 'OTHER';

export interface FlowRecord {
  id: string;
  data_source: DataSource;
  timestamp: string;
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  protocol: Protocol;
  flow_duration: number;
  flow_bytes_per_sec?: number;
  flow_packets_per_sec?: number;
  tot_fwd_pkts?: number;
  tot_bwd_pkts?: number;
  syn_ratio?: number;
  risk_score?: number;
  classified_attack?: string;
  simulation_run_id?: string;

  // Backend compatibility properties
  total_forward_packets?: number;
  total_backward_packets?: number;
  flow_bytes_per_second?: number;
  flow_packets_per_second?: number;
  total_length_forward_packets?: number;
  total_length_backward_packets?: number;
  tot_len_fwd_pkts?: number;
  tot_len_bwd_pkts?: number;
  source_ip?: string;
  destination_ip?: string;
  source_port?: number;
  destination_port?: number;
}

export interface FeatureAttribution {
  feature: string;
  label: string;
  observed_value: number;
  baseline_mean: number;
  baseline_std: number;
  z_score: number;
  direction: 'ABOVE_NORMAL' | 'BELOW_NORMAL';
  unit: string;
}

export interface AlertExplanation {
  top_features: FeatureAttribution[];
  narrative: string;
  anomaly_score: number;
  risk_score: number;
}

export interface MitigationAction {
  action_type: 'BLOCK_IP' | 'RATE_LIMIT' | 'ISOLATE_HOST' | 'NOTIFY_WEBHOOK';
  target_ip: string;
  generated_script: string;
  status: 'RECOMMENDED' | 'SIMULATED_APPLIED' | 'APPLIED' | 'DISMISSED';
  created_at: string;
}

export interface Alert {
  id: string;
  flow_id?: string;
  data_source: DataSource;
  timestamp: string;
  risk_score: number;
  risk_level: RiskLevel;
  attack_type: string;
  confidence: number;
  status: AlertStatus;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: string;
  rule_triggered: boolean;
  ml_triggered: boolean;
  explanation?: AlertExplanation;
  mitigations?: MitigationAction[];
}

export interface SimulationScenario {
  id: string;
  name: string;
  description: string;
  category: string;
  default_rate_pps: number;
  default_duration_sec: number;
  targeted_ports: number[];
}

export interface SimulationRun {
  id: string;
  scenario_name: string;
  target_ip: string;
  target_port?: number;
  total_packets_injected: number;
  duration_seconds: number;
  status: 'RUNNING' | 'COMPLETED' | 'FAILED';
  started_at: string;
  ended_at?: string;
  detected_alerts_count: number;
}

export interface AdaptiveThreshold {
  metric_name: string;
  current_threshold: number;
  previous_threshold: number;
  baseline_mean: number;
  baseline_std: number;
  false_positive_rate_window: number;
  reason?: string;
  updated_at: string;
}

export interface ConfusionMatrixCell {
  actual: string;
  predicted: string;
  count: number;
}

export interface ModelAnalytics {
  overall: {
    accuracy: number;
    precision: number;
    recall: number;
    f1_score: number;
    roc_auc: number;
  };
  anomaly_detection: {
    detection_rate: number;
    false_alarm_rate: number;
    true_positives: number;
    false_positives: number;
    true_negatives: number;
    false_negatives: number;
  };
  confusion_matrix_grid: number[][];
  confusion_matrix_records: ConfusionMatrixCell[];
  class_metrics: Record<string, {
    precision: number;
    recall: number;
    f1_score: number;
    support: number;
  }>;
  classes: string[];
}

export interface FeatureImportance {
  feature: string;
  importance: number;
}
