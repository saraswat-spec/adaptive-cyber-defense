"""
Network Flow Feature Engineering Pipeline.
Standardizes, cleans, and extracts 40 high-signal flow metrics
modeled after standard intrusion detection datasets (CIC-IDS2017 & NSL-KDD).
"""

import json
import os
from typing import Dict, List, Any, Tuple
import numpy as np
import pandas as pd
from sklearn.preprocessing import RobustScaler
import joblib

FEATURE_NAMES: List[str] = [
    # Flow Timing
    "flow_duration",
    "fwd_iat_mean",
    "fwd_iat_std",
    "fwd_iat_max",
    "fwd_iat_min",
    "bwd_iat_mean",
    "bwd_iat_std",
    "bwd_iat_max",
    "bwd_iat_min",
    # Volume & Rates
    "tot_fwd_pkts",
    "tot_bwd_pkts",
    "tot_len_fwd_pkts",
    "tot_len_bwd_pkts",
    "flow_bytes_per_sec",
    "flow_packets_per_sec",
    # Packet Length Stats
    "fwd_pkt_len_max",
    "fwd_pkt_len_min",
    "fwd_pkt_len_mean",
    "fwd_pkt_len_std",
    "bwd_pkt_len_max",
    "bwd_pkt_len_min",
    "bwd_pkt_len_mean",
    "bwd_pkt_len_std",
    "pkt_len_mean",
    "pkt_len_std",
    "pkt_len_var",
    # TCP Flags
    "fin_flag_cnt",
    "syn_flag_cnt",
    "rst_flag_cnt",
    "psh_flag_cnt",
    "ack_flag_cnt",
    "urg_flag_cnt",
    "ece_flag_cnt",
    # Ratios & Entropy
    "down_up_ratio",
    "pkt_size_avg",
    "fwd_seg_size_avg",
    "bwd_seg_size_avg",
    "subflow_fwd_pkts",
    "subflow_fwd_bytes",
    "port_entropy",
]

ATTACK_CLASSES: List[str] = [
    "Benign",
    "DoS_DDoS",
    "PortScan",
    "BruteForce",
    "WebAttack",
    "Infiltration"
]

class NetworkFeaturePipeline:
    def __init__(self, scaler_path: str = None):
        self.feature_names = FEATURE_NAMES
        self.scaler = None
        if scaler_path and os.path.exists(scaler_path):
            self.load_scaler(scaler_path)

    def fit_scaler(self, df: pd.DataFrame) -> RobustScaler:
        """Fits a RobustScaler on feature columns, resilient to outlier spikes."""
        X = self._prepare_matrix(df)
        self.scaler = RobustScaler()
        self.scaler.fit(X)
        return self.scaler

    def transform(self, df: pd.DataFrame) -> np.ndarray:
        """Transforms DataFrame into clean, scaled numpy feature matrix."""
        X = self._prepare_matrix(df)
        if self.scaler is not None:
            return self.scaler.transform(X)
        return X

    def transform_single_flow(self, flow_dict: Dict[str, Any]) -> Tuple[np.ndarray, np.ndarray]:
        """
        Transforms a single flow dictionary into:
        (raw_vector, scaled_vector) of shape (1, 40).
        """
        row = []
        for feat in self.feature_names:
            val = flow_dict.get(feat, 0.0)
            if val is None or np.isnan(val) or np.isinf(val):
                val = 0.0
            row.append(float(val))

        raw_vec = np.array(row, dtype=np.float32).reshape(1, -1)
        if self.scaler is not None:
            scaled_vec = self.scaler.transform(raw_vec)
        else:
            scaled_vec = raw_vec.copy()

        return raw_vec, scaled_vec

    def _prepare_matrix(self, df: pd.DataFrame) -> np.ndarray:
        """Ensures all 40 features exist, filling missing/inf values."""
        df_clean = df.copy()
        for feat in self.feature_names:
            if feat not in df_clean.columns:
                df_clean[feat] = 0.0

        # Select exact features in order
        matrix = df_clean[self.feature_names].to_numpy(dtype=np.float32)
        # Replace inf and nan
        matrix = np.nan_to_num(matrix, nan=0.0, posinf=1e6, neginf=-1e6)
        return matrix

    def save_scaler(self, path: str):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        joblib.dump(self.scaler, path)

    def load_scaler(self, path: str):
        self.scaler = joblib.load(path)
