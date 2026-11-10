"""
Synthetic Network Flow Generator.
Creates scientifically grounded network flows modeled after real-world SOC benchmarks.
Supports both training dataset generation and real-time Attack Simulation Laboratory feeds.
"""

import os
import random
from typing import Dict, List, Any
import numpy as np
import pandas as pd
from feature_pipeline import FEATURE_NAMES, ATTACK_CLASSES

def generate_benign_flow(source_label: str = "OBSERVED") -> Dict[str, Any]:
    """Simulates normal enterprise network traffic (HTTP, HTTPS, DNS, API)."""
    duration = float(np.random.exponential(scale=2.5) + 0.05)
    fwd_pkts = int(np.random.poisson(lam=12) + 2)
    bwd_pkts = int(np.random.poisson(lam=16) + 2)
    tot_bytes = (fwd_pkts * np.random.normal(350, 80)) + (bwd_pkts * np.random.normal(850, 150))
    tot_bytes = max(100.0, float(tot_bytes))

    flow = {
        "data_source": source_label,
        "attack_class": "Benign",
        "src_ip": f"192.168.1.{random.randint(10, 250)}",
        "src_port": random.randint(32768, 65535),
        "dst_ip": random.choice(["10.0.0.5", "10.0.0.10", "172.16.0.4", "8.8.8.8", "1.1.1.1"]),
        "dst_port": random.choice([80, 443, 53, 8080, 8443]),
        "protocol": "TCP" if random.random() > 0.1 else "UDP",
        # Features
        "flow_duration": duration,
        "fwd_iat_mean": float(duration / max(1, fwd_pkts)),
        "fwd_iat_std": float(np.random.uniform(0.01, 0.2)),
        "fwd_iat_max": float(duration * 0.4),
        "fwd_iat_min": float(0.001),
        "bwd_iat_mean": float(duration / max(1, bwd_pkts)),
        "bwd_iat_std": float(np.random.uniform(0.01, 0.2)),
        "bwd_iat_max": float(duration * 0.35),
        "bwd_iat_min": float(0.001),
        "tot_fwd_pkts": fwd_pkts,
        "tot_bwd_pkts": bwd_pkts,
        "tot_len_fwd_pkts": float(fwd_pkts * np.random.normal(350, 50)),
        "tot_len_bwd_pkts": float(bwd_pkts * np.random.normal(850, 100)),
        "flow_bytes_per_sec": float(tot_bytes / max(0.01, duration)),
        "flow_packets_per_sec": float((fwd_pkts + bwd_pkts) / max(0.01, duration)),
        "fwd_pkt_len_max": float(np.random.uniform(500, 1460)),
        "fwd_pkt_len_min": float(np.random.uniform(40, 64)),
        "fwd_pkt_len_mean": float(np.random.uniform(200, 450)),
        "fwd_pkt_len_std": float(np.random.uniform(50, 150)),
        "bwd_pkt_len_max": float(np.random.uniform(1000, 1500)),
        "bwd_pkt_len_min": float(np.random.uniform(40, 64)),
        "bwd_pkt_len_mean": float(np.random.uniform(600, 950)),
        "bwd_pkt_len_std": float(np.random.uniform(100, 250)),
        "pkt_len_mean": float(tot_bytes / max(1, fwd_pkts + bwd_pkts)),
        "pkt_len_std": float(np.random.uniform(80, 200)),
        "pkt_len_var": float(np.random.uniform(6400, 40000)),
        # Flags
        "fin_flag_cnt": 1 if random.random() > 0.3 else 0,
        "syn_flag_cnt": 1,
        "rst_flag_cnt": 0,
        "psh_flag_cnt": random.randint(1, 4),
        "ack_flag_cnt": fwd_pkts + bwd_pkts - 1,
        "urg_flag_cnt": 0,
        "ece_flag_cnt": 0,
        # Ratios
        "down_up_ratio": float(bwd_pkts / max(1, fwd_pkts)),
        "pkt_size_avg": float(tot_bytes / max(1, fwd_pkts + bwd_pkts)),
        "fwd_seg_size_avg": float(350.0),
        "bwd_seg_size_avg": float(850.0),
        "subflow_fwd_pkts": fwd_pkts,
        "subflow_fwd_bytes": float(fwd_pkts * 350.0),
        "port_entropy": float(np.random.uniform(0.05, 0.25)),
    }
    return flow

def generate_dos_ddos_flow(source_label: str = "SIMULATED") -> Dict[str, Any]:
    """Simulates DoS/DDoS (SYN flood, UDP storm, volumetric amplification)."""
    duration = float(np.random.uniform(0.1, 1.5))
    fwd_pkts = int(np.random.uniform(500, 5000))
    bwd_pkts = int(np.random.uniform(0, 5))  # Barely any replies received
    tot_bytes = float(fwd_pkts * np.random.uniform(64, 128))

    flow = {
        "data_source": source_label,
        "attack_class": "DoS_DDoS",
        "src_ip": f"203.0.113.{random.randint(1, 254)}",
        "src_port": random.randint(1024, 65535),
        "dst_ip": "10.0.0.5",
        "dst_port": random.choice([80, 443]),
        "protocol": "TCP",
        "flow_duration": duration,
        "fwd_iat_mean": float(duration / max(1, fwd_pkts)),
        "fwd_iat_std": float(0.0001),
        "fwd_iat_max": float(duration * 0.05),
        "fwd_iat_min": float(0.00001),
        "bwd_iat_mean": 0.0,
        "bwd_iat_std": 0.0,
        "bwd_iat_max": 0.0,
        "bwd_iat_min": 0.0,
        "tot_fwd_pkts": fwd_pkts,
        "tot_bwd_pkts": bwd_pkts,
        "tot_len_fwd_pkts": tot_bytes,
        "tot_len_bwd_pkts": float(bwd_pkts * 40),
        "flow_bytes_per_sec": float(tot_bytes / max(0.001, duration)),
        "flow_packets_per_sec": float(fwd_pkts / max(0.001, duration)),  # Massive PPS
        "fwd_pkt_len_max": float(128.0),
        "fwd_pkt_len_min": float(40.0),
        "fwd_pkt_len_mean": float(64.0),
        "fwd_pkt_len_std": float(10.0),
        "bwd_pkt_len_max": float(40.0),
        "bwd_pkt_len_min": float(40.0),
        "bwd_pkt_len_mean": float(40.0),
        "bwd_pkt_len_std": float(0.0),
        "pkt_len_mean": float(64.0),
        "pkt_len_std": float(8.0),
        "pkt_len_var": float(64.0),
        "fin_flag_cnt": 0,
        "syn_flag_cnt": fwd_pkts,  # Pure SYN flood
        "rst_flag_cnt": 0,
        "psh_flag_cnt": 0,
        "ack_flag_cnt": 0,
        "urg_flag_cnt": 0,
        "ece_flag_cnt": 0,
        "down_up_ratio": 0.0,
        "pkt_size_avg": 64.0,
        "fwd_seg_size_avg": 64.0,
        "bwd_seg_size_avg": 0.0,
        "subflow_fwd_pkts": fwd_pkts,
        "subflow_fwd_bytes": tot_bytes,
        "port_entropy": float(np.random.uniform(0.01, 0.1)),
    }
    return flow

def generate_portscan_flow(source_label: str = "SIMULATED") -> Dict[str, Any]:
    """Simulates Reconnaissance / Port Scan (Nmap SYN scan, port sweeps)."""
    duration = float(np.random.uniform(0.05, 0.8))
    fwd_pkts = int(np.random.uniform(20, 100))
    bwd_pkts = int(np.random.uniform(0, 10))
    tot_bytes = float(fwd_pkts * 44.0)

    flow = {
        "data_source": source_label,
        "attack_class": "PortScan",
        "src_ip": f"198.51.100.{random.randint(10, 80)}",
        "src_port": random.randint(40000, 60000),
        "dst_ip": "10.0.0.10",
        "dst_port": random.randint(1, 1024),
        "protocol": "TCP",
        "flow_duration": duration,
        "fwd_iat_mean": float(duration / max(1, fwd_pkts)),
        "fwd_iat_std": float(0.005),
        "fwd_iat_max": float(duration * 0.1),
        "fwd_iat_min": float(0.001),
        "bwd_iat_mean": 0.01,
        "bwd_iat_std": 0.005,
        "bwd_iat_max": 0.02,
        "bwd_iat_min": 0.001,
        "tot_fwd_pkts": fwd_pkts,
        "tot_bwd_pkts": bwd_pkts,
        "tot_len_fwd_pkts": tot_bytes,
        "tot_len_bwd_pkts": float(bwd_pkts * 40.0),
        "flow_bytes_per_sec": float(tot_bytes / max(0.01, duration)),
        "flow_packets_per_sec": float((fwd_pkts + bwd_pkts) / max(0.01, duration)),
        "fwd_pkt_len_max": float(44.0),
        "fwd_pkt_len_min": float(40.0),
        "fwd_pkt_len_mean": float(42.0),
        "fwd_pkt_len_std": float(1.5),
        "bwd_pkt_len_max": float(40.0),
        "bwd_pkt_len_min": float(40.0),
        "bwd_pkt_len_mean": float(40.0),
        "bwd_pkt_len_std": float(0.0),
        "pkt_len_mean": float(42.0),
        "pkt_len_std": float(1.5),
        "pkt_len_var": float(2.25),
        "fin_flag_cnt": 0,
        "syn_flag_cnt": fwd_pkts,
        "rst_flag_cnt": bwd_pkts,  # RST returned by closed ports
        "psh_flag_cnt": 0,
        "ack_flag_cnt": 0,
        "urg_flag_cnt": 0,
        "ece_flag_cnt": 0,
        "down_up_ratio": float(bwd_pkts / max(1, fwd_pkts)),
        "pkt_size_avg": 42.0,
        "fwd_seg_size_avg": 42.0,
        "bwd_seg_size_avg": 40.0,
        "subflow_fwd_pkts": fwd_pkts,
        "subflow_fwd_bytes": tot_bytes,
        "port_entropy": float(np.random.uniform(0.85, 0.99)),  # High port entropy!
    }
    return flow

def generate_bruteforce_flow(source_label: str = "SIMULATED") -> Dict[str, Any]:
    """Simulates credential brute-force attacks against SSH/FTP/Auth endpoints."""
    duration = float(np.random.uniform(4.0, 15.0))
    fwd_pkts = int(np.random.uniform(30, 120))
    bwd_pkts = int(np.random.uniform(25, 110))
    tot_bytes = float((fwd_pkts + bwd_pkts) * np.random.uniform(100, 200))

    flow = {
        "data_source": source_label,
        "attack_class": "BruteForce",
        "src_ip": f"198.51.100.{random.randint(120, 220)}",
        "src_port": random.randint(30000, 60000),
        "dst_ip": "10.0.0.5",
        "dst_port": random.choice([22, 21, 3389]),
        "protocol": "TCP",
        "flow_duration": duration,
        "fwd_iat_mean": float(duration / max(1, fwd_pkts)),
        "fwd_iat_std": float(0.05),
        "fwd_iat_max": float(0.8),
        "fwd_iat_min": float(0.01),
        "bwd_iat_mean": float(duration / max(1, bwd_pkts)),
        "bwd_iat_std": float(0.05),
        "bwd_iat_max": float(0.8),
        "bwd_iat_min": float(0.01),
        "tot_fwd_pkts": fwd_pkts,
        "tot_bwd_pkts": bwd_pkts,
        "tot_len_fwd_pkts": float(fwd_pkts * 120.0),
        "tot_len_bwd_pkts": float(bwd_pkts * 110.0),
        "flow_bytes_per_sec": float(tot_bytes / max(0.1, duration)),
        "flow_packets_per_sec": float((fwd_pkts + bwd_pkts) / max(0.1, duration)),
        "fwd_pkt_len_max": float(250.0),
        "fwd_pkt_len_min": float(40.0),
        "fwd_pkt_len_mean": float(120.0),
        "fwd_pkt_len_std": float(45.0),
        "bwd_pkt_len_max": float(200.0),
        "bwd_pkt_len_min": float(40.0),
        "bwd_pkt_len_mean": float(110.0),
        "bwd_pkt_len_std": float(35.0),
        "pkt_len_mean": float(115.0),
        "pkt_len_std": float(40.0),
        "pkt_len_var": float(1600.0),
        "fin_flag_cnt": int(np.random.uniform(5, 20)),
        "syn_flag_cnt": int(np.random.uniform(5, 20)),
        "rst_flag_cnt": int(np.random.uniform(2, 10)),
        "psh_flag_cnt": int(np.random.uniform(10, 40)),
        "ack_flag_cnt": fwd_pkts + bwd_pkts,
        "urg_flag_cnt": 0,
        "ece_flag_cnt": 0,
        "down_up_ratio": float(bwd_pkts / max(1, fwd_pkts)),
        "pkt_size_avg": 115.0,
        "fwd_seg_size_avg": 120.0,
        "bwd_seg_size_avg": 110.0,
        "subflow_fwd_pkts": fwd_pkts,
        "subflow_fwd_bytes": float(fwd_pkts * 120.0),
        "port_entropy": float(np.random.uniform(0.01, 0.08)),  # Targeted to single service
    }
    return flow

def generate_webattack_flow(source_label: str = "SIMULATED") -> Dict[str, Any]:
    """Simulates Web Application attacks (SQLi, XSS, Directory Traversal payloads)."""
    duration = float(np.random.uniform(0.5, 3.0))
    fwd_pkts = int(np.random.uniform(8, 25))
    bwd_pkts = int(np.random.uniform(6, 20))
    fwd_payload_len = float(np.random.uniform(1800, 4500))  # Extended query/payload length
    tot_bytes = fwd_payload_len + (bwd_pkts * 450.0)

    flow = {
        "data_source": source_label,
        "attack_class": "WebAttack",
        "src_ip": f"198.51.100.{random.randint(5, 50)}",
        "src_port": random.randint(32000, 61000),
        "dst_ip": "10.0.0.5",
        "dst_port": random.choice([80, 443, 8080]),
        "protocol": "TCP",
        "flow_duration": duration,
        "fwd_iat_mean": float(duration / max(1, fwd_pkts)),
        "fwd_iat_std": float(0.02),
        "fwd_iat_max": float(duration * 0.4),
        "fwd_iat_min": float(0.005),
        "bwd_iat_mean": float(duration / max(1, bwd_pkts)),
        "bwd_iat_std": float(0.02),
        "bwd_iat_max": float(duration * 0.3),
        "bwd_iat_min": float(0.005),
        "tot_fwd_pkts": fwd_pkts,
        "tot_bwd_pkts": bwd_pkts,
        "tot_len_fwd_pkts": fwd_payload_len,
        "tot_len_bwd_pkts": float(bwd_pkts * 450.0),
        "flow_bytes_per_sec": float(tot_bytes / max(0.1, duration)),
        "flow_packets_per_sec": float((fwd_pkts + bwd_pkts) / max(0.1, duration)),
        "fwd_pkt_len_max": float(np.random.uniform(1460, 2800)),
        "fwd_pkt_len_min": float(40.0),
        "fwd_pkt_len_mean": float(fwd_payload_len / max(1, fwd_pkts)),
        "fwd_pkt_len_std": float(np.random.uniform(200, 500)),
        "bwd_pkt_len_max": float(800.0),
        "bwd_pkt_len_min": float(40.0),
        "bwd_pkt_len_mean": float(450.0),
        "bwd_pkt_len_std": float(120.0),
        "pkt_len_mean": float(tot_bytes / max(1, fwd_pkts + bwd_pkts)),
        "pkt_len_std": float(250.0),
        "pkt_len_var": float(62500.0),
        "fin_flag_cnt": 1,
        "syn_flag_cnt": 1,
        "rst_flag_cnt": 0,
        "psh_flag_cnt": int(np.random.uniform(3, 8)),
        "ack_flag_cnt": fwd_pkts + bwd_pkts - 1,
        "urg_flag_cnt": 0,
        "ece_flag_cnt": 0,
        "down_up_ratio": float(bwd_pkts / max(1, fwd_pkts)),
        "pkt_size_avg": float(tot_bytes / max(1, fwd_pkts + bwd_pkts)),
        "fwd_seg_size_avg": float(fwd_payload_len / max(1, fwd_pkts)),
        "bwd_seg_size_avg": 450.0,
        "subflow_fwd_pkts": fwd_pkts,
        "subflow_fwd_bytes": fwd_payload_len,
        "port_entropy": float(np.random.uniform(0.05, 0.15)),
    }
    return flow

def generate_infiltration_flow(source_label: str = "SIMULATED") -> Dict[str, Any]:
    """Simulates Botnet C2 beaconing and stealthy data staging."""
    duration = float(np.random.uniform(30.0, 120.0))
    fwd_pkts = int(np.random.uniform(5, 15))
    bwd_pkts = int(np.random.uniform(5, 15))
    tot_bytes = float((fwd_pkts + bwd_pkts) * np.random.uniform(60, 100))

    flow = {
        "data_source": source_label,
        "attack_class": "Infiltration",
        "src_ip": "10.0.0.10",
        "src_port": random.randint(49152, 65535),
        "dst_ip": f"198.51.100.{random.randint(230, 254)}",
        "dst_port": random.choice([443, 8443, 53]),
        "protocol": "TCP",
        "flow_duration": duration,
        "fwd_iat_mean": float(duration / max(1, fwd_pkts)),
        "fwd_iat_std": float(0.001),  # Highly periodic beaconing!
        "fwd_iat_max": float(duration * 0.3),
        "fwd_iat_min": float(1.0),
        "bwd_iat_mean": float(duration / max(1, bwd_pkts)),
        "bwd_iat_std": float(0.001),
        "bwd_iat_max": float(duration * 0.3),
        "bwd_iat_min": float(1.0),
        "tot_fwd_pkts": fwd_pkts,
        "tot_bwd_pkts": bwd_pkts,
        "tot_len_fwd_pkts": float(fwd_pkts * 80.0),
        "tot_len_bwd_pkts": float(bwd_pkts * 70.0),
        "flow_bytes_per_sec": float(tot_bytes / duration),
        "flow_packets_per_sec": float((fwd_pkts + bwd_pkts) / duration),
        "fwd_pkt_len_max": float(120.0),
        "fwd_pkt_len_min": float(40.0),
        "fwd_pkt_len_mean": float(80.0),
        "fwd_pkt_len_std": float(15.0),
        "bwd_pkt_len_max": float(100.0),
        "bwd_pkt_len_min": float(40.0),
        "bwd_pkt_len_mean": float(70.0),
        "bwd_pkt_len_std": float(12.0),
        "pkt_len_mean": float(75.0),
        "pkt_len_std": float(14.0),
        "pkt_len_var": float(196.0),
        "fin_flag_cnt": 1,
        "syn_flag_cnt": 1,
        "rst_flag_cnt": 0,
        "psh_flag_cnt": 2,
        "ack_flag_cnt": fwd_pkts + bwd_pkts - 1,
        "urg_flag_cnt": 0,
        "ece_flag_cnt": 0,
        "down_up_ratio": 1.0,
        "pkt_size_avg": 75.0,
        "fwd_seg_size_avg": 80.0,
        "bwd_seg_size_avg": 70.0,
        "subflow_fwd_pkts": fwd_pkts,
        "subflow_fwd_bytes": float(fwd_pkts * 80.0),
        "port_entropy": float(0.01),
    }
    return flow

def generate_dataset(n_samples: int = 10000, benign_ratio: float = 0.70) -> pd.DataFrame:
    """
    Generates a full training dataset with balanced attack classes and realistic noise.
    """
    n_benign = int(n_samples * benign_ratio)
    n_attacks = n_samples - n_benign
    attacks_per_class = n_attacks // 5

    rows = []
    # Benign (Observed baseline)
    for _ in range(n_benign):
        rows.append(generate_benign_flow(source_label="OBSERVED"))

    # Attack classes
    for _ in range(attacks_per_class):
        rows.append(generate_dos_ddos_flow(source_label="SIMULATED"))
    for _ in range(attacks_per_class):
        rows.append(generate_portscan_flow(source_label="SIMULATED"))
    for _ in range(attacks_per_class):
        rows.append(generate_bruteforce_flow(source_label="SIMULATED"))
    for _ in range(attacks_per_class):
        rows.append(generate_webattack_flow(source_label="SIMULATED"))
    for _ in range(attacks_per_class):
        rows.append(generate_infiltration_flow(source_label="SIMULATED"))

    df = pd.DataFrame(rows)
    # Shuffle
    df = df.sample(frac=1.0, random_state=42).reset_index(drop=True)
    return df

if __name__ == "__main__":
    os.makedirs("artifacts", exist_ok=True)
    print("Generating 10,000 synthetic network flow dataset...")
    df = generate_dataset(n_samples=10000, benign_ratio=0.70)
    out_csv = "artifacts/training_dataset.csv"
    df.to_csv(out_csv, index=False)
    print(f"Dataset generated successfully -> {out_csv}")
    print("Class distribution:")
    print(df["attack_class"].value_counts())
