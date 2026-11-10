"""
Deterministic Rule-Based Signature & Heuristic Engine.
Rapidly filters known threat signatures, TCP flag violations, and rate breaches.
"""

from typing import Dict, Any, Tuple, Optional

class RuleEngine:
    @staticmethod
    def evaluate(flow: Dict[str, Any]) -> Tuple[bool, Optional[str], float]:
        """
        Evaluates heuristic rules on incoming flow dictionary.
        Returns: (is_triggered, matched_rule_name, confidence_boost)
        """
        fwd_pkts = float(flow.get("tot_fwd_pkts", 1))
        bwd_pkts = float(flow.get("tot_bwd_pkts", 0))
        syn_cnt = float(flow.get("syn_flag_cnt", 0))
        ack_cnt = float(flow.get("ack_flag_cnt", 0))
        pps = float(flow.get("flow_packets_per_sec", 0))
        bps = float(flow.get("flow_bytes_per_sec", 0))
        entropy = float(flow.get("port_entropy", 0.0))
        dst_port = int(flow.get("dst_port", 0))
        mean_pkt_len = float(flow.get("pkt_len_mean", 0))

        # Calculate SYN ratio
        syn_ratio = syn_cnt / max(1.0, fwd_pkts + bwd_pkts)

        # Rule 1: SYN Flood Detection
        if syn_cnt > 50 and syn_ratio > 0.80 and pps > 400:
            return True, "RULE_SYN_FLOOD_VOLUMETRIC", 0.95

        # Rule 2: Reconnaissance / Port Scan Heuristic
        if entropy > 0.75 and fwd_pkts > 15 and mean_pkt_len < 65:
            return True, "RULE_PORT_SCAN_HIGH_ENTROPY", 0.90

        # Rule 3: Authentication Brute Force
        if dst_port in [22, 21, 3389] and fwd_pkts > 30 and flow.get("flow_duration", 0) > 3.0:
            return True, "RULE_AUTH_PORT_BURST", 0.85

        # Rule 4: Extreme Volumetric Outlier
        if pps > 3000 or bps > 10_000_000:
            return True, "RULE_RATE_LIMIT_EXCEEDED", 0.88

        # Rule 5: Illegal TCP Flag Combinations (XMAS / NULL scans)
        fin = int(flow.get("fin_flag_cnt", 0))
        psh = int(flow.get("psh_flag_cnt", 0))
        urg = int(flow.get("urg_flag_cnt", 0))
        if fin == 1 and psh == 1 and urg == 1:
            return True, "RULE_TCP_XMAS_SCAN_FLAGS", 0.98
        if fwd_pkts > 5 and syn_cnt == 0 and ack_cnt == 0 and fin == 0:
            return True, "RULE_TCP_NULL_SCAN_FLAGS", 0.98

        return False, None, 0.0
