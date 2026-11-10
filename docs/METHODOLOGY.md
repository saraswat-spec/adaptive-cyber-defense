# Machine Learning & Detection Methodology (METHODOLOGY.md)

This document provides a rigorous mathematical and algorithmic explanation of the detection models, feature engineering pipelines, explainable AI (XAI), and adaptive feedback mechanisms in the **Adaptive Cyberattack Detection & Prevention System**.

---

## 1. Dataset & Threat Vectors

The detection engine is grounded in empirical network flow captures from the **CICIDS2017 (Canadian Institute for Cybersecurity)** benchmark suite, supplemented with high-fidelity synthetic telemetry adhering to IEEE network flow definitions.

### Modeled Threat Vectors
| Attack Family | Primary Indicator Profile | Network Signature |
|---|---|---|
| **Port Scan / Reconnaissance** | High flow rate, small packet lengths, short durations | Sequential SYN probes across non-standard ports |
| **DDoS (SYN Flood / HTTP)** | Extreme packet rates, disproportionate forward-to-backward ratios | High `syn_flag_count`, near-zero ACK/FIN, high entropy |
| **Brute Force (SSH / Web)** | Repeated failed authentications within narrow time windows | Moderate packet counts, consistent byte lengths |
| **Botnet / C2 Beaconing** | Periodic flow bursts with low jitter | Predictable `flow_duration` intervals and uniform packet sizing |
| **Benign Enterprise Traffic** | Balanced bidirectional flows, standard TCP handshakes | Full SYN-ACK-FIN life cycle, moderate bandwidth |

---

## 2. Feature Extraction & Engineering

Each bidirectional network conversation is condensed into a 40-dimensional feature vector $\mathbf{x} \in \mathbb{R}^{40}$.

### Key Feature Categories
1. **Flow Dynamics:**
   - $\text{flow\_duration}$: Total elapsed flow lifetime in microseconds.
   - $\text{tot\_fwd\_pkts}$, $\text{tot\_bwd\_pkts}$: Packet volumes in forward and reverse directions.
   - $\text{flow\_bytes\_per\_sec}$, $\text{flow\_packets\_per\_sec}$: Instantaneous throughput metrics.
2. **Packet Size Statistics:**
   - $\mu_{\text{length}}$, $\sigma_{\text{length}}$, $\sigma^2_{\text{length}}$: Mean, standard deviation, and variance of packet sizes.
   - $\text{down\_up\_ratio}$: Ratio of backward to forward packet transmissions.
3. **TCP Header & Flag Entropy:**
   - Counts for `SYN`, `ACK`, `FIN`, `RST`, `PSH`, `URG` flags.
   - Initial TCP window sizes (`init_win_bytes_forward`, `init_win_bytes_backward`).
   - Active and idle statistical distributions (`active_mean`, `idle_mean`).

### Feature Normalization
Continuous features are scaled using standard normalization trained strictly on baseline benign enterprise distributions:
$$z_i = \frac{x_i - \mu_{i,\text{baseline}}}{\sigma_{i,\text{baseline}} + \epsilon}$$
where $\epsilon = 10^{-7}$ prevents division by zero.

---

## 3. Dual-Model Machine Learning Engine

The system couples an unsupervised anomaly detector with a supervised classifier to detect both zero-day anomalies and known attack signatures.

```
       +-------------------------------------------------+
       |         Normalized Feature Vector x             |
       +-------------------------------------------------+
                     |                         |
                     v                         v
        +-------------------------+  +-------------------------+
        |    Isolation Forest     |  |      Random Forest      |
        |  (Unsupervised Anomaly) |  |  (Supervised Classifier)|
        +-------------------------+  +-------------------------+
                     |                         |
                     v                         v
          Anomaly Score S_iso            Attack Class + Conf.
                     \                         /
                      \                       /
                       v                     v
              +---------------------------------------+
              |     Hybrid Risk Synthesis Engine      |
              |       RiskScore: 0.0 -> 100.0         |
              +---------------------------------------+
```

### Model 1: Isolation Forest (Unsupervised Anomaly Detection)
- **Architecture:** Ensemble of 150 Isolation Trees.
- **Purpose:** Identifies structural outliers without relying on pre-existing attack signatures.
- **Mechanism:** Isolates points by recursively partitioning random feature intervals. Anomalous network flows exhibit significantly shorter average path lengths $h(\mathbf{x})$.
- **Scoring Function:**
  $$s(\mathbf{x}, n) = 2^{-\frac{\mathbb{E}(h(\mathbf{x}))}{c(n)}}$$
  where $c(n)$ is the average path length of unsuccessful searches in a Binary Search Tree of $n$ samples.

### Model 2: Random Forest (Supervised Attack Classification)
- **Architecture:** 150 Decision Trees with Gini impurity splitting criterion.
- **Purpose:** Classifies detected anomalies into precise threat categories (`PORT_SCAN`, `DDOS_SYN_FLOOD`, `SSH_BRUTE_FORCE`, `BENIGN`).
- **Output:** Class probability distribution $\mathbf{p} = [p_1, p_2, \dots, p_K]$ where confidence $C = \max_k(p_k)$.

---

## 4. Hybrid Detection & Risk Synthesis

The final risk assessment combines heuristic rule matches, supervised classification confidence, and unsupervised anomaly severity:

$$\text{RiskScore} = w_{\text{rule}} \cdot S_{\text{rule}} + w_{\text{rf}} \cdot (C_{\text{rf}} \times 100) + w_{\text{iso}} \cdot S_{\text{anomaly}}$$

### Configured Hyperparameters
- $w_{\text{rule}} = 0.35$ (Deterministic signature weight)
- $w_{\text{rf}} = 0.45$ (Supervised ML confidence weight)
- $w_{\text{iso}} = 0.20$ (Statistical anomaly weight)

### Risk Tiers & Triage Policy
| Composite Score | Severity Level | Automated Action |
|---|---|---|
| **0.0 - 39.9** | `LOW` | Log telemetry event; no alert generated |
| **40.0 - 59.9** | `MEDIUM` | Surface informational alert in SOC feed |
| **60.0 - 79.9** | `HIGH` | Generate alert; recommend rate-limiting |
| **80.0 - 100.0** | `CRITICAL` | Generate urgent alert; stage automated host/IP isolation |

---

## 5. Explainable AI (XAI) Architecture

To eliminate "black-box" decisions in high-stakes security operations, every generated alert includes local feature attribution and human-readable natural language explanations.

### Local Feature Attribution
For each feature $i$, the relative attribution score $A_i$ is computed from its standardized variance against baseline normal behavior:
$$A_i = \frac{|z_i|}{\sum_{j=1}^{40} |z_j|}$$

The top 5 contributing features are extracted with their observed value, expected baseline mean, and percentage contribution.

### Natural Language Synthesis
An automated narrative summarizer generates analyst briefing statements:
> *"Elevated risk of 88.5/100 detected for flow 10.0.0.5 -> 192.168.1.10:21. The decision is predominantly driven by high flow_packets_per_second (14,210 pps vs baseline 85.0 pps, contributing 34.2%) and syn_flag_count (contributing 28.5%), indicating an active SYN Flood or rapid Port Reconnaissance campaign."*

---

## 6. Adaptive Feedback & Threshold Recalibration

The system incorporates human-in-the-loop analyst feedback to iteratively tune detection boundaries without causing model drift or destabilization.

```
       +---------------------------------------------+
       |             Analyst Feedback                |
       +---------------------------------------------+
                       /             \
                      /               \
         CONFIRMED_THREAT            FALSE_POSITIVE
                    /                   \
                   v                     v
   +-----------------------+     +-------------------------------+
   | Preserve Baseline     |     | Check Quorum (N >= 2)         |
   | Update Threat Intel   |     | Controlled Bounded Adjustment |
   | Thresholds Unchanged  |     | Record Audit Trail            |
   +-----------------------+     +-------------------------------+
```

### Feedback Decision Matrix
1. **`CONFIRMED_THREAT`:**
   - Validates that the alert correctly identified a genuine security violation.
   - **Crucial Rule:** Thresholds are **not** lowered or modified. Lowering thresholds on confirmed attacks would widen the attack window for adversaries. `threshold_adjusted` is strictly set to `false`.
2. **`FALSE_POSITIVE`:**
   - Signals that normal business activity triggered an alert.
   - **Quorum Requirement:** Requires at least $N = 2$ validated feedback records to prevent isolated operational anomalies from perturbing system baselines.
   - **Bounded Calibration Formula:**
     $$\theta_{t+1} = \theta_t + \Delta \cdot \alpha$$
     where $\alpha = 0.05$ is the controlled learning rate.
   - **Safety Boundary Clamping:**
     $$\theta_{\text{anomaly}} \ge 0.0020 \quad \text{(prevents blindness to subtle anomalies)}$$
     $$\theta_{\text{syn\_flood}} \le 0.95 \quad \text{(prevents ignoring massive SYN storms)}$$
   - An immutable audit trail records `previous_threshold`, `current_threshold`, and the specific analyst justification.
