import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from app.services.hybrid_detector import detector
from synthetic_data_generator import generate_benign_flow, generate_portscan_flow, generate_dos_ddos_flow

print("=== TEST 1: Model & Artifact Loading ===")
assert detector.iso_forest is not None, "Isolation Forest not loaded"
assert detector.rf_classifier is not None, "Random Forest not loaded"
assert detector.pipeline.scaler is not None, "Scaler not loaded"
assert detector.xai_engine is not None, "XAI Engine not loaded"
print("  [PASS] All 4 ML artifacts loaded successfully.")

print("=== TEST 2: Benign Flow Inference ===")
benign_flow = generate_benign_flow()
flow_record, alert = detector.process_flow(benign_flow)
assert alert is None, "Expected no alert for normal benign traffic"
print("  [PASS] Benign flow processed without false positive alert.")

print("=== TEST 3: PortScan Attack Inference ===")
portscan_flow = generate_portscan_flow()
flow_record, alert = detector.process_flow(portscan_flow)
assert alert is not None, "Expected alert for PortScan attack"
assert alert.get("risk_level") in ["HIGH", "CRITICAL"]
print(f"  [PASS] PortScan alert detected: type={alert.get('attack_type')}, risk={alert.get('risk_score')}, level={alert.get('risk_level')}")

print("=== TEST 4: DDoS Attack Inference ===")
ddos_flow = generate_dos_ddos_flow()
flow_record, alert_ddos = detector.process_flow(ddos_flow)
assert alert_ddos is not None, "Expected alert for DDoS attack"
print(f"  [PASS] DDoS alert detected: type={alert_ddos.get('attack_type')}, risk={alert_ddos.get('risk_score')}")

print("=== TEST 5: FastAPI Router & Health Probe ===")
from fastapi.testclient import TestClient
from main import app
client = TestClient(app)
res_health = client.get("/health")
assert res_health.status_code == 200, "Health check failed"
assert res_health.json().get("status") == "healthy", "Status should be healthy"
print(f"  [PASS] Health check returned 200 OK: {res_health.json().get('service')}")

print("\nALL 5 PYTHON ML SUITE TESTS COMPLETED: 5/5 PASSED, 0 FAILED.")
