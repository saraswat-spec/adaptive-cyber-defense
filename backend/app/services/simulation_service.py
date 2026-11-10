"""
Attack Simulation Laboratory Service.
Drives realistic synthetic attack scenarios, tagging all telemetry strictly with
data_source='SIMULATED' and delivering real-time outcomes to the SOC.
"""

import asyncio
from datetime import datetime, timezone
import random
from typing import Dict, Any, List
import uuid

from app.db.storage import db_store
from app.services.hybrid_detector import detector
from synthetic_data_generator import (
    generate_dos_ddos_flow,
    generate_portscan_flow,
    generate_bruteforce_flow,
    generate_webattack_flow,
    generate_infiltration_flow
)

class SimulationService:
    @staticmethod
    async def run_scenario_async(
        run_id: str,
        scenario: str,
        target_ip: str,
        target_port: int,
        duration: float,
        packet_rate: int
    ):
        """Asynchronously executes the attack simulation over duration seconds."""
        total_packets = 0
        detected_alerts = 0
        iterations = max(1, int(duration * 2))  # Generate 2 pulses per second
        sleep_interval = duration / iterations

        try:
            for i in range(iterations):
                # Select scenario generator
                if scenario == "SYN_FLOOD":
                    flow = generate_dos_ddos_flow(source_label="SIMULATED")
                elif scenario == "PORT_SCAN":
                    flow = generate_portscan_flow(source_label="SIMULATED")
                elif scenario == "BRUTE_FORCE":
                    flow = generate_bruteforce_flow(source_label="SIMULATED")
                elif scenario == "WEB_ATTACK":
                    flow = generate_webattack_flow(source_label="SIMULATED")
                elif scenario == "INFILTRATION_BEACON":
                    flow = generate_infiltration_flow(source_label="SIMULATED")
                else:
                    flow = generate_dos_ddos_flow(source_label="SIMULATED")

                # Override target parameters if specified
                flow["dst_ip"] = target_ip
                if target_port:
                    flow["dst_port"] = target_port
                flow["simulation_run_id"] = run_id

                # Calculate packet increment
                fwd = flow.get("tot_fwd_pkts", 100)
                total_packets += fwd

                # Run through Hybrid Detection Engine
                _, alert = detector.process_flow(flow)
                if alert:
                    detected_alerts += 1

                # Update live progress
                db_store.update_simulation_run(run_id, {
                    "total_packets_injected": total_packets,
                    "detected_alerts_count": detected_alerts
                })

                await asyncio.sleep(sleep_interval)

            # Mark completed
            db_store.update_simulation_run(run_id, {
                "status": "COMPLETED",
                "ended_at": datetime.now(timezone.utc),
                "total_packets_injected": total_packets,
                "detected_alerts_count": detected_alerts
            })

        except Exception as e:
            print(f"Error in simulation execution: {e}")
            db_store.update_simulation_run(run_id, {
                "status": "FAILED",
                "ended_at": datetime.now(timezone.utc)
            })

    @staticmethod
    def launch(
        scenario: str,
        target_ip: str,
        target_port: int,
        duration: float,
        packet_rate: int
    ) -> Dict[str, Any]:
        """Creates run record and schedules asynchronous execution."""
        run_id = str(uuid.uuid4())
        run_record = {
            "id": run_id,
            "scenario_name": scenario,
            "target_ip": target_ip,
            "target_port": target_port,
            "duration_seconds": duration,
            "total_packets_injected": 0,
            "detected_alerts_count": 0,
            "status": "RUNNING",
            "started_at": datetime.now(timezone.utc),
            "ended_at": None
        }

        db_store.insert_simulation_run(run_record)

        # Launch async task
        asyncio.create_task(
            SimulationService.run_scenario_async(
                run_id=run_id,
                scenario=scenario,
                target_ip=target_ip,
                target_port=target_port,
                duration=duration,
                packet_rate=packet_rate
            )
        )

        return run_record
