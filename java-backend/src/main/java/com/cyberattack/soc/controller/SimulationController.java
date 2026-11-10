package com.cyberattack.soc.controller;

import com.cyberattack.soc.dto.SimulationLaunchDTO;
import com.cyberattack.soc.model.SimulationRun;
import com.cyberattack.soc.service.SimulationService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * Controller for the Red-Team Attack Simulation Laboratory.
 * Manages attack presets, scenario launches, and historical simulation test logs.
 */
@RestController
@RequestMapping("/api/v1/simulation")
public class SimulationController {

    private final SimulationService simulationService;

    public SimulationController(SimulationService simulationService) {
        this.simulationService = simulationService;
    }

    /**
     * Get predefined red-team attack scenarios (SYN Flood, Port Scan, Brute Force, Web Exploit, C2 Beacon).
     */
    @GetMapping("/scenarios")
    public ResponseEntity<List<Map<String, Object>>> getScenarios() {
        List<Map<String, Object>> scenarios = simulationService.getScenarioTemplates();
        return ResponseEntity.ok(scenarios);
    }

    /**
     * Launch an attack simulation run.
     */
    @PostMapping("/execute")
    public ResponseEntity<SimulationRun> executeSimulation(@Valid @RequestBody SimulationLaunchDTO dto) {
        SimulationRun runResult = simulationService.executeSimulation(dto);
        return new ResponseEntity<>(runResult, HttpStatus.ACCEPTED);
    }

    /**
     * Retrieve execution history of simulation runs.
     */
    @GetMapping("/runs")
    public ResponseEntity<List<SimulationRun>> getSimulationRuns() {
        List<SimulationRun> runs = simulationService.getSimulationRuns();
        return ResponseEntity.ok(runs);
    }
}
