package com.cyberattack.soc.service;

import com.cyberattack.soc.dto.SimulationLaunchDTO;
import com.cyberattack.soc.model.SimulationRun;

import java.util.List;
import java.util.Map;

public interface SimulationService {
    List<Map<String, Object>> getScenarioTemplates();
    SimulationRun executeSimulation(SimulationLaunchDTO dto);
    List<SimulationRun> getSimulationRuns();
}
