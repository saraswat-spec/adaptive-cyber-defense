package com.cyberattack.soc.service;

import com.cyberattack.soc.dto.DetectionResponseDTO;
import com.cyberattack.soc.dto.FlowIngestDTO;
import com.cyberattack.soc.dto.StatsResponseDTO;
import com.cyberattack.soc.model.NetworkEvent;
import com.cyberattack.soc.model.enums.DataSource;

import java.util.List;

public interface DetectionService {
    DetectionResponseDTO processEvent(FlowIngestDTO dto);
    List<NetworkEvent> getRecentEvents(int limit, DataSource source);
    StatsResponseDTO getTelemetryStats();
}
