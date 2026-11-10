package com.cyberattack.soc.controller;

import com.cyberattack.soc.dto.DetectionResponseDTO;
import com.cyberattack.soc.dto.FlowIngestDTO;
import com.cyberattack.soc.dto.StatsResponseDTO;
import com.cyberattack.soc.model.NetworkEvent;
import com.cyberattack.soc.model.enums.DataSource;
import com.cyberattack.soc.service.DetectionService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * Controller exposing Telemetry and Network Flow Ingestion endpoints.
 * Handles incoming network flows, delegates to the ML pipeline and risk scoring engine,
 * and serves telemetry monitoring data.
 */
@RestController
@RequestMapping("/api/v1/telemetry")
public class DetectionController {

    private final DetectionService detectionService;

    public DetectionController(DetectionService detectionService) {
        this.detectionService = detectionService;
    }

    /**
     * Ingest and evaluate a single network flow telemetry event.
     */
    @PostMapping("/ingest")
    public ResponseEntity<DetectionResponseDTO> ingestFlow(@Valid @RequestBody FlowIngestDTO dto) {
        DetectionResponseDTO response = detectionService.processEvent(dto);
        return new ResponseEntity<>(response, HttpStatus.CREATED);
    }

    /**
     * Retrieve recent network flow events with filtering.
     */
    @GetMapping("/flows")
    public ResponseEntity<List<NetworkEvent>> getFlows(
            @RequestParam(defaultValue = "50") int limit,
            @RequestParam(defaultValue = "0") int offset,
            @RequestParam(defaultValue = "ALL") String source) {

        DataSource dataSource = null;
        if (!"ALL".equalsIgnoreCase(source)) {
            try {
                dataSource = DataSource.valueOf(source.toUpperCase());
            } catch (IllegalArgumentException ignored) {
            }
        }

        List<NetworkEvent> events = detectionService.getRecentEvents(limit, dataSource);
        return ResponseEntity.ok(events);
    }

    /**
     * Retrieve real-time telemetry metrics and volume statistics.
     */
    @GetMapping("/stats")
    public ResponseEntity<StatsResponseDTO> getTelemetryStats() {
        StatsResponseDTO stats = detectionService.getTelemetryStats();
        return ResponseEntity.ok(stats);
    }
}
