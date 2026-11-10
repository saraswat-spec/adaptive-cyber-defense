package com.cyberattack.soc.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.Map;

/**
 * Health check controller for container orchestrators, cloud hosting platforms (e.g. Render),
 * and deployment monitoring.
 */
@RestController
public class HealthController {

    @GetMapping({"/health", "/api/v1/health"})
    public ResponseEntity<Map<String, Object>> healthCheck() {
        return ResponseEntity.ok(Map.of(
                "status", "UP",
                "service", "soc-java-backend",
                "version", "1.0.0",
                "timestamp", Instant.now().toString()
        ));
    }
}
