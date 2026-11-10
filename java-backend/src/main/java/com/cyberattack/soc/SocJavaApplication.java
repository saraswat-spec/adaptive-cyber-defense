package com.cyberattack.soc;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Adaptive Cyberattack Detection and Prevention System (Mini-SOC)
 * Java Spring Boot Main Application.
 *
 * Implements core application business logic, risk scoring, alert triage,
 * incident containment, and adaptive baseline threshold adaptation,
 * with machine-learning inference delegated via REST to the Python ML engine.
 */
@SpringBootApplication
public class SocJavaApplication {

    public static void main(String[] args) {
        SpringApplication.run(SocJavaApplication.class, args);
    }
}
