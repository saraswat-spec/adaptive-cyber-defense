package com.cyberattack.soc.dto;

import com.fasterxml.jackson.annotation.JsonAlias;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public class SimulationLaunchDTO {

    @NotBlank(message = "scenario name is required")
    @JsonAlias({"scenario", "scenario_name", "scenarioName"})
    private String scenario = "SYN_FLOOD";

    @NotBlank(message = "target IP is required")
    @JsonAlias({"target_ip", "targetIp"})
    private String targetIp = "10.0.0.5";

    @JsonAlias({"target_port", "targetPort"})
    private Integer targetPort = 80;

    @NotNull
    @Min(value = 10, message = "packet rate must be at least 10 pps")
    @Max(value = 10000, message = "packet rate cannot exceed 10000 pps")
    @JsonAlias({"packet_rate_pps", "packetRatePps"})
    private Integer packetRatePps = 1000;

    @NotNull
    @Min(value = 1, message = "duration must be at least 1 second")
    @Max(value = 60, message = "duration cannot exceed 60 seconds")
    @JsonAlias({"duration_seconds", "durationSeconds"})
    private Double durationSeconds = 5.0;

    public SimulationLaunchDTO() {}

    public String getScenario() { return scenario; }
    public void setScenario(String scenario) { this.scenario = scenario; }

    public String getTargetIp() { return targetIp; }
    public void setTargetIp(String targetIp) { this.targetIp = targetIp; }

    public Integer getTargetPort() { return targetPort; }
    public void setTargetPort(Integer targetPort) { this.targetPort = targetPort; }

    public Integer getPacketRatePps() { return packetRatePps; }
    public void setPacketRatePps(Integer packetRatePps) { this.packetRatePps = packetRatePps; }

    public Double getDurationSeconds() { return durationSeconds; }
    public void setDurationSeconds(Double durationSeconds) { this.durationSeconds = durationSeconds; }
}
