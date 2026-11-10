package com.cyberattack.soc.model;

import com.cyberattack.soc.model.enums.DataSource;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.time.LocalDateTime;
import java.util.Objects;
import java.util.UUID;

/**
 * Represents an individual network flow observation or attack lab test event.
 */
@Entity
@Table(name = "network_events")
public class NetworkEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @NotNull
    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private DataSource dataSource;

    @Column(nullable = false)
    private LocalDateTime timestamp;

    @NotBlank
    @Column(nullable = false, length = 45)
    private String sourceIp;

    @NotNull
    @Column(nullable = false)
    private Integer sourcePort;

    @NotBlank
    @Column(nullable = false, length = 45)
    private String destinationIp;

    @NotNull
    @Column(nullable = false)
    private Integer destinationPort;

    @NotBlank
    @Column(nullable = false, length = 10)
    private String protocol;

    private Double flowDuration = 0.0;
    private Integer totalForwardPackets = 1;
    private Integer totalBackwardPackets = 0;
    private Double totalLengthForwardPackets = 64.0;
    private Double totalLengthBackwardPackets = 0.0;
    private Double flowBytesPerSecond = 0.0;
    private Double flowPacketsPerSecond = 0.0;
    private Integer synFlagCount = 0;
    private Integer ackFlagCount = 0;
    private Integer finFlagCount = 0;
    private Integer rstFlagCount = 0;
    private Double portEntropy = 0.0;
    private Double synRatio = 0.0;

    private String simulationRunId;

    // Constructors
    public NetworkEvent() {
        this.timestamp = LocalDateTime.now();
        this.dataSource = DataSource.OBSERVED;
    }

    public NetworkEvent(DataSource dataSource, String sourceIp, Integer sourcePort,
                        String destinationIp, Integer destinationPort, String protocol) {
        this();
        this.dataSource = dataSource;
        this.sourceIp = sourceIp;
        this.sourcePort = sourcePort;
        this.destinationIp = destinationIp;
        this.destinationPort = destinationPort;
        this.protocol = protocol;
    }

    // Encapsulation: Getters and Setters
    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public DataSource getDataSource() {
        return dataSource;
    }

    public void setDataSource(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(LocalDateTime timestamp) {
        this.timestamp = timestamp;
    }

    public String getSourceIp() {
        return sourceIp;
    }

    public void setSourceIp(String sourceIp) {
        this.sourceIp = sourceIp;
    }

    public Integer getSourcePort() {
        return sourcePort;
    }

    public void setSourcePort(Integer sourcePort) {
        this.sourcePort = sourcePort;
    }

    public String getDestinationIp() {
        return destinationIp;
    }

    public void setDestinationIp(String destinationIp) {
        this.destinationIp = destinationIp;
    }

    public Integer getDestinationPort() {
        return destinationPort;
    }

    public void setDestinationPort(Integer destinationPort) {
        this.destinationPort = destinationPort;
    }

    public String getProtocol() {
        return protocol;
    }

    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }

    public Double getFlowDuration() {
        return flowDuration;
    }

    public void setFlowDuration(Double flowDuration) {
        this.flowDuration = flowDuration;
    }

    public Integer getTotalForwardPackets() {
        return totalForwardPackets;
    }

    public void setTotalForwardPackets(Integer totalForwardPackets) {
        this.totalForwardPackets = totalForwardPackets;
    }

    public Integer getTotalBackwardPackets() {
        return totalBackwardPackets;
    }

    public void setTotalBackwardPackets(Integer totalBackwardPackets) {
        this.totalBackwardPackets = totalBackwardPackets;
    }

    public Double getFlowBytesPerSecond() {
        return flowBytesPerSecond;
    }

    public void setFlowBytesPerSecond(Double flowBytesPerSecond) {
        this.flowBytesPerSecond = flowBytesPerSecond;
    }

    public Double getFlowPacketsPerSecond() {
        return flowPacketsPerSecond;
    }

    public void setFlowPacketsPerSecond(Double flowPacketsPerSecond) {
        this.flowPacketsPerSecond = flowPacketsPerSecond;
    }

    public Integer getSynFlagCount() {
        return synFlagCount;
    }

    public void setSynFlagCount(Integer synFlagCount) {
        this.synFlagCount = synFlagCount;
    }

    public Integer getAckFlagCount() {
        return ackFlagCount;
    }

    public void setAckFlagCount(Integer ackFlagCount) {
        this.ackFlagCount = ackFlagCount;
    }

    public Integer getFinFlagCount() {
        return finFlagCount;
    }

    public void setFinFlagCount(Integer finFlagCount) {
        this.finFlagCount = finFlagCount;
    }

    public Integer getRstFlagCount() {
        return rstFlagCount;
    }

    public void setRstFlagCount(Integer rstFlagCount) {
        this.rstFlagCount = rstFlagCount;
    }

    public Double getPortEntropy() {
        return portEntropy;
    }

    public void setPortEntropy(Double portEntropy) {
        this.portEntropy = portEntropy;
    }

    public Double getSynRatio() {
        return synRatio;
    }

    public void setSynRatio(Double synRatio) {
        this.synRatio = synRatio;
    }

    public String getSimulationRunId() {
        return simulationRunId;
    }

    public void setSimulationRunId(String simulationRunId) {
        this.simulationRunId = simulationRunId;
    }

    public Double getTotalLengthForwardPackets() {
        return totalLengthForwardPackets;
    }

    public void setTotalLengthForwardPackets(Double totalLengthForwardPackets) {
        this.totalLengthForwardPackets = totalLengthForwardPackets;
    }

    public Double getTotalLengthBackwardPackets() {
        return totalLengthBackwardPackets;
    }

    public void setTotalLengthBackwardPackets(Double totalLengthBackwardPackets) {
        this.totalLengthBackwardPackets = totalLengthBackwardPackets;
    }

    // Frontend compatibility aliases
    @JsonProperty("tot_len_fwd_pkts")
    public Double getTotLenFwdPkts() {
        return totalLengthForwardPackets;
    }

    @JsonProperty("tot_len_bwd_pkts")
    public Double getTotLenBwdPkts() {
        return totalLengthBackwardPackets;
    }

    @JsonProperty("src_ip")
    public String getSrcIp() {
        return sourceIp;
    }

    @JsonProperty("dst_ip")
    public String getDstIp() {
        return destinationIp;
    }

    @JsonProperty("src_port")
    public Integer getSrcPort() {
        return sourcePort;
    }

    @JsonProperty("dst_port")
    public Integer getDstPort() {
        return destinationPort;
    }

    @JsonProperty("tot_fwd_pkts")
    public Integer getTotFwdPkts() {
        return totalForwardPackets;
    }

    @JsonProperty("tot_bwd_pkts")
    public Integer getTotBwdPkts() {
        return totalBackwardPackets;
    }

    @JsonProperty("flow_bytes_per_sec")
    public Double getFlowBytesPerSec() {
        return flowBytesPerSecond;
    }

    @JsonProperty("flow_packets_per_sec")
    public Double getFlowPacketsPerSec() {
        return flowPacketsPerSecond;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        NetworkEvent that = (NetworkEvent) o;
        return Objects.equals(id, that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }

    @Override
    public String toString() {
        return "NetworkEvent{" +
                "id=" + id +
                ", dataSource=" + dataSource +
                ", sourceIp='" + sourceIp + '\'' +
                ", destinationIp='" + destinationIp + '\'' +
                ", protocol='" + protocol + '\'' +
                ", flowPacketsPerSecond=" + flowPacketsPerSecond +
                '}';
    }
}
