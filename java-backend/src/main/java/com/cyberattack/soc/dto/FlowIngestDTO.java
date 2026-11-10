package com.cyberattack.soc.dto;

import com.cyberattack.soc.model.enums.DataSource;
import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.util.HashMap;
import java.util.Map;

public class FlowIngestDTO {

    @NotNull(message = "data_source must be specified (OBSERVED, SIMULATED, or DATASET)")
    @JsonAlias({"data_source", "dataSource"})
    private DataSource dataSource = DataSource.OBSERVED;

    @NotBlank(message = "source IP is required")
    @JsonAlias({"src_ip", "srcIp", "source_ip", "sourceIp"})
    private String srcIp;

    @NotNull(message = "source port is required")
    @JsonAlias({"src_port", "srcPort", "source_port", "sourcePort"})
    private Integer srcPort;

    @NotBlank(message = "destination IP is required")
    @JsonAlias({"dst_ip", "dstIp", "destination_ip", "destinationIp"})
    private String dstIp;

    @NotNull(message = "destination port is required")
    @JsonAlias({"dst_port", "dstPort", "destination_port", "destinationPort"})
    private Integer dstPort;

    @JsonAlias({"protocol"})
    private String protocol = "TCP";

    @JsonAlias({"flow_duration", "flowDuration"})
    private Double flowDuration = 0.0;

    @JsonAlias({"tot_fwd_pkts", "totFwdPkts"})
    private Integer totFwdPkts = 1;

    @JsonAlias({"tot_bwd_pkts", "totBwdPkts"})
    private Integer totBwdPkts = 0;

    @JsonAlias({"tot_len_fwd_pkts", "totLenFwdPkts"})
    private Double totLenFwdPkts = 64.0;

    @JsonAlias({"tot_len_bwd_pkts", "totLenBwdPkts"})
    private Double totLenBwdPkts = 0.0;

    @JsonAlias({"flow_bytes_per_sec", "flowBytesPerSec"})
    private Double flowBytesPerSec = 0.0;

    @JsonAlias({"flow_packets_per_sec", "flowPacketsPerSec"})
    private Double flowPacketsPerSec = 0.0;

    @JsonAlias({"syn_flag_cnt", "synFlagCnt"})
    private Integer synFlagCnt = 0;

    @JsonAlias({"ack_flag_cnt", "ackFlagCnt"})
    private Integer ackFlagCnt = 0;

    @JsonAlias({"fin_flag_cnt", "finFlagCnt"})
    private Integer finFlagCnt = 0;

    @JsonAlias({"rst_flag_cnt", "rstFlagCnt"})
    private Integer rstFlagCnt = 0;

    @JsonAlias({"port_entropy", "portEntropy"})
    private Double portEntropy = 0.0;

    @JsonAlias({"simulation_run_id", "simulationRunId"})
    private String simulationRunId;

    @JsonAlias({"raw_features", "rawFeatures"})
    private Map<String, Object> rawFeatures = new HashMap<>();

    public FlowIngestDTO() {}

    // Getters and Setters
    public DataSource getDataSource() { return dataSource; }
    public void setDataSource(DataSource dataSource) { this.dataSource = dataSource; }

    public String getSrcIp() { return srcIp; }
    public void setSrcIp(String srcIp) { this.srcIp = srcIp; }

    public Integer getSrcPort() { return srcPort; }
    public void setSrcPort(Integer srcPort) { this.srcPort = srcPort; }

    public String getDstIp() { return dstIp; }
    public void setDstIp(String dstIp) { this.dstIp = dstIp; }

    public Integer getDstPort() { return dstPort; }
    public void setDstPort(Integer dstPort) { this.dstPort = dstPort; }

    public String getProtocol() { return protocol; }
    public void setProtocol(String protocol) { this.protocol = protocol; }

    public Double getFlowDuration() { return flowDuration; }
    public void setFlowDuration(Double flowDuration) { this.flowDuration = flowDuration; }

    public Integer getTotFwdPkts() { return totFwdPkts; }
    public void setTotFwdPkts(Integer totFwdPkts) { this.totFwdPkts = totFwdPkts; }

    public Integer getTotBwdPkts() { return totBwdPkts; }
    public void setTotBwdPkts(Integer totBwdPkts) { this.totBwdPkts = totBwdPkts; }

    public Double getTotLenFwdPkts() { return totLenFwdPkts; }
    public void setTotLenFwdPkts(Double totLenFwdPkts) { this.totLenFwdPkts = totLenFwdPkts; }

    public Double getTotLenBwdPkts() { return totLenBwdPkts; }
    public void setTotLenBwdPkts(Double totLenBwdPkts) { this.totLenBwdPkts = totLenBwdPkts; }

    public Double getFlowBytesPerSec() { return flowBytesPerSec; }
    public void setFlowBytesPerSec(Double flowBytesPerSec) { this.flowBytesPerSec = flowBytesPerSec; }

    public Double getFlowPacketsPerSec() { return flowPacketsPerSec; }
    public void setFlowPacketsPerSec(Double flowPacketsPerSec) { this.flowPacketsPerSec = flowPacketsPerSec; }

    public Integer getSynFlagCnt() { return synFlagCnt; }
    public void setSynFlagCnt(Integer synFlagCnt) { this.synFlagCnt = synFlagCnt; }

    public Integer getAckFlagCnt() { return ackFlagCnt; }
    public void setAckFlagCnt(Integer ackFlagCnt) { this.ackFlagCnt = ackFlagCnt; }

    public Integer getFinFlagCnt() { return finFlagCnt; }
    public void setFinFlagCnt(Integer finFlagCnt) { this.finFlagCnt = finFlagCnt; }

    public Integer getRstFlagCnt() { return rstFlagCnt; }
    public void setRstFlagCnt(Integer rstFlagCnt) { this.rstFlagCnt = rstFlagCnt; }

    public Double getPortEntropy() { return portEntropy; }
    public void setPortEntropy(Double portEntropy) { this.portEntropy = portEntropy; }

    public String getSimulationRunId() { return simulationRunId; }
    public void setSimulationRunId(String simulationRunId) { this.simulationRunId = simulationRunId; }

    public Map<String, Object> getRawFeatures() { return rawFeatures; }
    public void setRawFeatures(Map<String, Object> rawFeatures) { this.rawFeatures = rawFeatures; }

    @JsonAnySetter
    public void setAdditionalFeature(String key, Object value) {
        if (this.rawFeatures == null) {
            this.rawFeatures = new HashMap<>();
        }
        this.rawFeatures.put(key, value);
    }
}
