package com.cyberattack.soc.dto;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.HashMap;
import java.util.Map;

public class PythonMLPredictionRequest {
    private String data_source = "OBSERVED";
    private String src_ip;
    private Integer src_port;
    private String dst_ip;
    private Integer dst_port;
    private String protocol = "TCP";
    private Double flow_duration = 0.0;
    private Integer tot_fwd_pkts = 1;
    private Integer tot_bwd_pkts = 0;
    @JsonProperty("tot_len_fwd_pkts")
    @JsonAlias({"tot_len_fwd_pkts", "totLenFwdPkts"})
    private Double tot_len_fwd_pkts = 64.0;
    @JsonProperty("tot_len_bwd_pkts")
    @JsonAlias({"tot_len_bwd_pkts", "totLenBwdPkts"})
    private Double tot_len_bwd_pkts = 0.0;
    private Double flow_bytes_per_sec = 0.0;
    private Double flow_packets_per_sec = 0.0;
    private Integer syn_flag_cnt = 0;
    private Integer ack_flag_cnt = 0;
    private Integer fin_flag_cnt = 0;
    private Integer rst_flag_cnt = 0;
    private Double port_entropy = 0.0;
    private Map<String, Object> raw_features = new HashMap<>();

    public PythonMLPredictionRequest() {}

    // Getters and Setters
    public String getData_source() { return data_source; }
    public void setData_source(String data_source) { this.data_source = data_source; }

    public String getSrc_ip() { return src_ip; }
    public void setSrc_ip(String src_ip) { this.src_ip = src_ip; }

    public Integer getSrc_port() { return src_port; }
    public void setSrc_port(Integer src_port) { this.src_port = src_port; }

    public String getDst_ip() { return dst_ip; }
    public void setDst_ip(String dst_ip) { this.dst_ip = dst_ip; }

    public Integer getDst_port() { return dst_port; }
    public void setDst_port(Integer dst_port) { this.dst_port = dst_port; }

    public String getProtocol() { return protocol; }
    public void setProtocol(String protocol) { this.protocol = protocol; }

    public Double getFlow_duration() { return flow_duration; }
    public void setFlow_duration(Double flow_duration) { this.flow_duration = flow_duration; }

    public Integer getTot_fwd_pkts() { return tot_fwd_pkts; }
    public void setTot_fwd_pkts(Integer tot_fwd_pkts) { this.tot_fwd_pkts = tot_fwd_pkts; }

    public Integer getTot_bwd_pkts() { return tot_bwd_pkts; }
    public void setTot_bwd_pkts(Integer tot_bwd_pkts) { this.tot_bwd_pkts = tot_bwd_pkts; }

    public Double getTot_len_fwd_pkts() { return tot_len_fwd_pkts; }
    public void setTot_len_fwd_pkts(Double tot_len_fwd_pkts) { this.tot_len_fwd_pkts = tot_len_fwd_pkts; }

    public Double getTot_len_bwd_pkts() { return tot_len_bwd_pkts; }
    public void setTot_len_bwd_pkts(Double tot_len_bwd_pkts) { this.tot_len_bwd_pkts = tot_len_bwd_pkts; }

    public Double getFlow_bytes_per_sec() { return flow_bytes_per_sec; }
    public void setFlow_bytes_per_sec(Double flow_bytes_per_sec) { this.flow_bytes_per_sec = flow_bytes_per_sec; }

    public Double getFlow_packets_per_sec() { return flow_packets_per_sec; }
    public void setFlow_packets_per_sec(Double flow_packets_per_sec) { this.flow_packets_per_sec = flow_packets_per_sec; }

    public Integer getSyn_flag_cnt() { return syn_flag_cnt; }
    public void setSyn_flag_cnt(Integer syn_flag_cnt) { this.syn_flag_cnt = syn_flag_cnt; }

    public Integer getAck_flag_cnt() { return ack_flag_cnt; }
    public void setAck_flag_cnt(Integer ack_flag_cnt) { this.ack_flag_cnt = ack_flag_cnt; }

    public Integer getFin_flag_cnt() { return fin_flag_cnt; }
    public void setFin_flag_cnt(Integer fin_flag_cnt) { this.fin_flag_cnt = fin_flag_cnt; }

    public Integer getRst_flag_cnt() { return rst_flag_cnt; }
    public void setRst_flag_cnt(Integer rst_flag_cnt) { this.rst_flag_cnt = rst_flag_cnt; }

    public Double getPort_entropy() { return port_entropy; }
    public void setPort_entropy(Double port_entropy) { this.port_entropy = port_entropy; }

    public Map<String, Object> getRaw_features() { return raw_features; }
    public void setRaw_features(Map<String, Object> raw_features) { this.raw_features = raw_features; }
}
