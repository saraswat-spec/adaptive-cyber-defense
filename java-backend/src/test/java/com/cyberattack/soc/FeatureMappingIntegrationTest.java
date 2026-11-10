package com.cyberattack.soc;

import com.cyberattack.soc.dto.DetectionResponseDTO;
import com.cyberattack.soc.dto.FlowIngestDTO;
import com.cyberattack.soc.model.NetworkEvent;
import com.cyberattack.soc.model.enums.DataSource;
import com.cyberattack.soc.service.DetectionService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.*;

@SpringBootTest
public class FeatureMappingIntegrationTest {

    @Autowired
    private DetectionService detectionService;

    @Autowired
    private RestTemplate restTemplate;

    private MockRestServiceServer mockServer;

    @BeforeEach
    public void setup() {
        mockServer = MockRestServiceServer.createServer(restTemplate);
    }

    @Test
    public void testForwardAndBackwardPacketBytesPreservedE2E() {
        // Prepare ingest request with exact packet byte values
        FlowIngestDTO dto = new FlowIngestDTO();
        dto.setDataSource(DataSource.SIMULATED);
        dto.setSrcIp("192.168.1.105");
        dto.setSrcPort(49152);
        dto.setDstIp("10.0.0.5");
        dto.setDstPort(443);
        dto.setProtocol("TCP");
        dto.setFlowDuration(2.45);
        dto.setTotFwdPkts(14);
        dto.setTotBwdPkts(18);
        dto.setTotLenFwdPkts(4900.0);
        dto.setTotLenBwdPkts(15300.0);
        dto.setFlowBytesPerSec(8244.9);
        dto.setFlowPacketsPerSec(13.06);
        dto.setSynFlagCnt(1);
        dto.setAckFlagCnt(31);
        dto.setFinFlagCnt(1);
        dto.setRstFlagCnt(0);
        dto.setPortEntropy(0.15);

        Map<String, Object> raw = new HashMap<>();
        raw.put("fwd_iat_mean", 0.175);
        raw.put("bwd_iat_mean", 0.136);
        dto.setRawFeatures(raw);

        // Expect the Python ML service to receive the exact forward and backward packet byte counts
        String pythonResponseJson = """
            {
                "anomaly_score": 0.0791,
                "predicted_class": "Benign",
                "class_probability": 0.96,
                "rule_triggered": false,
                "rule_name": null,
                "rule_confidence": 0.0,
                "explanation_narrative": "Flow behavior adheres closely to historical benign baselines.",
                "top_features": []
            }
            """;

        mockServer.expect(requestTo("http://localhost:8000/api/v1/ml/predict"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(jsonPath("$.tot_len_fwd_pkts").value(4900.0))
                .andExpect(jsonPath("$.tot_len_bwd_pkts").value(15300.0))
                .andExpect(jsonPath("$.raw_features.tot_len_fwd_pkts").value(4900.0))
                .andExpect(jsonPath("$.raw_features.tot_len_bwd_pkts").value(15300.0))
                .andRespond(withSuccess(pythonResponseJson, MediaType.APPLICATION_JSON));

        // Execute DetectionService
        DetectionResponseDTO response = detectionService.processEvent(dto);

        // Verify Mock Expectations
        mockServer.verify();

        // Verify Java NetworkEvent entity persistence
        NetworkEvent event = response.getNetworkEvent();
        assertNotNull(event);
        assertEquals(4900.0, event.getTotalLengthForwardPackets());
        assertEquals(15300.0, event.getTotalLengthBackwardPackets());
        assertEquals(4900.0, event.getTotLenFwdPkts());
        assertEquals(15300.0, event.getTotLenBwdPkts());

        // Verify detection result
        assertNotNull(response.getDetectionResult());
        assertFalse(response.getDetectionResult().isFallbackUsed());
        assertEquals("Benign", response.getDetectionResult().getPredictedAttackClass());
    }
}
