package com.cyberattack.soc.dto;

import com.cyberattack.soc.model.DetectionResult;
import com.cyberattack.soc.model.NetworkEvent;
import com.cyberattack.soc.model.ThreatAlert;

public class DetectionResponseDTO {
    private NetworkEvent networkEvent;
    private DetectionResult detectionResult;
    private ThreatAlert threatAlert;

    public DetectionResponseDTO() {}

    public DetectionResponseDTO(NetworkEvent networkEvent, DetectionResult detectionResult, ThreatAlert threatAlert) {
        this.networkEvent = networkEvent;
        this.detectionResult = detectionResult;
        this.threatAlert = threatAlert;
    }

    public NetworkEvent getNetworkEvent() { return networkEvent; }
    public void setNetworkEvent(NetworkEvent networkEvent) { this.networkEvent = networkEvent; }

    public DetectionResult getDetectionResult() { return detectionResult; }
    public void setDetectionResult(DetectionResult detectionResult) { this.detectionResult = detectionResult; }

    public ThreatAlert getThreatAlert() { return threatAlert; }
    public void setThreatAlert(ThreatAlert threatAlert) { this.threatAlert = threatAlert; }
}
