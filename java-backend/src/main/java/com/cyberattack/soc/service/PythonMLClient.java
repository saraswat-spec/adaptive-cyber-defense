package com.cyberattack.soc.service;

import com.cyberattack.soc.dto.PythonMLPredictionRequest;
import com.cyberattack.soc.dto.PythonMLPredictionResponse;
import com.cyberattack.soc.exception.MLServiceUnavailableException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

/**
 * Client for HTTP REST communication with the Python Machine Learning service.
 * Python handles the Scikit-learn models (Isolation Forest & Random Forest)
 * while Java consumes the inference outputs for application business logic.
 */
@Component
public class PythonMLClient {

    private static final Logger logger = LoggerFactory.getLogger(PythonMLClient.class);

    private final RestTemplate restTemplate;

    @Value("${soc.python.ml-url:http://localhost:8000/api/v1}")
    private String pythonServiceBaseUrl;

    public PythonMLClient(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public PythonMLPredictionResponse getInference(PythonMLPredictionRequest request) {
        String targetUrl = pythonServiceBaseUrl + "/ml/predict";
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        HttpEntity<PythonMLPredictionRequest> entity = new HttpEntity<>(request, headers);

        try {
            logger.debug("Dispatching flow vector to Python ML engine at {}", targetUrl);
            ResponseEntity<PythonMLPredictionResponse> response = restTemplate.postForEntity(
                    targetUrl,
                    entity,
                    PythonMLPredictionResponse.class
            );

            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                return response.getBody();
            } else {
                throw new MLServiceUnavailableException("Python ML service returned status: " + response.getStatusCode());
            }
        } catch (Exception ex) {
            logger.warn("Direct /ml/predict unavailable ({}). Attempting fallback to /telemetry/ingest or local heuristic fallback.", ex.getMessage());
            return fallbackInference(request);
        }
    }

    /**
     * Fallback inference in case the Python engine is starting up or unreachable.
     * Clearly tags response with is_fallback=true and prefixed narrative to distinguish
     * from authentic Machine Learning predictions.
     */
    private PythonMLPredictionResponse fallbackInference(PythonMLPredictionRequest req) {
        PythonMLPredictionResponse fallback = new PythonMLPredictionResponse();
        fallback.setIs_fallback(true);

        // Heuristic checks
        if (req.getSyn_flag_cnt() != null && req.getSyn_flag_cnt() > 100) {
            fallback.setRule_triggered(true);
            fallback.setRule_name("RULE_SYN_FLOOD_VOLUMETRIC");
            fallback.setPredicted_class("DoS_DDoS");
            fallback.setClass_probability(0.95);
            fallback.setAnomaly_score(-0.25);
            fallback.setExplanation_narrative("[HEURISTIC FALLBACK - Python ML Engine Offline] Fallback rule evaluation: Severe SYN packet flood detected.");
        } else if (req.getPort_entropy() != null && req.getPort_entropy() > 0.75) {
            fallback.setRule_triggered(true);
            fallback.setRule_name("RULE_PORT_SCAN_HIGH_ENTROPY");
            fallback.setPredicted_class("PortScan");
            fallback.setClass_probability(0.90);
            fallback.setAnomaly_score(-0.20);
            fallback.setExplanation_narrative("[HEURISTIC FALLBACK - Python ML Engine Offline] Fallback rule evaluation: High port dispersion entropy indicates reconnaissance scan.");
        } else {
            fallback.setRule_triggered(false);
            fallback.setPredicted_class("Benign");
            fallback.setClass_probability(0.85);
            fallback.setAnomaly_score(0.08);
            fallback.setExplanation_narrative("[HEURISTIC FALLBACK - Python ML Engine Offline] Baseline flow metrics within normal operational bounds.");
        }
        return fallback;
    }
}
