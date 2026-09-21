package com.vigidock.controller;

import com.vigidock.dto.AiExplanationRequest;
import com.vigidock.dto.AiExplanationResponse;
import com.vigidock.dto.ApiResponse;
import com.vigidock.dto.K8sMisconfigRequest;
import com.vigidock.service.AiService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping({"/api/ai", "/api/v1/ai"})
@RequiredArgsConstructor
@CrossOrigin(origins = "*")
public class AiController {

    private final AiService aiService;

    /**
     * Generates a plain-English AI explanation & automated remediation for a CVE vulnerability.
     * Endpoint: POST /api/ai/explain-cve (and /api/ai/explain)
     * Payload: { "vulnerabilityId": "CVE-2023-1234", "packageName": "openssl", "installedVersion": "1.1.1t", "fixedVersion": "1.1.1u", "severity": "HIGH", "description": "..." }
     */
    @PostMapping({"/explain-cve", "/explain"})
    public ResponseEntity<ApiResponse<AiExplanationResponse>> explainCve(
            @Valid @RequestBody AiExplanationRequest request) {
        log.info("Received request for AI CVE explanation: {}", request.getVulnerabilityId());
        AiExplanationResponse explanation = aiService.explainVulnerability(request);
        return ResponseEntity.ok(ApiResponse.success(HttpStatus.OK, explanation, "AI explanation generated successfully"));
    }

    /**
     * Generates security context analysis and a hardened Kubernetes YAML snippet for a misconfiguration.
     * Endpoint: POST /api/ai/explain-k8s (and /api/ai/remediate-k8s)
     * Payload: { "misconfigRule": "KSV014 - Root container detected", "yamlContent": "...", "resourceName": "deployment" }
     */
    @PostMapping({"/explain-k8s", "/remediate-k8s"})
    public ResponseEntity<ApiResponse<AiExplanationResponse>> explainK8s(
            @Valid @RequestBody K8sMisconfigRequest request) {
        log.info("Received request for AI K8s remediation: {}", request.getMisconfigRule());
        AiExplanationResponse response = aiService.explainK8sMisconfig(
                request.getMisconfigRule(),
                request.getYamlContent()
        );
        return ResponseEntity.ok(ApiResponse.success(HttpStatus.OK, response, "Kubernetes hardening recommendations generated"));
    }
}
