package com.vigidock.controller;

import com.vigidock.dto.AiExplanationRequest;
import com.vigidock.dto.AiExplanationResponse;
import com.vigidock.dto.ApiResponse;
import com.vigidock.service.AiService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/api/v1/ai")
@RequiredArgsConstructor
@CrossOrigin(origins = "*")
public class AiController {

    private final AiService aiService;

    @PostMapping("/explain")
    public ResponseEntity<ApiResponse<AiExplanationResponse>> explainVulnerability(
            @Valid @RequestBody AiExplanationRequest request) {
        log.info("Generating AI explanation for vulnerability: {}", request.getVulnerabilityId());
        AiExplanationResponse explanation = aiService.explainVulnerability(request);
        return ResponseEntity.ok(ApiResponse.success(explanation, "AI explanation generated successfully"));
    }

    @PostMapping("/remediate-k8s")
    public ResponseEntity<ApiResponse<AiExplanationResponse>> remediateK8sConfig(
            @RequestBody(required = false) String rawManifest) {
        log.info("Generating AI remediation for Kubernetes manifest");
        AiExplanationResponse response = aiService.explainK8sMisconfig("K8S-SECURITY-HARDENING", rawManifest);
        return ResponseEntity.ok(ApiResponse.success(response, "Kubernetes hardening recommendations generated"));
    }
}

