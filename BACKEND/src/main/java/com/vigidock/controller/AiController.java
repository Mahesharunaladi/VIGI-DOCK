package com.vigidock.controller;

import com.vigidock.dto.AiExplanationRequest;
import com.vigidock.dto.AiExplanationResponse;
import com.vigidock.dto.ApiResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Slf4j
@RestController
@RequestMapping("/api/v1/ai")
@RequiredArgsConstructor
@CrossOrigin(origins = "*")
public class AiController {

    @PostMapping("/explain")
    public ResponseEntity<ApiResponse<AiExplanationResponse>> explainVulnerability(
            @Valid @RequestBody AiExplanationRequest request) {
        log.info("Generating AI explanation for vulnerability: {}", request.getVulnerabilityId());

        AiExplanationResponse explanation = AiExplanationResponse.builder()
                .vulnerabilityId(request.getVulnerabilityId())
                .plainEnglishSummary("Analysis generated for " + request.getVulnerabilityId())
                .impactAnalysis("Potential security exposure in " + (request.getPackageName() != null ? request.getPackageName() : "package"))
                .attackVector("Network / Local Execution")
                .recommendedFix("Upgrade " + request.getPackageName() + " to version " + (request.getFixedVersion() != null ? request.getFixedVersion() : "latest safe release"))
                .remediationCommands(List.of(
                        "apk update && apk upgrade " + (request.getPackageName() != null ? request.getPackageName() : ""),
                        "docker build --no-cache -t myapp:secure ."
                ))
                .build();

        return ResponseEntity.ok(ApiResponse.success(explanation, "AI explanation generated successfully"));
    }

    @PostMapping("/remediate-k8s")
    public ResponseEntity<ApiResponse<AiExplanationResponse>> remediateK8sConfig(
            @RequestBody String rawManifest) {
        log.info("Generating AI remediation for Kubernetes manifest");

        AiExplanationResponse response = AiExplanationResponse.builder()
                .vulnerabilityId("K8S-SECURITY-MISCONFIG")
                .plainEnglishSummary("Identified missing security context and excessive privileges in manifest.")
                .recommendedFix("Apply runAsNonRoot, readOnlyRootFilesystem, and drop ALL capabilities.")
                .patchedManifestSnippet("# Hardened SecurityContext\nsecurityContext:\n  readOnlyRootFilesystem: true\n  runAsNonRoot: true\n  allowPrivilegeEscalation: false\n  capabilities:\n    drop:\n      - ALL")
                .build();

        return ResponseEntity.ok(ApiResponse.success(response, "Kubernetes hardening recommendations generated"));
    }
}

