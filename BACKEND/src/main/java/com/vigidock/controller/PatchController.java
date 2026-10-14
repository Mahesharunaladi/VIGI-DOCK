package com.vigidock.controller;

import com.vigidock.dto.ApiResponse;
import com.vigidock.dto.PatchRequest;
import com.vigidock.dto.PatchResponse;
import com.vigidock.service.GitPatchService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping({"/api/fix", "/api/v1/fix"})
@RequiredArgsConstructor
public class PatchController {

    private final GitPatchService gitPatchService;

    @PostMapping("/generate-patch")
    public ResponseEntity<ApiResponse<PatchResponse>> generatePatch(@Valid @RequestBody PatchRequest request) {
        String patchType = request.getPatchType().trim().toUpperCase();
        log.info("Generating automated patch for type: {}", patchType);

        PatchResponse response;
        if ("DOCKERFILE".equals(patchType) || "DOCKER".equals(patchType)) {
            String patched = gitPatchService.generatePatchedDockerfile(
                    request.getOriginalDockerfile(),
                    request.getVulnerablePackage(),
                    request.getFixedVersion()
            );
            response = PatchResponse.builder()
                    .patchType("DOCKERFILE")
                    .patchedContent(patched)
                    .unifiedDiff(gitPatchService.toUnifiedDiff("Dockerfile", request.getOriginalDockerfile(), patched))
                    .build();
        } else if ("K8S".equals(patchType) || "KUBERNETES".equals(patchType) || "YAML".equals(patchType)) {
            String patched = gitPatchService.generateK8sYamlFix(request.getOriginalYaml(), request.getMisconfigRule());
            response = PatchResponse.builder()
                    .patchType("K8S")
                    .patchedContent(patched)
                    .unifiedDiff(gitPatchService.toUnifiedDiff(
                            "manifest.yaml",
                            request.getOriginalYaml() == null ? "" : request.getOriginalYaml(),
                            patched))
                    .build();
        } else {
            throw new IllegalArgumentException("Unsupported patchType. Use DOCKERFILE or K8S.");
        }

        return ResponseEntity.ok(ApiResponse.success(HttpStatus.OK, response, "Remediation patch generated successfully"));
    }
}
