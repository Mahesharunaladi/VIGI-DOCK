package com.vigidock.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AiExplanationRequest {

    @NotBlank(message = "Vulnerability ID (CVE) or issue description is required")
    private String vulnerabilityId;

    private String packageName;

    private String installedVersion;

    private String fixedVersion;

    private String severity;

    private String description;

    private String context; // Dockerfile, K8s YAML snippet, or base image
}

