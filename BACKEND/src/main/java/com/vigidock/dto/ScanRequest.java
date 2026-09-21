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
public class ScanRequest {

    @NotBlank(message = "Docker image name/tag cannot be blank (e.g. 'nginx:alpine' or 'myrepo/app:v1.0')")
    private String imageName;

    private String severityThreshold; // e.g. "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL"

    private boolean enableAiAnalysis;
}

