package com.vigidock.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class AnsibleDeployRequest {
    @NotBlank private String manifestYaml;
    private String targetNamespace = "default";
    private String targetEnvironment = "LOCAL";
    private String scanId;
}
