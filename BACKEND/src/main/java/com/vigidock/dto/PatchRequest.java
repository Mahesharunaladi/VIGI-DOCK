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
public class PatchRequest {

    @NotBlank(message = "patchType is required (DOCKERFILE or K8S)")
    private String patchType;

    private String originalDockerfile;

    private String originalYaml;

    private String vulnerablePackage;

    private String fixedVersion;

    private String misconfigRule;
}
