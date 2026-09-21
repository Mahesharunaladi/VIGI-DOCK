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
public class K8sMisconfigRequest {

    @NotBlank(message = "Misconfiguration rule or title is required (e.g. 'KSV014 - Root container detected')")
    private String misconfigRule;

    private String yamlContent;

    private String resourceName;

    private String severity;
}
