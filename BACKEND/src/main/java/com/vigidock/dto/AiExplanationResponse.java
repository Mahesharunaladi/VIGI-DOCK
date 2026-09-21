package com.vigidock.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AiExplanationResponse {

    private String vulnerabilityId;
    private String plainEnglishSummary;
    private String impactAnalysis;
    private String attackVector;
    private String recommendedFix;
    private List<String> remediationCommands;
    private String patchedManifestSnippet;
}

