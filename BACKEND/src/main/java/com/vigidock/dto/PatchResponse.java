package com.vigidock.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PatchResponse {

    private String patchType;
    private String unifiedDiff;
    private String patchedContent;
}
