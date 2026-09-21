package com.vigidock.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.vigidock.dto.AiExplanationRequest;
import com.vigidock.dto.AiExplanationResponse;
import com.vigidock.entity.VulnerabilityDetail;
import com.vigidock.exception.VigiDockException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;

import java.util.ArrayList;
import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class AiService {

    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;

    @Value("${vigidock.ai.gemini.api-key:${gemini.api.key:}}")
    private String geminiApiKey;

    @Value("${vigidock.ai.gemini.model:gemini-1.5-flash}")
    private String geminiModel;

    @Value("${vigidock.ai.gemini.api-url:https://generativelanguage.googleapis.com/v1beta/models}")
    private String geminiApiUrl;

    /**
     * Generates a plain-English explanation and fix for a VulnerabilityDetail entity.
     *
     * @param cve Vulnerability detail entity containing CVE ID, package, and description
     * @return Structured AI explanation response
     */
    public AiExplanationResponse explainVulnerability(VulnerabilityDetail cve) {
        if (cve == null) {
            throw new IllegalArgumentException("Vulnerability detail cannot be null");
        }

        AiExplanationRequest request = AiExplanationRequest.builder()
                .vulnerabilityId(cve.getVulnerabilityId())
                .packageName(cve.getPackageName())
                .installedVersion(cve.getInstalledVersion())
                .fixedVersion(cve.getFixedVersion())
                .severity(cve.getSeverity())
                .description(cve.getDescription())
                .build();

        return explainVulnerability(request);
    }

    /**
     * Generates a plain-English explanation and fix for an AiExplanationRequest DTO.
     *
     * @param request AI explanation request DTO
     * @return Structured AI explanation response
     */
    public AiExplanationResponse explainVulnerability(AiExplanationRequest request) {
        if (request == null || !StringUtils.hasText(request.getVulnerabilityId())) {
            throw new IllegalArgumentException("Vulnerability ID is required for AI explanation");
        }

        log.info("Requesting Gemini AI explanation for CVE: {}", request.getVulnerabilityId());

        if (!StringUtils.hasText(geminiApiKey)) {
            log.warn("Gemini API key is not configured. Returning deterministic fallback explanation.");
            return buildFallbackVulnerabilityExplanation(request);
        }

        String prompt = buildVulnerabilityPrompt(request);

        try {
            String rawJsonResponse = callGeminiApi(prompt);
            return parseAiExplanationResponse(rawJsonResponse, request.getVulnerabilityId());
        } catch (Exception e) {
            log.error("Failed to generate AI explanation via Gemini API: {}. Falling back to default response.", e.getMessage());
            return buildFallbackVulnerabilityExplanation(request);
        }
    }

    /**
     * Generates plain-English context and a corrected Kubernetes YAML snippet for a misconfiguration.
     *
     * @param misconfigRule The misconfiguration rule or title (e.g. "KSV014 - Root container detected")
     * @param yamlContent   The problematic Kubernetes YAML manifest snippet
     * @return Structured AI explanation with patched YAML snippet
     */
    public AiExplanationResponse explainK8sMisconfig(String misconfigRule, String yamlContent) {
        if (!StringUtils.hasText(misconfigRule)) {
            throw new IllegalArgumentException("Misconfiguration rule cannot be null or empty");
        }

        log.info("Requesting Gemini AI remediation for K8s misconfig: {}", misconfigRule);

        if (!StringUtils.hasText(geminiApiKey)) {
            log.warn("Gemini API key is not configured. Returning fallback K8s remediation.");
            return buildFallbackK8sRemediation(misconfigRule, yamlContent);
        }

        String prompt = buildK8sMisconfigPrompt(misconfigRule, yamlContent);

        try {
            String rawJsonResponse = callGeminiApi(prompt);
            return parseAiExplanationResponse(rawJsonResponse, misconfigRule);
        } catch (Exception e) {
            log.error("Failed to generate K8s AI remediation via Gemini API: {}. Falling back to default response.", e.getMessage());
            return buildFallbackK8sRemediation(misconfigRule, yamlContent);
        }
    }

    /**
     * Executes the Gemini generateContent REST call forcing a JSON response schema.
     */
    private String callGeminiApi(String promptText) throws Exception {
        String endpoint = String.format("%s/%s:generateContent?key=%s", geminiApiUrl, geminiModel, geminiApiKey);

        // Build Gemini Request Payload
        ObjectNode rootNode = objectMapper.createObjectNode();

        ArrayNode contentsArray = rootNode.putArray("contents");
        ObjectNode contentObj = contentsArray.addObject();
        ArrayNode partsArray = contentObj.putArray("parts");
        partsArray.addObject().put("text", promptText);

        ObjectNode generationConfig = rootNode.putObject("generationConfig");
        generationConfig.put("responseMimeType", "application/json");
        generationConfig.put("temperature", 0.2);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        HttpEntity<String> httpEntity = new HttpEntity<>(objectMapper.writeValueAsString(rootNode), headers);
        ResponseEntity<String> response = restTemplate.exchange(endpoint, HttpMethod.POST, httpEntity, String.class);

        if (!response.getStatusCode().is2xxSuccessful() || !StringUtils.hasText(response.getBody())) {
            throw new VigiDockException("Gemini API returned non-200 status: " + response.getStatusCode());
        }

        // Extract the generated text from Gemini response structure: candidates[0].content.parts[0].text
        JsonNode responseJson = objectMapper.readTree(response.getBody());
        JsonNode textNode = responseJson.path("candidates")
                .path(0)
                .path("content")
                .path("parts")
                .path(0)
                .path("text");

        if (textNode.isMissingNode() || !StringUtils.hasText(textNode.asText())) {
            throw new VigiDockException("Empty text content in Gemini response candidates");
        }

        return textNode.asText();
    }

    private String buildVulnerabilityPrompt(AiExplanationRequest req) {
        return String.format("""
            You are a Senior Principal Security Engineer & DevSecOps Expert.
            Analyze the following container vulnerability and provide a clear, beginner-friendly explanation along with exact remediation steps.

            Vulnerability Details:
            - CVE / Issue ID: %s
            - Affected Package: %s
            - Installed Version: %s
            - Fixed Version: %s
            - Severity: %s
            - Description: %s
            - Additional Context: %s

            You MUST respond ONLY with a valid JSON object strictly matching this schema:
            {
              "vulnerabilityId": "%s",
              "plainEnglishSummary": "<Beginner-friendly explanation of what this vulnerability means in simple terms>",
              "impactAnalysis": "<How this affects container runtime security, confidentiality, integrity, or availability>",
              "attackVector": "<How an attacker could exploit this (e.g. remote code execution, privilege escalation)>",
              "recommendedFix": "<Clear, concise guidance on what code or base image needs updating>",
              "remediationCommands": [
                 "<Terminal or Docker command 1, e.g. apk update && apk upgrade %s>",
                 "<Terminal or Docker command 2, e.g. docker build --no-cache -t app:secure .>"
              ],
              "patchedManifestSnippet": null
            }
            """,
                req.getVulnerabilityId(),
                StringUtils.hasText(req.getPackageName()) ? req.getPackageName() : "Unknown Package",
                StringUtils.hasText(req.getInstalledVersion()) ? req.getInstalledVersion() : "N/A",
                StringUtils.hasText(req.getFixedVersion()) ? req.getFixedVersion() : "Latest available",
                StringUtils.hasText(req.getSeverity()) ? req.getSeverity() : "HIGH",
                StringUtils.hasText(req.getDescription()) ? req.getDescription() : "No detailed description provided.",
                StringUtils.hasText(req.getContext()) ? req.getContext() : "Docker container environment",
                req.getVulnerabilityId(),
                StringUtils.hasText(req.getPackageName()) ? req.getPackageName() : "package"
        );
    }

    private String buildK8sMisconfigPrompt(String misconfigRule, String yamlContent) {
        return String.format("""
            You are a Kubernetes Security & DevSecOps Expert.
            Analyze the following Kubernetes misconfiguration rule and manifest snippet, and provide an actionable plain-English fix and hardened YAML.

            Misconfiguration Rule: %s
            Original Manifest Content:
            %s

            You MUST respond ONLY with a valid JSON object strictly matching this schema:
            {
              "vulnerabilityId": "%s",
              "plainEnglishSummary": "<Beginner-friendly explanation of why this configuration violates security best practices>",
              "impactAnalysis": "<Risk to the pod, node, or cluster if exploited (e.g., container breakout, unauthorized API access)>",
              "attackVector": "<Attacker vector or privilege abuse scenario>",
              "recommendedFix": "<Actionable instruction for the engineer>",
              "remediationCommands": [
                 "kubectl apply -f hardened-manifest.yaml",
                 "kubectl rollout restart deployment/<name>"
              ],
              "patchedManifestSnippet": "<The exact corrected, secure Kubernetes YAML snippet with securityContext, readOnlyRootFilesystem, runAsNonRoot, etc.>"
            }
            """,
                misconfigRule,
                StringUtils.hasText(yamlContent) ? yamlContent : "No YAML snippet provided",
                misconfigRule
        );
    }

    private AiExplanationResponse parseAiExplanationResponse(String jsonString, String defaultId) {
        try {
            // Clean possible markdown code fences (```json ... ```)
            String cleanedJson = jsonString.trim();
            if (cleanedJson.startsWith("```json")) {
                cleanedJson = cleanedJson.substring(7);
            } else if (cleanedJson.startsWith("```")) {
                cleanedJson = cleanedJson.substring(3);
            }
            if (cleanedJson.endsWith("```")) {
                cleanedJson = cleanedJson.substring(0, cleanedJson.length() - 3);
            }
            cleanedJson = cleanedJson.trim();

            JsonNode node = objectMapper.readTree(cleanedJson);

            List<String> commands = new ArrayList<>();
            JsonNode cmdNode = node.path("remediationCommands");
            if (cmdNode.isArray()) {
                cmdNode.forEach(c -> commands.add(c.asText()));
            }

            return AiExplanationResponse.builder()
                    .vulnerabilityId(node.path("vulnerabilityId").asText(defaultId))
                    .plainEnglishSummary(node.path("plainEnglishSummary").asText(node.path("summary").asText()))
                    .impactAnalysis(node.path("impactAnalysis").asText(node.path("impact").asText()))
                    .attackVector(node.path("attackVector").asText("Network / Container Runtime"))
                    .recommendedFix(node.path("recommendedFix").asText(node.path("remediation").asText()))
                    .remediationCommands(commands)
                    .patchedManifestSnippet(node.path("patchedManifestSnippet").asText(null))
                    .build();

        } catch (Exception e) {
            log.error("Failed to parse Gemini JSON payload: {}", e.getMessage());
            throw new VigiDockException("Failed to parse LLM structured response: " + e.getMessage(), e);
        }
    }

    private AiExplanationResponse buildFallbackVulnerabilityExplanation(AiExplanationRequest req) {
        String pkg = StringUtils.hasText(req.getPackageName()) ? req.getPackageName() : "affected package";
        String fixed = StringUtils.hasText(req.getFixedVersion()) ? req.getFixedVersion() : "the latest safe version";

        return AiExplanationResponse.builder()
                .vulnerabilityId(req.getVulnerabilityId())
                .plainEnglishSummary(String.format(
                        "The package '%s' contains a security flaw (%s) allowing potential unauthorized access or instability in the container.",
                        pkg, req.getVulnerabilityId()))
                .impactAnalysis("Unpatched dependencies in container images increase the attack surface and can lead to container compromise.")
                .attackVector("Exploitation of unpatched software library functions via standard container interfaces.")
                .recommendedFix(String.format("Upgrade '%s' to version %s or rebuild using an updated minimal base image (e.g. alpine:latest, distroless).", pkg, fixed))
                .remediationCommands(List.of(
                        String.format("# Upgrade %s in Dockerfile\nRUN apt-get update && apt-get install -y --only-upgrade %s", pkg, pkg),
                        "docker build --no-cache -t vigidock/app:secure ."
                ))
                .build();
    }

    private AiExplanationResponse buildFallbackK8sRemediation(String rule, String yaml) {
        return AiExplanationResponse.builder()
                .vulnerabilityId(rule)
                .plainEnglishSummary("The Kubernetes configuration lacks essential container hardening controls, allowing the pod to run with excessive privileges.")
                .impactAnalysis("In case of container compromise, lack of securityContext allows host filesystem tampering or privilege escalation.")
                .attackVector("Container breakout and root execution on node filesystem.")
                .recommendedFix("Add a strict securityContext block with readOnlyRootFilesystem: true, runAsNonRoot: true, and drop all Linux capabilities.")
                .remediationCommands(List.of(
                        "kubectl apply -f hardened-manifest.yaml",
                        "kubectl get pods -n default"
                ))
                .patchedManifestSnippet("""
                    securityContext:
                      runAsNonRoot: true
                      runAsUser: 10001
                      readOnlyRootFilesystem: true
                      allowPrivilegeEscalation: false
                      capabilities:
                        drop:
                          - ALL
                    """)
                .build();
    }
}

