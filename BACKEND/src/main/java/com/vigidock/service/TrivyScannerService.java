package com.vigidock.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.vigidock.dto.ScanResponse;
import com.vigidock.dto.VulnerabilityDto;
import com.vigidock.exception.ScanException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.multipart.MultipartFile;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.Pattern;

@Slf4j
@Service
@RequiredArgsConstructor
public class TrivyScannerService {

    private final ObjectMapper objectMapper;

    @Value("${vigidock.scanner.trivy-path:trivy}")
    private String trivyPath;

    @Value("${vigidock.scanner.timeout-seconds:300}")
    private long timeoutSeconds;

    @Value("${vigidock.scanner.upload-dir:uploads}")
    private String uploadDirConfig;

    // Pattern to ensure Docker image name does not contain illegal control characters
    private static final Pattern SAFE_IMAGE_NAME_PATTERN =
            Pattern.compile("^[a-zA-Z0-9_.:/@-]+$");

    /**
     * Scans a Docker image using Trivy CLI via ProcessBuilder.
     *
     * @param imageName Docker image reference (e.g. "nginx:alpine", "redis:7.0")
     * @return ScanResponse containing parsed vulnerabilities and metrics
     */
    public ScanResponse scanDockerImage(String imageName) {
        validateImageName(imageName);
        log.info("Initiating Trivy image scan for: {}", imageName);

        List<String> command = List.of(
                trivyPath,
                "image",
                "--format", "json",
                "--quiet",
                imageName
        );

        String jsonOutput = executeProcess(command, "Docker Image Scan [" + imageName + "]");
        return parseTrivyOutput(jsonOutput, imageName, "DOCKER_IMAGE");
    }

    /**
     * Scans a Kubernetes YAML manifest using Trivy CLI config mode.
     * Temporarily saves the uploaded file, runs the scan, and cleans up the file.
     *
     * @param file Uploaded multipart Kubernetes YAML manifest
     * @return ScanResponse containing detected misconfigurations and security risks
     */
    public ScanResponse scanKubernetesYaml(MultipartFile file) {
        if (file == null || file.isEmpty()) {
            throw new IllegalArgumentException("Kubernetes YAML file cannot be empty");
        }

        String originalFilename = StringUtils.cleanPath(
                file.getOriginalFilename() != null ? file.getOriginalFilename() : "manifest.yaml"
        );

        Path tempFilePath = null;
        try {
            // Ensure target upload directory exists
            Path uploadDirPath = resolveUploadDirectory();
            if (!Files.exists(uploadDirPath)) {
                Files.createDirectories(uploadDirPath);
            }

            // Create a unique temporary file to avoid collisions
            String sanitizedPrefix = originalFilename.replaceAll("[^a-zA-Z0-9.-]", "_");
            String tempFileName = UUID.randomUUID() + "-" + sanitizedPrefix;
            tempFilePath = uploadDirPath.resolve(tempFileName);

            Files.copy(file.getInputStream(), tempFilePath, StandardCopyOption.REPLACE_EXISTING);
            log.info("Saved temporary K8s manifest to: {}", tempFilePath);

            List<String> command = List.of(
                    trivyPath,
                    "config",
                    "--format", "json",
                    "--quiet",
                    tempFilePath.toAbsolutePath().toString()
            );

            String jsonOutput = executeProcess(command, "Kubernetes Manifest Scan [" + originalFilename + "]");
            return parseTrivyOutput(jsonOutput, originalFilename, "K8S_CONFIG");

        } catch (IOException e) {
            throw new ScanException("Failed to save or process uploaded Kubernetes manifest: " + e.getMessage(), e);
        } finally {
            if (tempFilePath != null) {
                try {
                    Files.deleteIfExists(tempFilePath);
                    log.debug("Cleaned up temporary upload file: {}", tempFilePath);
                } catch (IOException e) {
                    log.warn("Failed to delete temporary file {}: {}", tempFilePath, e.getMessage());
                }
            }
        }
    }

    /**
     * Executes process securely with ProcessBuilder, capturing stdout/stderr without deadlocks.
     */
    private String executeProcess(List<String> command, String operationName) {
        ProcessBuilder processBuilder = new ProcessBuilder(command);
        // Do not use shell (/bin/sh -c), invoke the binary directly with discrete arguments
        processBuilder.environment().put("TRIVY_NO_PROGRESS", "true");

        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            Process process = processBuilder.start();

            Future<String> stdoutFuture = executor.submit(() -> readStream(process.getInputStream()));
            Future<String> stderrFuture = executor.submit(() -> readStream(process.getErrorStream()));

            boolean finished = process.waitFor(timeoutSeconds, TimeUnit.SECONDS);
            if (!finished) {
                process.destroyForcibly();
                throw new ScanException("Scan timed out after " + timeoutSeconds + " seconds for " + operationName);
            }

            int exitCode = process.exitValue();
            String stdout = stdoutFuture.get(5, TimeUnit.SECONDS);
            String stderr = stderrFuture.get(5, TimeUnit.SECONDS);

            if (exitCode != 0) {
                log.error("Trivy process exited with code {} for {}. Stderr: {}", exitCode, operationName, stderr);
                throw new ScanException("Trivy scan failed (exit code " + exitCode + "): " +
                        (StringUtils.hasText(stderr) ? stderr : stdout));
            }

            return stdout;

        } catch (IOException e) {
            throw new ScanException("Failed to invoke Trivy binary at '" + trivyPath + "'. Ensure Trivy is installed and in system PATH. Error: " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ScanException("Scan process execution was interrupted: " + e.getMessage(), e);
        } catch (ExecutionException | TimeoutException e) {
            throw new ScanException("Error reading Trivy process output: " + e.getMessage(), e);
        } finally {
            executor.shutdownNow();
        }
    }

    /**
     * Parses the Trivy JSON structure into our standardized ScanResponse DTO.
     */
    private ScanResponse parseTrivyOutput(String jsonOutput, String target, String scanType) {
        String scanId = UUID.randomUUID().toString();
        List<VulnerabilityDto> vulnerabilities = new ArrayList<>();

        int critical = 0;
        int high = 0;
        int medium = 0;
        int low = 0;

        try {
            if (!StringUtils.hasText(jsonOutput)) {
                return buildEmptyResponse(scanId, target, scanType);
            }

            JsonNode rootNode = objectMapper.readTree(jsonOutput);
            JsonNode resultsNode = rootNode.path("Results");

            if (resultsNode.isArray()) {
                for (JsonNode result : resultsNode) {
                    // 1. Process standard Vulnerabilities (from image scans)
                    JsonNode vulnsNode = result.path("Vulnerabilities");
                    if (vulnsNode.isArray()) {
                        for (JsonNode vNode : vulnsNode) {
                            String severity = vNode.path("Severity").asText("UNKNOWN").toUpperCase();
                            switch (severity) {
                                case "CRITICAL" -> critical++;
                                case "HIGH" -> high++;
                                case "MEDIUM" -> medium++;
                                case "LOW" -> low++;
                            }

                            List<String> cweList = new ArrayList<>();
                            JsonNode cweNode = vNode.path("CweIDs");
                            if (cweNode.isArray()) {
                                cweNode.forEach(c -> cweList.add(c.asText()));
                            }

                            vulnerabilities.add(VulnerabilityDto.builder()
                                    .vulnerabilityId(vNode.path("VulnerabilityID").asText())
                                    .pkgName(vNode.path("PkgName").asText())
                                    .installedVersion(vNode.path("InstalledVersion").asText())
                                    .fixedVersion(vNode.path("FixedVersion").asText(null))
                                    .severity(severity)
                                    .title(vNode.path("Title").asText())
                                    .description(vNode.path("Description").asText())
                                    .primaryUrl(vNode.path("PrimaryURL").asText())
                                    .cweIds(cweList)
                                    .build());
                        }
                    }

                    // 2. Process Misconfigurations (from K8s manifest config scans)
                    JsonNode misconfigsNode = result.path("Misconfigurations");
                    if (misconfigsNode.isArray()) {
                        for (JsonNode mNode : misconfigsNode) {
                            String severity = mNode.path("Severity").asText("UNKNOWN").toUpperCase();
                            switch (severity) {
                                case "CRITICAL" -> critical++;
                                case "HIGH" -> high++;
                                case "MEDIUM" -> medium++;
                                case "LOW" -> low++;
                            }

                            vulnerabilities.add(VulnerabilityDto.builder()
                                    .vulnerabilityId(mNode.path("ID").asText())
                                    .pkgName(mNode.path("Title").asText("Kubernetes Misconfiguration"))
                                    .installedVersion(mNode.path("Status").asText("FAIL"))
                                    .fixedVersion(mNode.path("Resolution").asText(null))
                                    .severity(severity)
                                    .title(mNode.path("Title").asText())
                                    .description(mNode.path("Description").asText(mNode.path("Message").asText()))
                                    .primaryUrl(mNode.path("PrimaryURL").asText())
                                    .cweIds(Collections.emptyList())
                                    .aiRemediation(mNode.path("Resolution").asText(null))
                                    .build());
                        }
                    }
                }
            }

            int total = critical + high + medium + low;
            String riskScore = calculateRiskScore(critical, high, medium, low);

            Map<String, Object> summary = new HashMap<>();
            summary.put("total", total);
            summary.put("critical", critical);
            summary.put("high", high);
            summary.put("medium", medium);
            summary.put("low", low);
            summary.put("riskScore", riskScore);

            return ScanResponse.builder()
                    .scanId(scanId)
                    .target(target)
                    .scanType(scanType)
                    .status("COMPLETED")
                    .totalVulnerabilities(total)
                    .criticalCount(critical)
                    .highCount(high)
                    .mediumCount(medium)
                    .lowCount(low)
                    .vulnerabilities(vulnerabilities)
                    .summary(summary)
                    .overallRiskScore(riskScore)
                    .scannedAt(LocalDateTime.now())
                    .build();

        } catch (Exception e) {
            log.error("Failed to parse Trivy output JSON: {}", e.getMessage(), e);
            throw new ScanException("Failed to parse Trivy scan output: " + e.getMessage(), e);
        }
    }

    private String calculateRiskScore(int critical, int high, int medium, int low) {
        int score = (critical * 10) + (high * 5) + (medium * 2) + low;
        if (critical > 0 || score >= 25) {
            return "CRITICAL (" + score + ")";
        } else if (high > 0 || score >= 15) {
            return "HIGH (" + score + ")";
        } else if (medium > 0 || score >= 5) {
            return "MEDIUM (" + score + ")";
        } else if (low > 0) {
            return "LOW (" + score + ")";
        }
        return "SECURE (0)";
    }

    private ScanResponse buildEmptyResponse(String scanId, String target, String scanType) {
        return ScanResponse.builder()
                .scanId(scanId)
                .target(target)
                .scanType(scanType)
                .status("COMPLETED")
                .totalVulnerabilities(0)
                .criticalCount(0)
                .highCount(0)
                .mediumCount(0)
                .lowCount(0)
                .vulnerabilities(Collections.emptyList())
                .summary(Map.of("total", 0, "status", "NO_VULNERABILITIES_FOUND"))
                .overallRiskScore("SECURE (0)")
                .scannedAt(LocalDateTime.now())
                .build();
    }

    private String readStream(java.io.InputStream inputStream) throws IOException {
        StringBuilder sb = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream))) {
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line).append(System.lineSeparator());
            }
        }
        return sb.toString().trim();
    }

    private void validateImageName(String imageName) {
        if (!StringUtils.hasText(imageName)) {
            throw new IllegalArgumentException("Docker image name cannot be null or empty");
        }
        if (!SAFE_IMAGE_NAME_PATTERN.matcher(imageName.trim()).matches()) {
            throw new IllegalArgumentException("Invalid Docker image name format: Contains disallowed characters");
        }
    }

    private Path resolveUploadDirectory() {
        Path path = Paths.get("src/main/resources/uploads");
        if (Files.exists(path)) {
            return path;
        }
        return Paths.get(uploadDirConfig);
    }
}
