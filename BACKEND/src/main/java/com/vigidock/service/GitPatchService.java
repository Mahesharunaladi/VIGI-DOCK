package com.vigidock.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.dataformat.yaml.YAMLMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Slf4j
@Service
@RequiredArgsConstructor
public class GitPatchService {

    private static final Pattern FROM_PATTERN = Pattern.compile("^(FROM\\s+)(\\S+)(.*)$", Pattern.CASE_INSENSITIVE);
    private static final Pattern PACKAGE_TOKEN = Pattern.compile("([A-Za-z0-9._+-]+)(?:=|@)([^\\s\\\\]+)");

    private final YAMLMapper yamlMapper;

    public String generateDockerfilePatch(String originalDockerfile, String vulnerablePackage, String fixedVersion) {
        String patched = generatePatchedDockerfile(originalDockerfile, vulnerablePackage, fixedVersion);
        return toUnifiedDiff("Dockerfile", originalDockerfile, patched);
    }

    public String generatePatchedDockerfile(String originalDockerfile, String vulnerablePackage, String fixedVersion) {
        if (!StringUtils.hasText(originalDockerfile)) {
            throw new IllegalArgumentException("Original Dockerfile content is required");
        }
        if (!StringUtils.hasText(vulnerablePackage)) {
            throw new IllegalArgumentException("Vulnerable package name is required");
        }

        String safeVersion = StringUtils.hasText(fixedVersion) ? fixedVersion.trim() : "latest";
        String[] originalLines = originalDockerfile.split("\\R", -1);
        List<String> patchedLines = new ArrayList<>();
        boolean mutated = false;

        for (String line : originalLines) {
            String updated = rewritePackageInstallLine(line, vulnerablePackage, safeVersion);
            if (!updated.equals(line)) {
                mutated = true;
                patchedLines.add(updated);
                continue;
            }

            Matcher fromMatcher = FROM_PATTERN.matcher(line);
            if (fromMatcher.matches() && looksLikeBaseImage(fromMatcher.group(2), vulnerablePackage)) {
                String image = fromMatcher.group(2);
                String rewrittenImage = rewriteImageTag(image, safeVersion);
                patchedLines.add(fromMatcher.group(1) + rewrittenImage + fromMatcher.group(3));
                mutated = true;
                continue;
            }

            patchedLines.add(line);
        }

        if (!mutated) {
            patchedLines.add("RUN apt-get update && apt-get install -y --only-upgrade "
                    + vulnerablePackage + "=" + safeVersion + " || apk add --no-cache "
                    + vulnerablePackage + "=" + safeVersion);
        }

        String patched = String.join("\n", patchedLines);
        if (!patched.endsWith("\n") && originalDockerfile.endsWith("\n")) {
            patched = patched + "\n";
        }
        return patched;
    }

    public String generateK8sYamlFix(String originalYaml, String misconfigRule) {
        if (!StringUtils.hasText(originalYaml)) {
            throw new IllegalArgumentException("Original Kubernetes YAML is required");
        }

        try {
            String[] documents = originalYaml.split("(?m)^---\\s*$");
            List<String> rendered = new ArrayList<>();
            for (String document : documents) {
                if (!StringUtils.hasText(document.trim())) {
                    continue;
                }
                JsonNode root = yamlMapper.readTree(document);
                if (root instanceof ObjectNode objectNode) {
                    hardenManifest(objectNode, misconfigRule);
                    rendered.add(yamlMapper.writeValueAsString(objectNode).trim());
                } else {
                    rendered.add(document.trim());
                }
            }
            return String.join("\n---\n", rendered) + "\n";
        } catch (Exception e) {
            log.error("Failed to parse Kubernetes YAML for automated fix: {}", e.getMessage());
            throw new IllegalArgumentException("Unable to parse Kubernetes YAML: " + e.getMessage(), e);
        }
    }

    private String rewritePackageInstallLine(String line, String pkg, String version) {
        String trimmed = line.trim();
        if (!trimmed.toUpperCase(Locale.ROOT).startsWith("RUN ")) {
            return line;
        }
        Matcher matcher = PACKAGE_TOKEN.matcher(line);
        StringBuffer buffer = new StringBuffer();
        boolean replaced = false;
        while (matcher.find()) {
            if (matcher.group(1).equalsIgnoreCase(pkg)) {
                matcher.appendReplacement(buffer, Matcher.quoteReplacement(pkg + "=" + version));
                replaced = true;
            }
        }
        matcher.appendTail(buffer);
        if (replaced) {
            return buffer.toString();
        }

        if (line.matches("(?i).*\\b(apk|apt-get|apt|yum|dnf|microdnf)\\b.*")
                && line.matches("(?i).*\\b" + Pattern.quote(pkg) + "\\b.*")) {
            return line.replaceFirst("(?i)\\b" + Pattern.quote(pkg) + "\\b", pkg + "=" + version);
        }
        return line;
    }

    private boolean looksLikeBaseImage(String imageReference, String pkg) {
        String image = imageReference.toLowerCase(Locale.ROOT);
        String packageName = pkg.toLowerCase(Locale.ROOT);
        return image.contains(packageName) || image.startsWith(packageName + ":") || image.endsWith("/" + packageName);
    }

    private String rewriteImageTag(String image, String version) {
        int digestIndex = image.indexOf('@');
        String withoutDigest = digestIndex >= 0 ? image.substring(0, digestIndex) : image;
        int slash = withoutDigest.lastIndexOf('/');
        int colon = withoutDigest.lastIndexOf(':');
        if (colon > slash) {
            return withoutDigest.substring(0, colon + 1) + version;
        }
        return withoutDigest + ":" + version;
    }

    private void hardenManifest(ObjectNode root, String misconfigRule) {
        ObjectNode podSpec = locatePodSpec(root);
        if (podSpec == null) {
            return;
        }

        ObjectNode podSecurityContext = getOrCreateObject(podSpec, "securityContext");
        podSecurityContext.put("runAsNonRoot", true);
        podSecurityContext.put("runAsUser", 10001);
        ObjectNode seccomp = getOrCreateObject(podSecurityContext, "seccompProfile");
        seccomp.put("type", "RuntimeDefault");

        hardenContainerList(podSpec, "containers");
        hardenContainerList(podSpec, "initContainers");

        if (StringUtils.hasText(misconfigRule) && misconfigRule.toLowerCase(Locale.ROOT).contains("hostnetwork")) {
            podSpec.put("hostNetwork", false);
        }
        if (StringUtils.hasText(misconfigRule) && misconfigRule.toLowerCase(Locale.ROOT).contains("privileged")) {
            podSpec.put("hostPID", false);
            podSpec.put("hostIPC", false);
        }
    }

    private void hardenContainerList(ObjectNode podSpec, String fieldName) {
        JsonNode containersNode = podSpec.get(fieldName);
        if (!(containersNode instanceof ArrayNode containers)) {
            return;
        }
        for (JsonNode container : containers) {
            if (container instanceof ObjectNode containerNode) {
                ObjectNode securityContext = getOrCreateObject(containerNode, "securityContext");
                securityContext.put("runAsNonRoot", true);
                securityContext.put("runAsUser", 10001);
                securityContext.put("readOnlyRootFilesystem", true);
                securityContext.put("allowPrivilegeEscalation", false);
                securityContext.put("privileged", false);
                ObjectNode capabilities = getOrCreateObject(securityContext, "capabilities");
                ArrayNode drop = capabilities.putArray("drop");
                drop.add("ALL");
            }
        }
    }

    private ObjectNode locatePodSpec(ObjectNode root) {
        String kind = root.path("kind").asText("");
        ObjectNode spec = asObject(root.get("spec"));
        if (spec == null) {
            return null;
        }
        if ("Pod".equalsIgnoreCase(kind)) {
            return spec;
        }
        if ("CronJob".equalsIgnoreCase(kind)) {
            ObjectNode jobTemplate = asObject(spec.path("jobTemplate"));
            ObjectNode jobSpec = jobTemplate == null ? null : asObject(jobTemplate.path("spec"));
            ObjectNode template = jobSpec == null ? null : asObject(jobSpec.path("template"));
            return template == null ? null : asObject(template.path("spec"));
        }
        ObjectNode template = asObject(spec.path("template"));
        if (template != null) {
            ObjectNode nested = asObject(template.path("spec"));
            if (nested != null) {
                return nested;
            }
        }
        return spec;
    }

    private ObjectNode getOrCreateObject(ObjectNode parent, String field) {
        JsonNode existing = parent.get(field);
        if (existing instanceof ObjectNode objectNode) {
            return objectNode;
        }
        return parent.putObject(field);
    }

    private ObjectNode asObject(JsonNode node) {
        return node instanceof ObjectNode objectNode ? objectNode : null;
    }

    public String toUnifiedDiff(String fileName, String original, String patched) {
        String[] left = original.split("\\R", -1);
        String[] right = patched.split("\\R", -1);
        StringBuilder diff = new StringBuilder();
        diff.append("--- a/").append(fileName).append('\n');
        diff.append("+++ b/").append(fileName).append('\n');
        diff.append("@@ -1,").append(left.length).append(" +1,").append(right.length).append(" @@\n");

        int max = Math.max(left.length, right.length);
        for (int i = 0; i < max; i++) {
            String before = i < left.length ? left[i] : null;
            String after = i < right.length ? right[i] : null;
            if (before != null && after != null && before.equals(after)) {
                diff.append(' ').append(before).append('\n');
            } else {
                if (before != null) {
                    diff.append('-').append(before).append('\n');
                }
                if (after != null) {
                    diff.append('+').append(after).append('\n');
                }
            }
        }
        return diff.toString();
    }
}
