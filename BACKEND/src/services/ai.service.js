const { getGeminiClient } = require('../config/aiConfig');

/**
 * Fallback static AI response when Gemini API key is not provided.
 */
const getFallbackAnalysis = (scanData) => {
  const { summary = {}, vulnerabilities = [], misconfigurations = [], target = 'Target' } = scanData;
  return {
    summary: `Automated DevSecOps Security Assessment for ${target}. The scan identified ${summary.critical || 0} Critical, ${summary.high || 0} High, and ${summary.medium || 0} Medium vulnerabilities, alongside ${summary.totalMisconfigurations || 0} security misconfigurations. Overall security rating is ${summary.securityScore || 0}/100.`,
    remediationPlan: [
      'Upgrade base image to the latest minimal hardened variant (e.g. Alpine 3.19+ or Distroless).',
      'Pin application dependencies and update packages with known high-severity CVEs.',
      'Enforce non-root execution by setting securityContext.runAsNonRoot: true in Kubernetes manifests.',
      'Configure read-only root filesystems and specify explicit CPU/Memory request and limit boundaries.',
      'Enable container image signature verification and SBOM tracking in your CI/CD pipeline.'
    ],
    securityRecommendations: [
      'Implement automated Trivy vulnerability gates in GitHub Actions or GitLab CI.',
      'Enable Falco or eBPF runtime security agents on Kubernetes worker nodes to detect anomalies.',
      'Enforce Pod Security Standards (Restricted Profile) in production namespaces.'
    ],
    patchedConfig: null,
    generatedAt: new Date().toISOString(),
  };
};

const AiService = {
  /**
   * Generates a comprehensive AI explanation and remediation plan for a full scan.
   */
  async analyzeScan(scanData) {
    const model = getGeminiClient();
    if (!model) {
      return getFallbackAnalysis(scanData);
    }

    const { target, targetType, summary, vulnerabilities = [], misconfigurations = [] } = scanData;
    
    // Select top 8 most critical findings to keep prompt concise & focused
    const topVulns = vulnerabilities
      .filter(v => ['CRITICAL', 'HIGH'].includes(v.severity))
      .slice(0, 8)
      .map(v => `- [${v.severity}] ${v.vulnerabilityId} in ${v.pkgName} (Installed: ${v.installedVersion}, Fixed: ${v.fixedVersion}): ${v.title}`);

    const topMisconfigs = misconfigurations
      .slice(0, 6)
      .map(m => `- [${m.severity}] ${m.id}: ${m.title} -> ${m.message}`);

    const prompt = `
You are VigiDock AI, a world-class DevSecOps Container and Kubernetes Security Expert.
Analyze the following vulnerability & misconfiguration report and provide a crisp, actionable security analysis.

TARGET: ${target} (${targetType})
SECURITY SCORE: ${summary?.securityScore || 0}/100
CRITICAL: ${summary?.critical || 0}, HIGH: ${summary?.high || 0}, MEDIUM: ${summary?.medium || 0}, LOW: ${summary?.low || 0}

TOP VULNERABILITIES:
${topVulns.length > 0 ? topVulns.join('\n') : 'None detected.'}

TOP MISCONFIGURATIONS:
${topMisconfigs.length > 0 ? topMisconfigs.join('\n') : 'None detected.'}

Respond strictly in valid JSON format with the following JSON schema:
{
  "summary": "2-3 paragraph plain-English executive summary of the security posture, risk level, and potential attack vectors",
  "remediationPlan": [
    "Step 1 actionable fix...",
    "Step 2 actionable fix...",
    "Step 3 actionable fix..."
  ],
  "securityRecommendations": [
    "Best practice 1 for container lifecycle...",
    "Best practice 2 for Kubernetes hardening..."
  ]
}
`;

    try {
      const result = await model.generateContent(prompt);
      const textResponse = result.response.text();
      
      // Clean JSON formatting if wrapped in code blocks
      const cleanJson = textResponse.replace(/^```json\s*/i, '').replace(/\s*```$/i, '').trim();
      const parsed = JSON.parse(cleanJson);
      return {
        ...parsed,
        generatedAt: new Date().toISOString(),
      };
    } catch (err) {
      console.error(`[AiService] Gemini API call failed: ${err.message}. Returning fallback analysis.`);
      return getFallbackAnalysis(scanData);
    }
  },

  /**
   * Explain a single CVE vulnerability with plain-English insights and code fixes.
   */
  async explainVulnerability(vulnerability) {
    const model = getGeminiClient();
    if (!model) {
      return {
        vulnerabilityId: vulnerability.vulnerabilityId,
        explanation: `Vulnerability ${vulnerability.vulnerabilityId} in ${vulnerability.pkgName} represents a security risk. Upgrade to fixed version ${vulnerability.fixedVersion || 'latest'}.`,
        impact: 'Potential privilege escalation or remote code execution depending on workload exposure.',
        remediationCode: vulnerability.fixedVersion ? `npm update ${vulnerability.pkgName} || apk add --upgrade ${vulnerability.pkgName}` : '# Check upstream vendor advisory',
      };
    }

    const prompt = `
You are a senior container security engineer. Explain this CVE vulnerability in clear, developer-friendly terms:

CVE: ${vulnerability.vulnerabilityId}
Package: ${vulnerability.pkgName}
Installed Version: ${vulnerability.installedVersion}
Fixed Version: ${vulnerability.fixedVersion}
Severity: ${vulnerability.severity}
Description: ${vulnerability.description}

Respond strictly in valid JSON with schema:
{
  "explanation": "Clear explanation of what this flaw is and how it works in containers",
  "impact": "Concrete impact on production pods/containers",
  "remediationSteps": "Exact commands or configuration changes to fix it",
  "fixedVersion": "${vulnerability.fixedVersion || 'N/A'}"
}
`;

    try {
      const result = await model.generateContent(prompt);
      const textResponse = result.response.text();
      const cleanJson = textResponse.replace(/^```json\s*/i, '').replace(/\s*```$/i, '').trim();
      return JSON.parse(cleanJson);
    } catch (err) {
      console.error(`[AiService] Gemini CVE explain error: ${err.message}`);
      return {
        vulnerabilityId: vulnerability.vulnerabilityId,
        explanation: vulnerability.description,
        impact: `Severity level is ${vulnerability.severity}.`,
        remediationSteps: vulnerability.remediation,
      };
    }
  },

  /**
   * Automatically generate hardened Kubernetes YAML or Dockerfile.
   */
  async hardenConfiguration(rawContent, targetType = 'kubernetes-yaml', misconfigurations = []) {
    const model = getGeminiClient();
    if (!model) {
      return {
        original: rawContent,
        hardened: rawContent + '\n# [VigiDock AI Note] Add securityContext: runAsNonRoot: true, readOnlyRootFilesystem: true',
        changesApplied: ['Added baseline securityContext recommendations'],
      };
    }

    const prompt = `
You are a DevSecOps hardening automated assistant.
Take the following ${targetType} configuration and harden it against security misconfigurations:

RAW CONTENT:
\`\`\`
${rawContent}
\`\`\`

DETECTED ISSUES:
${JSON.stringify(misconfigurations, null, 2)}

Return strictly valid JSON with schema:
{
  "hardenedContent": "The fully corrected and securely configured YAML or Dockerfile",
  "changesApplied": [
    "List of specific security changes made (e.g. Set runAsNonRoot: true, dropped all capabilities, added resource limits)"
  ]
}
`;

    try {
      const result = await model.generateContent(prompt);
      const textResponse = result.response.text();
      const cleanJson = textResponse.replace(/^```json\s*/i, '').replace(/\s*```$/i, '').trim();
      return JSON.parse(cleanJson);
    } catch (err) {
      console.error(`[AiService] Gemini YAML hardening error: ${err.message}`);
      return {
        original: rawContent,
        hardenedContent: rawContent,
        changesApplied: ['Could not apply AI hardening due to API limitation.'],
      };
    }
  },

  /**
   * Interactive DevSecOps conversational AI chat.
   */
  async chatAssistant(message, scanContext = null) {
    const model = getGeminiClient();
    if (!model) {
      return {
        reply: `VigiDock AI DevSecOps Assistant: I received your question regarding "${message}". Please configure GEMINI_API_KEY in .env for full conversational capabilities. For general security: ensure non-root execution, use multi-stage builds, and update base images regularly.`,
      };
    }

    const contextSnippet = scanContext 
      ? `\nCURRENT SCAN CONTEXT:\nTarget: ${scanContext.target}\nScore: ${scanContext.summary?.securityScore}/100\nCritical Issues: ${scanContext.summary?.critical}\n`
      : '';

    const prompt = `
You are VigiDock AI DevSecOps Assistant, an expert in Docker, Kubernetes, Linux kernel security, container runtime security (gVisor, Kata, runc), and cloud-native DevSecOps.
${contextSnippet}
USER QUESTION: ${message}

Provide a direct, helpful, technical, yet easy-to-understand response with relevant code snippets, CLI commands, or YAML configs when applicable.
`;

    try {
      const result = await model.generateContent(prompt);
      return {
        reply: result.response.text(),
      };
    } catch (err) {
      console.error(`[AiService] Chat Assistant error: ${err.message}`);
      return {
        reply: `Error communicating with AI assistant: ${err.message}.`,
      };
    }
  }
};

module.exports = AiService;
