const AiService = require('../services/ai.service');
const { ScanRepository } = require('../models/scan.model');

const AiController = {
  /**
   * POST /api/ai/explain-vulnerability
   * Request deep-dive explanation for a specific CVE or vulnerability finding.
   */
  async explainVulnerability(req, res, next) {
    try {
      const { vulnerabilityId, pkgName, installedVersion, fixedVersion, severity, description } = req.body;

      if (!vulnerabilityId) {
        return res.status(400).json({
          success: false,
          error: { message: '"vulnerabilityId" is required (e.g. "CVE-2024-21626").' },
        });
      }

      const explanation = await AiService.explainVulnerability({
        vulnerabilityId,
        pkgName: pkgName || 'Unknown Package',
        installedVersion,
        fixedVersion,
        severity: severity || 'UNKNOWN',
        description: description || 'Vulnerability detected in container.',
      });

      res.status(200).json({
        success: true,
        data: explanation,
      });
    } catch (err) {
      next(err);
    }
  },

  /**
   * POST /api/ai/remediate-config
   * Automatically generate hardened Kubernetes YAML or Dockerfile configuration.
   */
  async remediateConfig(req, res, next) {
    try {
      const { rawContent, targetType = 'kubernetes-yaml', misconfigurations = [] } = req.body;

      if (!rawContent || typeof rawContent !== 'string') {
        return res.status(400).json({
          success: false,
          error: { message: '"rawContent" string is required.' },
        });
      }

      const result = await AiService.hardenConfiguration(rawContent, targetType, misconfigurations);

      res.status(200).json({
        success: true,
        data: result,
      });
    } catch (err) {
      next(err);
    }
  },

  /**
   * POST /api/ai/re-analyze/:scanId
   * Trigger fresh Gemini AI analysis for a completed scan.
   */
  async reAnalyzeScan(req, res, next) {
    try {
      const { scanId } = req.params;
      const scan = await ScanRepository.findById(scanId);

      if (!scan) {
        return res.status(404).json({
          success: false,
          error: { message: `Scan with ID "${scanId}" was not found.` },
        });
      }

      const aiAnalysis = await AiService.analyzeScan(scan);
      const updated = await ScanRepository.updateById(scanId, { aiAnalysis });

      res.status(200).json({
        success: true,
        message: 'AI analysis generated and updated.',
        data: {
          scanId,
          aiAnalysis: updated.aiAnalysis,
        },
      });
    } catch (err) {
      next(err);
    }
  },

  /**
   * POST /api/ai/chat
   * Interactive DevSecOps AI chatbot endpoint.
   */
  async chatAssistant(req, res, next) {
    try {
      const { message, scanId } = req.body;

      if (!message || typeof message !== 'string') {
        return res.status(400).json({
          success: false,
          error: { message: '"message" string is required.' },
        });
      }

      let scanContext = null;
      if (scanId) {
        scanContext = await ScanRepository.findById(scanId);
      }

      const response = await AiService.chatAssistant(message, scanContext);

      res.status(200).json({
        success: true,
        data: response,
      });
    } catch (err) {
      next(err);
    }
  },
};

module.exports = AiController;
