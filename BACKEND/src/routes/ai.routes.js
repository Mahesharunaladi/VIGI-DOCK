const express = require('express');
const router = express.Router();
const AiController = require('../controllers/ai.controller');

// POST /api/ai/explain-vulnerability - Plain-English explanation for single CVE
router.post('/explain-vulnerability', AiController.explainVulnerability);

// POST /api/ai/remediate-config - Automated YAML/Dockerfile hardening
router.post('/remediate-config', AiController.remediateConfig);

// POST /api/ai/re-analyze/:scanId - Re-run AI analysis on scan
router.post('/re-analyze/:scanId', AiController.reAnalyzeScan);

// POST /api/ai/chat - Interactive DevSecOps AI chat assistant
router.post('/chat', AiController.chatAssistant);

module.exports = router;
