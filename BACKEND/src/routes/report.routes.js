const express = require('express');
const router = express.Router();
const ReportController = require('../controllers/report.controller');

// Health check for Report service
router.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok', service: 'report' });
});

// GET /api/reports/:scanId/pdf - Download PDF security report
router.get('/:scanId/pdf', ReportController.downloadPdfReport);

// GET /api/reports/:scanId/summary - Executive summary JSON
router.get('/:scanId/summary', ReportController.getReportSummary);

module.exports = router;
