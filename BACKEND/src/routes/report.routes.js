const express = require('express');
const router = express.Router();
const ReportController = require('../controllers/report.controller');

// GET /api/reports/:scanId/pdf - Download PDF security report
router.get('/:scanId/pdf', ReportController.downloadPdfReport);

// GET /api/reports/:scanId/summary - Executive summary JSON
router.get('/:scanId/summary', ReportController.getReportSummary);

module.exports = router;
