const PdfService = require('../services/pdf.service');
const { ScanRepository } = require('../models/scan.model');

const ReportController = {
  /**
   * GET /api/reports/:scanId/pdf
   * Generate and stream a downloadable PDF security audit report.
   */
  async downloadPdfReport(req, res, next) {
    try {
      const { scanId } = req.params;
      const scan = await ScanRepository.findById(scanId);

      if (!scan) {
        return res.status(404).json({
          success: false,
          error: { message: `Scan "${scanId}" was not found.` },
        });
      }

      const filename = `vigidock-report-${scan.target.replace(/[^a-zA-Z0-9-_]/g, '_')}-${scanId.slice(0, 8)}.pdf`;

      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);

      await PdfService.generatePdfReport(scan, res);
    } catch (err) {
      next(err);
    }
  },

  /**
   * GET /api/reports/:scanId/summary
   * Retrieve structured executive summary for reporting dashboards.
   */
  async getReportSummary(req, res, next) {
    try {
      const { scanId } = req.params;
      const scan = await ScanRepository.findById(scanId);

      if (!scan) {
        return res.status(404).json({
          success: false,
          error: { message: `Scan "${scanId}" was not found.` },
        });
      }

      res.status(200).json({
        success: true,
        data: {
          scanId: scan.scanId,
          target: scan.target,
          targetType: scan.targetType,
          status: scan.status,
          createdAt: scan.createdAt,
          completedAt: scan.completedAt,
          summary: scan.summary,
          aiAnalysis: scan.aiAnalysis,
          vulnerabilitiesCount: scan.vulnerabilities?.length || 0,
          misconfigurationsCount: scan.misconfigurations?.length || 0,
        },
      });
    } catch (err) {
      next(err);
    }
  },
};

module.exports = ReportController;
