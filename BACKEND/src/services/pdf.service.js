const PDFDocument = require('pdfkit');
const fs = require('fs');
const path = require('path');

const PdfService = {
  /**
   * Generates a comprehensive PDF report stream or buffer for a given scan record.
   * @param {Object} scan - The scan database object
   * @param {Object} outputStream - Node.js writable stream (e.g. res for HTTP response or fs.createWriteStream)
   */
  generatePdfReport(scan, outputStream) {
    return new Promise((resolve, reject) => {
      const doc = new PDFDocument({
        size: 'A4',
        margin: 40,
        info: {
          Title: `VigiDock AI Security Report - ${scan.target}`,
          Author: 'VigiDock AI Security Scanner',
          Subject: 'Container & Kubernetes Vulnerability Assessment',
        }
      });

      doc.pipe(outputStream);
      outputStream.on('finish', () => resolve(true));
      outputStream.on('error', (err) => reject(err));

      const primaryColor = '#1e293b';
      const accentColor = '#3b82f6';
      const criticalColor = '#ef4444';
      const highColor = '#f97316';
      const mediumColor = '#eab308';
      const lowColor = '#10b981';

      // --- HEADER ---
      doc.rect(40, 40, 515, 60).fill('#0f172a');
      
      doc.fillColor('#ffffff')
         .fontSize(22)
         .font('Helvetica-Bold')
         .text('VIGIDOCK AI', 55, 52);
      
      doc.fontSize(10)
         .font('Helvetica')
         .fillColor('#94a3b8')
         .text('Intelligent Container Security & Remediation Report', 55, 78);

      doc.fillColor('#ffffff')
         .fontSize(9)
         .text(`Generated: ${new Date().toLocaleString()}`, 380, 55, { align: 'right', width: 160 });

      doc.moveDown(3);

      // --- TARGET INFO ---
      const yMeta = 120;
      doc.roundedRect(40, yMeta, 515, 65, 4).fillAndStroke('#f8fafc', '#e2e8f0');

      doc.fillColor(primaryColor).fontSize(10).font('Helvetica-Bold').text('SCAN METADATA', 55, yMeta + 12);
      doc.font('Helvetica').fontSize(9).fillColor('#475569');
      doc.text(`Scan ID: ${scan.scanId}`, 55, yMeta + 30);
      doc.text(`Target: ${scan.target}`, 55, yMeta + 45);
      doc.text(`Type: ${scan.targetType.toUpperCase()}`, 300, yMeta + 30);
      doc.text(`Status: ${scan.status}`, 300, yMeta + 45);

      // --- SCORECARD & SEVERITY COUNTS ---
      const yScore = 200;
      const score = scan.summary?.securityScore || 0;
      const scoreColor = score >= 80 ? '#10b981' : score >= 50 ? '#eab308' : '#ef4444';

      // Score Box
      doc.roundedRect(40, yScore, 120, 75, 4).fillAndStroke('#f1f5f9', '#cbd5e1');
      doc.fillColor('#64748b').fontSize(9).font('Helvetica-Bold').text('SECURITY SCORE', 45, yScore + 10, { width: 110, align: 'center' });
      doc.fillColor(scoreColor).fontSize(26).font('Helvetica-Bold').text(`${score}/100`, 45, yScore + 30, { width: 110, align: 'center' });

      // Severity Breakdown Boxes
      const boxes = [
        { label: 'CRITICAL', count: scan.summary?.critical || 0, color: criticalColor, x: 175 },
        { label: 'HIGH', count: scan.summary?.high || 0, color: highColor, x: 270 },
        { label: 'MEDIUM', count: scan.summary?.medium || 0, color: mediumColor, x: 365 },
        { label: 'LOW', count: scan.summary?.low || 0, color: lowColor, x: 460 },
      ];

      boxes.forEach(b => {
        doc.roundedRect(b.x, yScore, 85, 75, 4).fillAndStroke('#f8fafc', '#e2e8f0');
        doc.fillColor(b.color).fontSize(10).font('Helvetica-Bold').text(b.label, b.x + 5, yScore + 15, { width: 75, align: 'center' });
        doc.fillColor(primaryColor).fontSize(22).font('Helvetica-Bold').text(`${b.count}`, b.x + 5, yScore + 38, { width: 75, align: 'center' });
      });

      // --- AI EXECUTIVE SUMMARY ---
      let yPos = 300;
      if (scan.aiAnalysis && scan.aiAnalysis.summary) {
        doc.fillColor(accentColor).fontSize(13).font('Helvetica-Bold').text('AI-Powered Executive Analysis', 40, yPos);
        yPos += 20;

        doc.roundedRect(40, yPos, 515, 90, 4).fillAndStroke('#eff6ff', '#bfdbfe');
        doc.fillColor('#1e3a8a').fontSize(9).font('Helvetica').text(scan.aiAnalysis.summary, 50, yPos + 10, { width: 495, lineGap: 3 });
        yPos += 105;

        if (Array.isArray(scan.aiAnalysis.remediationPlan) && scan.aiAnalysis.remediationPlan.length > 0) {
          doc.fillColor(primaryColor).fontSize(11).font('Helvetica-Bold').text('Actionable Remediation Roadmap:', 40, yPos);
          yPos += 18;
          scan.aiAnalysis.remediationPlan.slice(0, 4).forEach((step, idx) => {
            doc.fillColor('#334155').fontSize(9).font('Helvetica').text(`${idx + 1}. ${step}`, 50, yPos, { width: 490 });
            yPos += 14;
          });
          yPos += 10;
        }
      }

      // --- TOP VULNERABILITIES TABLE ---
      if (yPos > 620) {
        doc.addPage();
        yPos = 40;
      }

      doc.fillColor(primaryColor).fontSize(13).font('Helvetica-Bold').text('Top Vulnerabilities (CVEs)', 40, yPos);
      yPos += 20;

      // Table Header
      doc.rect(40, yPos, 515, 20).fill('#334155');
      doc.fillColor('#ffffff').fontSize(8).font('Helvetica-Bold');
      doc.text('SEVERITY', 45, yPos + 6, { width: 60 });
      doc.text('CVE ID', 110, yPos + 6, { width: 90 });
      doc.text('PACKAGE', 205, yPos + 6, { width: 80 });
      doc.text('INSTALLED', 290, yPos + 6, { width: 70 });
      doc.text('FIXED IN', 365, yPos + 6, { width: 70 });
      doc.text('REMEDIATION', 440, yPos + 6, { width: 110 });

      yPos += 20;
      const vulns = (scan.vulnerabilities || []).slice(0, 15);

      if (vulns.length === 0) {
        doc.fillColor('#64748b').fontSize(9).font('Helvetica-Oblique').text('No vulnerabilities detected.', 45, yPos + 8);
        yPos += 25;
      } else {
        vulns.forEach((v, idx) => {
          if (yPos > 750) {
            doc.addPage();
            yPos = 40;
          }

          const bgColor = idx % 2 === 0 ? '#ffffff' : '#f8fafc';
          doc.rect(40, yPos, 515, 22).fill(bgColor);

          const sColor = v.severity === 'CRITICAL' ? criticalColor : v.severity === 'HIGH' ? highColor : mediumColor;
          doc.fillColor(sColor).fontSize(8).font('Helvetica-Bold').text(v.severity, 45, yPos + 6, { width: 60 });
          doc.fillColor(primaryColor).fontSize(8).font('Helvetica').text(v.vulnerabilityId, 110, yPos + 6, { width: 90 });
          doc.text(v.pkgName, 205, yPos + 6, { width: 80 });
          doc.text(v.installedVersion || 'N/A', 290, yPos + 6, { width: 70 });
          doc.text(v.fixedVersion || 'N/A', 365, yPos + 6, { width: 70 });
          doc.fillColor('#2563eb').text(v.fixedVersion ? `Upgrade to ${v.fixedVersion}` : 'Investigate', 440, yPos + 6, { width: 110 });

          yPos += 22;
        });
      }

      // --- MISCONFIGURATIONS ---
      const misconfigs = (scan.misconfigurations || []).slice(0, 8);
      if (misconfigs.length > 0) {
        if (yPos > 650) {
          doc.addPage();
          yPos = 40;
        }

        yPos += 15;
        doc.fillColor(primaryColor).fontSize(13).font('Helvetica-Bold').text('Security Misconfigurations', 40, yPos);
        yPos += 20;

        misconfigs.forEach(m => {
          if (yPos > 720) {
            doc.addPage();
            yPos = 40;
          }
          doc.roundedRect(40, yPos, 515, 36, 3).fillAndStroke('#fffbeb', '#fef3c7');
          doc.fillColor('#b45309').fontSize(8).font('Helvetica-Bold').text(`[${m.severity}] ${m.id}: ${m.title}`, 48, yPos + 6);
          doc.fillColor('#78350f').fontSize(8).font('Helvetica').text(m.message || m.resolution, 48, yPos + 18, { width: 500 });
          yPos += 42;
        });
      }

      // --- FOOTER ON ALL PAGES ---
      const range = doc.bufferedPageRange();
      for (let i = range.start; i < range.start + range.count; i++) {
        doc.switchToPage(i);
        doc.fontSize(8).fillColor('#94a3b8').text(
          `VigiDock AI • Confidential & Proprietary Security Audit Report • Page ${i + 1} of ${range.count}`,
          40,
          795,
          { align: 'center', width: 515 }
        );
      }

      doc.end();
    });
  }
};

module.exports = PdfService;
