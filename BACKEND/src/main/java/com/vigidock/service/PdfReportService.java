package com.vigidock.service;

import com.itextpdf.io.font.constants.StandardFonts;
import com.itextpdf.kernel.colors.Color;
import com.itextpdf.kernel.colors.ColorConstants;
import com.itextpdf.kernel.colors.DeviceRgb;
import com.itextpdf.kernel.font.PdfFont;
import com.itextpdf.kernel.font.PdfFontFactory;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.itextpdf.layout.Document;
import com.itextpdf.layout.borders.Border;
import com.itextpdf.layout.borders.SolidBorder;
import com.itextpdf.layout.element.Cell;
import com.itextpdf.layout.element.Paragraph;
import com.itextpdf.layout.element.Table;
import com.itextpdf.layout.properties.TextAlignment;
import com.itextpdf.layout.properties.UnitValue;
import com.vigidock.entity.ScanRecord;
import com.vigidock.entity.VulnerabilityDetail;
import com.vigidock.exception.ScanException;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.time.format.DateTimeFormatter;
import java.util.Collections;
import java.util.List;

@Service
public class PdfReportService {

    private static final Color BRAND_BLUE = new DeviceRgb(24, 78, 119);
    private static final Color LIGHT_BLUE = new DeviceRgb(232, 242, 250);
    private static final Color LIGHT_GRAY = new DeviceRgb(245, 247, 250);
    private static final DateTimeFormatter DATE_FORMATTER =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm");

    /**
     * Generates a downloadable PDF report for a completed scan.
     *
     * @param scanRecord scan statistics, AI summary, and vulnerability findings
     * @return PDF document bytes
     */
    public byte[] generateReport(ScanRecord scanRecord) {
        if (scanRecord == null) {
            throw new IllegalArgumentException("Scan record cannot be null");
        }

        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            PdfFont regularFont = PdfFontFactory.createFont(StandardFonts.HELVETICA);
            PdfFont boldFont = PdfFontFactory.createFont(StandardFonts.HELVETICA_BOLD);

            try (PdfDocument pdfDocument = new PdfDocument(new PdfWriter(outputStream));
                 Document document = new Document(pdfDocument)) {
                document.setMargins(36, 36, 36, 36);
                addHeader(document, scanRecord, boldFont);
                addTargetDetails(document, scanRecord, regularFont, boldFont);
                addExecutiveSummary(document, scanRecord, regularFont, boldFont);
                addActiveThreats(document, scanRecord, regularFont, boldFont);
                addDetailedFindings(document, scanRecord, regularFont, boldFont);
                addAiRemediationSteps(document, scanRecord, regularFont, boldFont);
            }

            return outputStream.toByteArray();
        } catch (IOException e) {
            throw new ScanException("Failed to generate PDF security report", e);
        }
    }

    private void addHeader(Document document, ScanRecord scanRecord, PdfFont boldFont) {
        Paragraph title = new Paragraph("VigiDock AI - Security Analysis Report")
                .setFont(boldFont)
                .setFontSize(20)
                .setFontColor(BRAND_BLUE)
                .setTextAlignment(TextAlignment.CENTER)
                .setMarginBottom(4);
        document.add(title);

        document.add(new Paragraph("Scan ID: " + valueOrFallback(scanRecord.getScanId(), "N/A"))
                .setFontSize(9)
                .setFontColor(ColorConstants.GRAY)
                .setTextAlignment(TextAlignment.CENTER)
                .setMarginBottom(18));
    }

    private void addTargetDetails(Document document, ScanRecord scanRecord,
                                  PdfFont regularFont, PdfFont boldFont) {
        addSectionHeading(document, "Target Details", boldFont);
        Table details = new Table(UnitValue.createPercentArray(new float[]{1, 2}))
                .useAllAvailableWidth()
                .setMarginBottom(16);
        addKeyValue(details, "Scan ID", valueOrFallback(scanRecord.getScanId(), "N/A"), regularFont, boldFont);
        addKeyValue(details, "Target", valueOrFallback(scanRecord.getTarget(), "N/A"), regularFont, boldFont);
        addKeyValue(details, "Scan Type", valueOrFallback(scanRecord.getScanType(), "N/A"), regularFont, boldFont);
        addKeyValue(details, "Status", valueOrFallback(scanRecord.getStatus(), "N/A"), regularFont, boldFont);
        addKeyValue(details, "Overall Risk", valueOrFallback(scanRecord.getOverallRiskScore(), "N/A"), regularFont, boldFont);
        document.add(details);
    }

    private void addExecutiveSummary(Document document, ScanRecord scanRecord,
                                     PdfFont regularFont, PdfFont boldFont) {
        addSectionHeading(document, "Severity Counts", boldFont);

        Table summaryTable = new Table(UnitValue.createPercentArray(new float[]{2.5f, 1.5f, 1, 1, 1, 1}))
                .useAllAvailableWidth()
                .setMarginBottom(16);
        addSummaryCell(summaryTable, "Image/YAML Name", boldFont, LIGHT_BLUE);
        addSummaryCell(summaryTable, "Date", boldFont, LIGHT_BLUE);
        addSummaryCell(summaryTable, "Critical", boldFont, severityColor("CRITICAL"));
        addSummaryCell(summaryTable, "High", boldFont, severityColor("HIGH"));
        addSummaryCell(summaryTable, "Medium", boldFont, severityColor("MEDIUM"));
        addSummaryCell(summaryTable, "Low", boldFont, severityColor("LOW"));

        addSummaryCell(summaryTable, valueOrFallback(scanRecord.getTarget(), "N/A"), regularFont, ColorConstants.WHITE);
        addSummaryCell(summaryTable, scanRecord.getScannedAt() == null
                ? "N/A" : DATE_FORMATTER.format(scanRecord.getScannedAt()), regularFont, ColorConstants.WHITE);
        addBadgeCell(summaryTable, scanRecord.getCriticalCount(), severityColor("CRITICAL"), boldFont);
        addBadgeCell(summaryTable, scanRecord.getHighCount(), severityColor("HIGH"), boldFont);
        addBadgeCell(summaryTable, scanRecord.getMediumCount(), severityColor("MEDIUM"), boldFont);
        addBadgeCell(summaryTable, scanRecord.getLowCount(), severityColor("LOW"), boldFont);
        document.add(summaryTable);

        if (hasText(scanRecord.getAiSummary())) {
            document.add(new Paragraph("AI Executive Summary")
                    .setFont(boldFont)
                    .setFontSize(11)
                    .setFontColor(BRAND_BLUE)
                    .setMarginBottom(4));
            document.add(new Paragraph(scanRecord.getAiSummary())
                    .setFont(regularFont)
                    .setFontSize(10)
                    .setMarginBottom(14));
        }
    }

    private void addDetailedFindings(Document document, ScanRecord scanRecord,
                                     PdfFont regularFont, PdfFont boldFont) {
        addSectionHeading(document, "Detailed Findings", boldFont);

        List<VulnerabilityDetail> findings = scanRecord.getVulnerabilities() == null
                ? Collections.emptyList() : scanRecord.getVulnerabilities();
        if (findings.isEmpty()) {
            document.add(new Paragraph("No vulnerabilities were identified in this scan.")
                    .setFont(regularFont)
                    .setFontSize(10));
            return;
        }

        for (int index = 0; index < findings.size(); index++) {
            VulnerabilityDetail finding = findings.get(index);
            Table findingTable = new Table(UnitValue.createPercentArray(new float[]{1, 4}))
                    .useAllAvailableWidth()
                    .setMarginBottom(10);

            Cell numberCell = new Cell(1, 1)
                    .add(new Paragraph(String.valueOf(index + 1))
                            .setFont(boldFont)
                            .setFontColor(ColorConstants.WHITE)
                            .setTextAlignment(TextAlignment.CENTER))
                    .setBackgroundColor(BRAND_BLUE)
                    .setVerticalAlignment(com.itextpdf.layout.properties.VerticalAlignment.MIDDLE)
                    .setBorder(Border.NO_BORDER);
            findingTable.addCell(numberCell);

            Cell detailCell = new Cell().setBackgroundColor(LIGHT_GRAY)
                    .setBorder(new SolidBorder(new DeviceRgb(220, 225, 230), 0.7f));
            Paragraph identifier = new Paragraph()
                    .add(new com.itextpdf.layout.element.Text(valueOrFallback(finding.getVulnerabilityId(), "Unknown finding"))
                            .setFont(boldFont))
                    .add("  ")
                    .add(new com.itextpdf.layout.element.Text("[" + valueOrFallback(finding.getSeverity(), "UNKNOWN") + "]")
                            .setFont(boldFont).setFontColor(severityColor(finding.getSeverity())));
            detailCell.add(identifier.setFontSize(11).setFontColor(BRAND_BLUE));
            detailCell.add(labelParagraph("Package", valueOrFallback(finding.getPackageName(), "N/A"), regularFont, boldFont));
            detailCell.add(labelParagraph("Plain-English Explanation", firstNonBlank(
                    finding.getAiExplanation(), finding.getDescription(), "No explanation available."), regularFont, boldFont));
            detailCell.add(labelParagraph("Remediation Fix", firstNonBlank(
                    finding.getAiRemediation(), finding.getFixedVersion(), "No remediation guidance available."), regularFont, boldFont));
            findingTable.addCell(detailCell);
            document.add(findingTable);
        }
    }

    private void addActiveThreats(Document document, ScanRecord scanRecord,
                                  PdfFont regularFont, PdfFont boldFont) {
        addSectionHeading(document, "Top EPSS Active Threats", boldFont);
        List<VulnerabilityDetail> threats = scanRecord.getVulnerabilities() == null
                ? Collections.emptyList()
                : scanRecord.getVulnerabilities().stream()
                .filter(finding -> "ACTIVE_THREAT".equalsIgnoreCase(finding.getThreatTag()))
                .sorted((left, right) -> Double.compare(
                        right.getEpssScore() == null ? 0.0 : right.getEpssScore(),
                        left.getEpssScore() == null ? 0.0 : left.getEpssScore()))
                .limit(10)
                .toList();

        if (threats.isEmpty()) {
            document.add(new Paragraph("No findings currently meet the ACTIVE_THREAT threshold (CVSS >= 7.0 and EPSS > 0.50).")
                    .setFont(regularFont)
                    .setFontSize(10)
                    .setMarginBottom(12));
            return;
        }

        Table table = new Table(UnitValue.createPercentArray(new float[]{2, 1.2f, 1, 1, 2}))
                .useAllAvailableWidth()
                .setMarginBottom(16);
        addSummaryCell(table, "CVE", boldFont, LIGHT_BLUE);
        addSummaryCell(table, "Package", boldFont, LIGHT_BLUE);
        addSummaryCell(table, "CVSS", boldFont, LIGHT_BLUE);
        addSummaryCell(table, "EPSS", boldFont, LIGHT_BLUE);
        addSummaryCell(table, "Tag", boldFont, LIGHT_BLUE);
        for (VulnerabilityDetail threat : threats) {
            addSummaryCell(table, valueOrFallback(threat.getVulnerabilityId(), "N/A"), regularFont, ColorConstants.WHITE);
            addSummaryCell(table, valueOrFallback(threat.getPackageName(), "N/A"), regularFont, ColorConstants.WHITE);
            addSummaryCell(table, formatScore(threat.getCvssScore()), regularFont, ColorConstants.WHITE);
            addSummaryCell(table, formatScore(threat.getEpssScore()), regularFont, ColorConstants.WHITE);
            addSummaryCell(table, valueOrFallback(threat.getThreatTag(), "MONITORED"), regularFont, ColorConstants.WHITE);
        }
        document.add(table);
    }

    private void addAiRemediationSteps(Document document, ScanRecord scanRecord,
                                       PdfFont regularFont, PdfFont boldFont) {
        addSectionHeading(document, "AI Remediation Steps", boldFont);
        List<VulnerabilityDetail> findings = scanRecord.getVulnerabilities() == null
                ? Collections.emptyList() : scanRecord.getVulnerabilities();
        if (findings.isEmpty()) {
            document.add(new Paragraph("No remediation steps were generated for this scan.")
                    .setFont(regularFont)
                    .setFontSize(10));
            return;
        }

        int shown = 0;
        for (VulnerabilityDetail finding : findings) {
            String remediation = firstNonBlank(finding.getAiRemediation(),
                    hasText(finding.getFixedVersion()) ? "Upgrade to " + finding.getFixedVersion() : null,
                    null);
            if (!hasText(remediation)) {
                continue;
            }
            document.add(new Paragraph(valueOrFallback(finding.getVulnerabilityId(), "Finding"))
                    .setFont(boldFont)
                    .setFontSize(11)
                    .setFontColor(BRAND_BLUE)
                    .setMarginBottom(2));
            document.add(new Paragraph(remediation)
                    .setFont(regularFont)
                    .setFontSize(10)
                    .setMarginBottom(10));
            shown++;
            if (shown == 8) {
                break;
            }
        }
        if (shown == 0) {
            document.add(new Paragraph("Request AI explanations for individual CVEs to populate remediation guidance.")
                    .setFont(regularFont)
                    .setFontSize(10));
        }
    }

    private void addKeyValue(Table table, String key, String value, PdfFont regularFont, PdfFont boldFont) {
        table.addCell(new Cell()
                .add(new Paragraph(key).setFont(boldFont).setFontSize(9))
                .setBackgroundColor(LIGHT_BLUE)
                .setPadding(6));
        table.addCell(new Cell()
                .add(new Paragraph(value).setFont(regularFont).setFontSize(9))
                .setPadding(6));
    }

    private String formatScore(Double score) {
        return score == null ? "N/A" : String.format("%.3f", score);
    }

    private void addSectionHeading(Document document, String heading, PdfFont boldFont) {
        document.add(new Paragraph(heading)
                .setFont(boldFont)
                .setFontSize(14)
                .setFontColor(BRAND_BLUE)
                .setBorderBottom(new SolidBorder(BRAND_BLUE, 1.2f))
                .setPaddingBottom(4)
                .setMarginBottom(8));
    }

    private void addSummaryCell(Table table, String text, PdfFont font, Color backgroundColor) {
        table.addCell(new Cell()
                .add(new Paragraph(text).setFont(font).setFontSize(9))
                .setBackgroundColor(backgroundColor)
                .setTextAlignment(TextAlignment.CENTER)
                .setVerticalAlignment(com.itextpdf.layout.properties.VerticalAlignment.MIDDLE)
                .setPadding(6));
    }

    private void addBadgeCell(Table table, int count, Color backgroundColor, PdfFont boldFont) {
        table.addCell(new Cell()
                .add(new Paragraph(String.valueOf(count)).setFont(boldFont).setFontSize(12))
                .setBackgroundColor(backgroundColor)
                .setTextAlignment(TextAlignment.CENTER)
                .setVerticalAlignment(com.itextpdf.layout.properties.VerticalAlignment.MIDDLE)
                .setPadding(6));
    }

    private Paragraph labelParagraph(String label, String value, PdfFont regularFont, PdfFont boldFont) {
        return new Paragraph()
                .add(new com.itextpdf.layout.element.Text(label + ": ").setFont(boldFont))
                .add(new com.itextpdf.layout.element.Text(value).setFont(regularFont))
                .setFontSize(9)
                .setMarginTop(3)
                .setMarginBottom(3);
    }

    private Color severityColor(String severity) {
        if (severity == null) {
            return ColorConstants.GRAY;
        }
        return switch (severity.toUpperCase()) {
            case "CRITICAL" -> new DeviceRgb(190, 35, 45);
            case "HIGH" -> new DeviceRgb(220, 105, 35);
            case "MEDIUM" -> new DeviceRgb(205, 155, 25);
            case "LOW" -> new DeviceRgb(45, 135, 75);
            default -> ColorConstants.GRAY;
        };
    }

    private String firstNonBlank(String first, String second, String fallback) {
        return hasText(first) ? first : hasText(second) ? second : fallback;
    }

    private String valueOrFallback(String value, String fallback) {
        return hasText(value) ? value : fallback;
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }
}
