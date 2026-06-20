"""
CyberRecon Pro - PDF Report Generator
Generates professional security assessment PDF reports using ReportLab.
"""

import os
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                 TableStyle, HRFlowable, PageBreak, KeepTogether)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.platypus import BaseDocTemplate, Frame, PageTemplate
import json

# ─── Color Palette ─────────────────────────────────────────────────────────────
C_DARK       = colors.HexColor('#060b14')
C_NAVY       = colors.HexColor('#0a1628')
C_CYAN       = colors.HexColor('#00d4ff')
C_PURPLE     = colors.HexColor('#7c3aed')
C_GREEN      = colors.HexColor('#00ff88')
C_RED        = colors.HexColor('#ff3366')
C_ORANGE     = colors.HexColor('#ffaa00')
C_YELLOW     = colors.HexColor('#ffd700')
C_WHITE      = colors.white
C_LIGHTGRAY  = colors.HexColor('#c9d1d9')
C_MIDGRAY    = colors.HexColor('#444d56')

RISK_COLORS = {
    'critical':      C_RED,
    'high':          C_ORANGE,
    'medium':        C_YELLOW,
    'low':           C_GREEN,
    'informational': C_LIGHTGRAY,
    'info':          C_LIGHTGRAY,
}

# ─── Page Template with header/footer ──────────────────────────────────────────
def _header_footer(canvas, doc):
    canvas.saveState()
    width, height = A4

    # Header bar
    canvas.setFillColor(C_NAVY)
    canvas.rect(0, height - 1.2*cm, width, 1.2*cm, fill=1, stroke=0)

    # Logo text
    canvas.setFillColor(C_CYAN)
    canvas.setFont('Helvetica-Bold', 10)
    canvas.drawString(1*cm, height - 0.85*cm, 'CYBERRECON PRO')

    # Right header
    canvas.setFillColor(C_LIGHTGRAY)
    canvas.setFont('Helvetica', 8)
    canvas.drawRightString(width - 1*cm, height - 0.85*cm, 'CONFIDENTIAL — AUTHORIZED USE ONLY')

    # Footer line
    canvas.setStrokeColor(C_CYAN)
    canvas.setLineWidth(0.5)
    canvas.line(1*cm, 1.2*cm, width - 1*cm, 1.2*cm)

    # Page number
    canvas.setFillColor(C_LIGHTGRAY)
    canvas.setFont('Helvetica', 8)
    canvas.drawCentredString(width / 2, 0.7*cm, f'Page {doc.page}')

    # Footer left
    canvas.drawString(1*cm, 0.7*cm, f'Generated: {datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")}')

    canvas.restoreState()


def generate_pdf_report(filepath: str, title: str, target, scans: list,
                         analyst: str, generated: datetime):
    """
    Generate a professional PDF security assessment report.
    """
    doc = SimpleDocTemplate(
        filepath,
        pagesize=A4,
        rightMargin=1.5*cm,
        leftMargin=1.5*cm,
        topMargin=2*cm,
        bottomMargin=2*cm,
    )

    styles = getSampleStyleSheet()
    story  = []

    # ── Custom Styles ──────────────────────────────────────────────────────────
    s_title = ParagraphStyle('CRTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=28,
        textColor=C_CYAN,
        alignment=TA_CENTER,
        spaceAfter=12,
    )
    s_subtitle = ParagraphStyle('CRSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=14,
        textColor=C_LIGHTGRAY,
        alignment=TA_CENTER,
        spaceAfter=6,
    )
    s_h1 = ParagraphStyle('CRH1',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=16,
        textColor=C_CYAN,
        spaceBefore=18,
        spaceAfter=8,
        borderPad=4,
    )
    s_h2 = ParagraphStyle('CRH2',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=12,
        textColor=C_PURPLE,
        spaceBefore=12,
        spaceAfter=6,
    )
    s_body = ParagraphStyle('CRBody',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        textColor=C_LIGHTGRAY,
        spaceAfter=4,
        leading=14,
    )
    s_code = ParagraphStyle('CRCode',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=8,
        textColor=C_GREEN,
        backColor=C_NAVY,
        spaceAfter=4,
        leftIndent=8,
        rightIndent=8,
        borderPad=6,
    )
    s_warning = ParagraphStyle('CRWarning',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=9,
        textColor=C_RED,
        spaceAfter=4,
    )
    s_center = ParagraphStyle('CRCenter',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        textColor=C_LIGHTGRAY,
        alignment=TA_CENTER,
        spaceAfter=4,
    )

    # ── Cover Page ─────────────────────────────────────────────────────────────
    story.append(Spacer(1, 3*cm))

    # Decorative top bar table
    story.append(Table(
        [['']],
        colWidths=[18*cm],
        rowHeights=[0.3*cm],
        style=TableStyle([('BACKGROUND', (0,0), (-1,-1), C_CYAN)])
    ))
    story.append(Spacer(1, 0.5*cm))

    story.append(Paragraph('SECURITY ASSESSMENT REPORT', s_title))
    story.append(Paragraph(title, s_subtitle))
    story.append(Spacer(1, 0.3*cm))

    # Cover info table
    cover_data = [
        ['Report Title',  title],
        ['Target',        target.name if target else 'All Targets'],
        ['Domain',        target.domain if target and target.domain else 'N/A'],
        ['Analyst',       analyst],
        ['Generated',     generated.strftime('%B %d, %Y — %H:%M UTC')],
        ['Classification','CONFIDENTIAL'],
        ['Report Type',   'Security Assessment & Reconnaissance'],
    ]
    cover_table = Table(cover_data, colWidths=[5*cm, 12*cm])
    cover_table.setStyle(TableStyle([
        ('BACKGROUND',   (0,0), (0,-1), C_NAVY),
        ('BACKGROUND',   (1,0), (1,-1), colors.HexColor('#0d1a2e')),
        ('TEXTCOLOR',    (0,0), (0,-1), C_CYAN),
        ('TEXTCOLOR',    (1,0), (1,-1), C_LIGHTGRAY),
        ('FONTNAME',     (0,0), (0,-1), 'Helvetica-Bold'),
        ('FONTNAME',     (1,0), (1,-1), 'Helvetica'),
        ('FONTSIZE',     (0,0), (-1,-1), 9),
        ('PADDING',      (0,0), (-1,-1), 8),
        ('ROWBACKGROUNDS', (0,0), (-1,-1), [C_NAVY, colors.HexColor('#0d1a2e')]),
        ('GRID',         (0,0), (-1,-1), 0.5, C_MIDGRAY),
        ('VALIGN',       (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(cover_table)
    story.append(Spacer(1, 0.5*cm))

    story.append(Table(
        [['']],
        colWidths=[18*cm],
        rowHeights=[0.3*cm],
        style=TableStyle([('BACKGROUND', (0,0), (-1,-1), C_PURPLE)])
    ))
    story.append(Spacer(1, 2*cm))

    # Legal disclaimer on cover
    disclaimer_text = (
        '<b>LEGAL DISCLAIMER:</b> This report has been prepared for authorized security '
        'assessment purposes only. All testing was conducted with explicit written permission '
        'from the target organization. Unauthorized use of the techniques or tools described '
        'herein may be illegal. The findings are confidential and intended solely for the '
        'authorized recipient.'
    )
    story.append(Paragraph(disclaimer_text, ParagraphStyle('Disclaimer',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        textColor=C_ORANGE,
        borderColor=C_ORANGE,
        borderWidth=0.5,
        borderPad=8,
        backColor=colors.HexColor('#1a0a00'),
        alignment=TA_CENTER,
    )))
    story.append(PageBreak())

    # ── Executive Summary ──────────────────────────────────────────────────────
    story.append(Paragraph('1. Executive Summary', s_h1))
    story.append(HRFlowable(width='100%', thickness=0.5, color=C_CYAN))
    story.append(Spacer(1, 0.3*cm))

    completed_scans = [s for s in scans if s.status == 'completed']
    total_results   = sum(s.results.count() for s in completed_scans)

    summary_text = (
        f'This security assessment report documents the reconnaissance and vulnerability analysis '
        f'conducted against the target <b>{target.name if target else "specified targets"}</b>. '
        f'A total of <b>{len(completed_scans)}</b> scans were performed using industry-standard '
        f'security tools. The assessment identified <b>{total_results}</b> findings that require '
        f'review and remediation.'
    )
    story.append(Paragraph(summary_text, s_body))
    story.append(Spacer(1, 0.3*cm))

    # Scan summary table
    if scans:
        story.append(Paragraph('Scan Summary', s_h2))
        scan_data = [['Tool', 'Scan Type', 'Status', 'Started', 'Duration']]
        for s in scans:
            duration = ''
            if s.completed_at and s.started_at:
                delta = s.completed_at - s.started_at
                duration = f'{int(delta.total_seconds())}s'
            scan_data.append([
                s.tool.upper(),
                s.scan_type or 'Standard',
                s.status.upper(),
                s.started_at.strftime('%Y-%m-%d %H:%M') if s.started_at else '',
                duration,
            ])
        _add_table(story, scan_data)

    story.append(PageBreak())

    # ── Reconnaissance Findings ────────────────────────────────────────────────
    story.append(Paragraph('2. Reconnaissance Findings', s_h1))
    story.append(HRFlowable(width='100%', thickness=0.5, color=C_CYAN))
    story.append(Spacer(1, 0.3*cm))

    # Collect all results by type
    all_results = []
    for s in completed_scans:
        for r in s.results.all():
            try:
                d = json.loads(r.data)
            except Exception:
                d = {}
            d['_risk']     = r.risk_level
            d['_analysis'] = r.ai_analysis
            d['_type']     = r.result_type
            d['_tool']     = s.tool
            all_results.append(d)

    # ── Open Ports ─────────────────────────────────────────────────────────────
    port_results = [r for r in all_results if r.get('_type') == 'port']
    if port_results:
        story.append(Paragraph('2.1 Open Ports & Services', s_h2))
        port_data = [['Port', 'Protocol', 'Service', 'Version', 'Risk']]
        for p in port_results:
            risk = p.get('_risk', 'informational')
            port_data.append([
                str(p.get('port', '')),
                p.get('protocol', 'tcp').upper(),
                p.get('service', ''),
                (p.get('product', '') + ' ' + p.get('version', '')).strip(),
                risk.upper(),
            ])
        _add_colored_table(story, port_data, risk_col=4)

    # ── Subdomains ─────────────────────────────────────────────────────────────
    sub_results = [r for r in all_results if r.get('_type') == 'subdomain']
    if sub_results:
        story.append(Paragraph('2.2 Discovered Subdomains', s_h2))
        sub_data = [['Subdomain', 'Source', 'Risk']]
        for s in sub_results:
            sub_data.append([
                s.get('subdomain', s.get('value', '')),
                s.get('source', ''),
                s.get('_risk', 'informational').upper(),
            ])
        _add_table(story, sub_data)

    # ── DNS Records ────────────────────────────────────────────────────────────
    dns_results = [r for r in all_results if r.get('_type') == 'dns']
    if dns_results:
        story.append(Paragraph('2.3 DNS Information', s_h2))
        dns_data = [['Type', 'Domain', 'Values', 'Risk']]
        for d in dns_results:
            values = d.get('values', [])
            if isinstance(values, list):
                val_str = ', '.join(str(v) for v in values[:5])
            else:
                val_str = str(values)[:80]
            dns_data.append([
                d.get('record_type', d.get('type_label', '')),
                d.get('domain', ''),
                val_str,
                d.get('_risk', 'informational').upper(),
            ])
        _add_table(story, dns_data)

    # ── Technologies ───────────────────────────────────────────────────────────
    tech_results = [r for r in all_results if r.get('_type') == 'tech']
    if tech_results:
        story.append(Paragraph('2.4 Technology Stack', s_h2))
        tech_data = [['Technology', 'Version', 'Risk']]
        for t in tech_results:
            tech_data.append([
                t.get('technology', ''),
                t.get('version', ''),
                t.get('_risk', 'informational').upper(),
            ])
        _add_table(story, tech_data)

    story.append(PageBreak())

    # ── AI Risk Analysis ───────────────────────────────────────────────────────
    story.append(Paragraph('3. AI-Powered Risk Analysis', s_h1))
    story.append(HRFlowable(width='100%', thickness=0.5, color=C_CYAN))
    story.append(Spacer(1, 0.3*cm))

    risk_findings = [r for r in all_results
                     if r.get('_risk') in ('critical', 'high') and r.get('_analysis')]
    if risk_findings:
        for r in risk_findings[:20]:  # Limit to top 20
            risk = r.get('_risk', 'low')
            color = RISK_COLORS.get(risk, C_LIGHTGRAY)
            story.append(KeepTogether([
                Paragraph(f'[{risk.upper()}] {r.get("_type","").upper()} — '
                          f'{r.get("port", r.get("subdomain", r.get("technology", "Finding")))}',
                          ParagraphStyle('FindingTitle',
                              parent=styles['Normal'],
                              fontName='Helvetica-Bold',
                              fontSize=9,
                              textColor=color,
                              spaceBefore=8,
                          )),
                Paragraph(r.get('_analysis', ''), s_body),
                HRFlowable(width='100%', thickness=0.3, color=C_MIDGRAY),
            ]))
    else:
        story.append(Paragraph('No critical or high-risk findings identified.', s_body))

    story.append(PageBreak())

    # ── Recommendations ────────────────────────────────────────────────────────
    story.append(Paragraph('4. Recommendations', s_h1))
    story.append(HRFlowable(width='100%', thickness=0.5, color=C_CYAN))
    story.append(Spacer(1, 0.3*cm))

    recommendations = [
        ('Patch Management',        'Regularly update all software, OS, and dependencies to address known CVEs.'),
        ('Network Segmentation',    'Isolate database servers, admin interfaces, and internal services from the internet.'),
        ('Firewall Rules',          'Restrict unnecessary open ports. Follow principle of least privilege for network access.'),
        ('TLS/SSL Hardening',       'Enforce TLS 1.2+ only. Disable SSLv3, TLS 1.0, and weak cipher suites.'),
        ('Authentication',          'Implement MFA on all externally accessible services. Enforce strong password policies.'),
        ('Monitoring & Alerting',   'Deploy SIEM, IDS/IPS, and log all authentication and access events.'),
        ('Vulnerability Scanning',  'Conduct regular automated vulnerability assessments and penetration tests.'),
        ('Security Headers',        'Implement CSP, HSTS, X-Frame-Options, and X-Content-Type-Options headers.'),
    ]

    for i, (rec_title, rec_text) in enumerate(recommendations, 1):
        story.append(KeepTogether([
            Paragraph(f'{i}. {rec_title}', s_h2),
            Paragraph(rec_text, s_body),
        ]))

    story.append(PageBreak())

    # ── Methodology & Scope ────────────────────────────────────────────────────
    story.append(Paragraph('5. Assessment Methodology', s_h1))
    story.append(HRFlowable(width='100%', thickness=0.5, color=C_CYAN))
    story.append(Spacer(1, 0.3*cm))

    tools_used = list(set(s.tool for s in scans))
    methodology_text = (
        f'This assessment followed a structured reconnaissance methodology utilizing the following '
        f'tools: <b>{", ".join(t.upper() for t in tools_used)}</b>. '
        f'All activities were performed in accordance with the authorized scope defined for this engagement. '
        f'Testing was conducted from: {datetime.utcnow().strftime("%Y-%m-%d")}.'
    )
    story.append(Paragraph(methodology_text, s_body))

    if target and target.scope:
        story.append(Paragraph('Defined Scope:', s_h2))
        story.append(Paragraph(target.scope, s_code))

    # ── Final Disclaimer ───────────────────────────────────────────────────────
    story.append(PageBreak())
    story.append(Paragraph('Legal Notice', s_h1))
    story.append(HRFlowable(width='100%', thickness=0.5, color=C_RED))
    story.append(Spacer(1, 0.5*cm))

    final_disclaimer = (
        'This report and its contents are STRICTLY CONFIDENTIAL and intended solely for the '
        'authorized recipient. All security testing described in this report was performed with '
        'explicit written authorization from the target organization.\n\n'
        'Unauthorized distribution, reproduction, or use of this report or any techniques '
        'described herein may violate applicable laws including the Computer Fraud and Abuse Act '
        '(CFAA), the Computer Misuse Act (CMA), and equivalent international legislation.\n\n'
        'CyberRecon Pro is designed exclusively for authorized security testing, educational '
        'purposes, and defensive security research. The authors and contributors accept no '
        'liability for misuse.'
    )
    story.append(Paragraph(final_disclaimer, s_body))

    # Build PDF
    doc.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer)


def _add_table(story, data):
    """Add a standard styled table to the story."""
    if len(data) <= 1:
        return
    col_count = len(data[0])
    page_width = 18 * cm
    col_widths = [page_width / col_count] * col_count

    t = Table(data, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ('BACKGROUND',   (0,0), (-1,0),  colors.HexColor('#0a1628')),
        ('TEXTCOLOR',    (0,0), (-1,0),  colors.HexColor('#00d4ff')),
        ('FONTNAME',     (0,0), (-1,0),  'Helvetica-Bold'),
        ('FONTSIZE',     (0,0), (-1,-1), 8),
        ('TEXTCOLOR',    (0,1), (-1,-1), colors.HexColor('#c9d1d9')),
        ('FONTNAME',     (0,1), (-1,-1), 'Helvetica'),
        ('ROWBACKGROUNDS', (0,1), (-1,-1),
         [colors.HexColor('#0d1117'), colors.HexColor('#161b22')]),
        ('GRID',         (0,0), (-1,-1), 0.3, colors.HexColor('#30363d')),
        ('PADDING',      (0,0), (-1,-1), 5),
        ('VALIGN',       (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(t)
    story.append(Spacer(1, 0.3*cm))


def _add_colored_table(story, data, risk_col=None):
    """Add table with risk-colored rows."""
    if len(data) <= 1:
        return
    col_count = len(data[0])
    page_width = 18 * cm
    col_widths = [page_width / col_count] * col_count

    t = Table(data, colWidths=col_widths, repeatRows=1)
    style_cmds = [
        ('BACKGROUND',   (0,0), (-1,0),  colors.HexColor('#0a1628')),
        ('TEXTCOLOR',    (0,0), (-1,0),  colors.HexColor('#00d4ff')),
        ('FONTNAME',     (0,0), (-1,0),  'Helvetica-Bold'),
        ('FONTSIZE',     (0,0), (-1,-1), 8),
        ('TEXTCOLOR',    (0,1), (-1,-1), colors.HexColor('#c9d1d9')),
        ('FONTNAME',     (0,1), (-1,-1), 'Helvetica'),
        ('ROWBACKGROUNDS', (0,1), (-1,-1),
         [colors.HexColor('#0d1117'), colors.HexColor('#161b22')]),
        ('GRID',         (0,0), (-1,-1), 0.3, colors.HexColor('#30363d')),
        ('PADDING',      (0,0), (-1,-1), 5),
        ('VALIGN',       (0,0), (-1,-1), 'MIDDLE'),
    ]

    if risk_col is not None:
        for row_idx, row in enumerate(data[1:], 1):
            risk = str(row[risk_col]).lower()
            color = RISK_COLORS.get(risk, colors.HexColor('#c9d1d9'))
            style_cmds.append(('TEXTCOLOR', (risk_col, row_idx), (risk_col, row_idx), color))
            style_cmds.append(('FONTNAME',  (risk_col, row_idx), (risk_col, row_idx), 'Helvetica-Bold'))

    t.setStyle(TableStyle(style_cmds))
    story.append(t)
    story.append(Spacer(1, 0.3*cm))
