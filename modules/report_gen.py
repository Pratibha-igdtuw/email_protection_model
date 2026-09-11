"""
Auto-generates a downloadable forensic PDF report per analyzed email:
threat score, geo data, header trace, SPF/DKIM/DMARC results,
blacklist status, WHOIS summary, timestamp, analyst notes.
"""
import os
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                 TableStyle, HRFlowable)

SEVERITY_COLORS = {
    'Critical': colors.HexColor('#b91c1c'),
    'High': colors.HexColor('#d97706'),
    'Medium': colors.HexColor('#ca8a04'),
    'Low': colors.HexColor('#16a34a'),
}


def generate_pdf_report(case, output_path, analyst_notes=""):
    """
    `case` is a dict assembled by the analysis pipeline containing:
    parsed_email, auth_result, geo_result, whois_result, classify_result,
    blacklist_hits, risk_result, case_id
    """
    doc = SimpleDocTemplate(output_path, pagesize=A4,
                             topMargin=18 * mm, bottomMargin=18 * mm,
                             leftMargin=18 * mm, rightMargin=18 * mm)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle('TitleX', parent=styles['Title'], fontSize=18, spaceAfter=4)
    h2 = ParagraphStyle('H2', parent=styles['Heading2'], spaceBefore=14, spaceAfter=6,
                         textColor=colors.HexColor('#1e293b'))
    normal = styles['Normal']
    mono = ParagraphStyle('Mono', parent=styles['Code'], fontSize=7.5, leading=9)

    elements = []
    elements.append(Paragraph("Email Forensic Intelligence Report", title_style))
    elements.append(Paragraph(f"Case ID: {case.get('case_id', 'N/A')} &nbsp;|&nbsp; "
                               f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}", normal))
    elements.append(HRFlowable(width="100%", color=colors.HexColor('#cbd5e1'), spaceBefore=8, spaceAfter=10))

    # --- Verdict ---
    risk = case.get('risk_result', {})
    severity = risk.get('severity', 'Low')
    sev_color = SEVERITY_COLORS.get(severity, colors.grey)
    verdict_data = [
        ['Combined Risk Score', f"{risk.get('combined_score', 0)} / 100"],
        ['Severity', severity],
    ]
    t = Table(verdict_data, colWidths=[70 * mm, 90 * mm])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f1f5f9')),
        ('TEXTCOLOR', (1, 1), (1, 1), sev_color),
        ('FONTNAME', (1, 1), (1, 1), 'Helvetica-Bold'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
    ]))
    elements.append(t)

    # --- Score breakdown ---
    elements.append(Paragraph("Risk Score Breakdown", h2))
    breakdown = risk.get('breakdown', {})
    bd_rows = [['Component', 'Points']] + [[k.replace('_', ' ').title(), str(v)] for k, v in breakdown.items()]
    bt = Table(bd_rows, colWidths=[110 * mm, 50 * mm])
    bt.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#334155')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('GRID', (0, 0), (-1, -1), 0.4, colors.HexColor('#cbd5e1')),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fafc')]),
    ]))
    elements.append(bt)

    # --- Email summary ---
    parsed = case.get('parsed_email', {})
    elements.append(Paragraph("Email Summary", h2))
    summary_rows = [
        ['From', parsed.get('from_raw', '') or ''],
        ['Subject', parsed.get('subject', '') or ''],
        ['Date', parsed.get('date', '') or ''],
        ['Sender Domain', parsed.get('sender_domain', '') or ''],
        ['Originating IP', parsed.get('originating_ip', '') or 'Not found'],
        ['Message-ID', parsed.get('message_id', '') or ''],
    ]
    st = Table(summary_rows, colWidths=[40 * mm, 120 * mm])
    st.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('GRID', (0, 0), (-1, -1), 0.4, colors.HexColor('#e2e8f0')),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    elements.append(st)

    # --- SPF/DKIM/DMARC ---
    auth = case.get('auth_result', {})
    elements.append(Paragraph("Email Authentication (SPF / DKIM / DMARC)", h2))
    auth_rows = [
        ['SPF', auth.get('spf', 'none')],
        ['DKIM', auth.get('dkim', 'none')],
        ['DMARC', auth.get('dmarc', 'none')],
        ['DMARC Published Policy', auth.get('dmarc_published_policy') or 'Not resolved'],
    ]
    at = Table(auth_rows, colWidths=[60 * mm, 100 * mm])
    at.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('GRID', (0, 0), (-1, -1), 0.4, colors.HexColor('#e2e8f0')),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
    ]))
    elements.append(at)
    if auth.get('high_weight_flags'):
        elements.append(Spacer(1, 4))
        for flag in auth['high_weight_flags']:
            elements.append(Paragraph(f"⚠ {flag}", ParagraphStyle('Flag', parent=normal, textColor=colors.HexColor('#b91c1c'), fontSize=9)))

    # --- Content AI red flags ---
    classify = case.get('classify_result', {})
    elements.append(Paragraph("Content AI / NLP Analysis", h2))
    elements.append(Paragraph(f"ML phishing probability: <b>{classify.get('ml_probability', 0)}%</b>", normal))
    if classify.get('red_flags'):
        for f in classify['red_flags']:
            elements.append(Paragraph(f"• {f}", normal))
    else:
        elements.append(Paragraph("No significant NLP red flags detected.", normal))

    # --- Geo ---
    geo = case.get('geo_result', {})
    elements.append(Paragraph("GeoLocation Intelligence", h2))
    if geo.get('status') == 'success':
        geo_rows = [
            ['IP', geo.get('ip', '')],
            ['Country', f"{geo.get('country','')} ({geo.get('country_code','')})"],
            ['Region / City', f"{geo.get('region','')} / {geo.get('city','')}"],
            ['ISP / Org', f"{geo.get('isp','')} / {geo.get('org','')}"],
            ['ASN', geo.get('asn', '')],
            ['Proxy/VPN', str(geo.get('is_proxy_or_vpn', False))],
            ['Hosting Provider', str(geo.get('is_hosting_provider', False))],
        ]
        gt = Table(geo_rows, colWidths=[45 * mm, 115 * mm])
        gt.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.4, colors.HexColor('#e2e8f0')),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
        ]))
        elements.append(gt)
    else:
        elements.append(Paragraph(f"GeoIP lookup status: {geo.get('status', 'unavailable')} — "
                                   f"{geo.get('message', '')}", normal))

    # --- WHOIS ---
    whois_r = case.get('whois_result', {})
    elements.append(Paragraph("WHOIS Summary", h2))
    if whois_r.get('status') == 'success':
        w_rows = [
            ['Registrar', whois_r.get('registrar', '') or ''],
            ['Creation Date', whois_r.get('creation_date', '') or ''],
            ['Domain Age (days)', str(whois_r.get('domain_age_days', 'N/A'))],
            ['Newly Registered (<30d)', str(whois_r.get('is_newly_registered', False))],
        ]
        wt = Table(w_rows, colWidths=[55 * mm, 105 * mm])
        wt.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.4, colors.HexColor('#e2e8f0')),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
        ]))
        elements.append(wt)
    else:
        elements.append(Paragraph(f"WHOIS status: {whois_r.get('status', 'unavailable')} — "
                                   f"{whois_r.get('message', '')}", normal))

    # --- Blacklist / Reputation ---
    local_hits = case.get('local_blacklist_hits', [])
    abuseipdb_r = case.get('abuseipdb_result', {})
    phishtank_r = case.get('phishtank_result', {})
    bl_reasons = case.get('blacklist_reasons', [])
    elements.append(Paragraph("Blacklist / Reputation Check", h2))
    if local_hits:
        for hit in local_hits:
            elements.append(Paragraph(
                f"• Local blacklist: {hit.get('indicator')} ({hit.get('type')}) — {hit.get('reason')}", normal))
    if phishtank_r.get('hits'):
        for hit in phishtank_r['hits']:
            elements.append(Paragraph(
                f"• PhishTank-verified: {hit.get('domain')} (impersonating {hit.get('target')}, "
                f"verified {hit.get('verified_time')})", normal))
    if abuseipdb_r.get('status') == 'success':
        elements.append(Paragraph(
            f"• AbuseIPDB confidence score: {abuseipdb_r.get('abuse_confidence_score')}% "
            f"({abuseipdb_r.get('total_reports')} reports)", normal))
    if not local_hits and not phishtank_r.get('hits') and abuseipdb_r.get('status') != 'success':
        elements.append(Paragraph("No blacklist, PhishTank, or AbuseIPDB matches.", normal))
    if phishtank_r.get('dataset_size'):
        elements.append(Paragraph(
            f"(Checked sender domain and message URLs against a snapshot of "
            f"{phishtank_r['dataset_size']:,} PhishTank-verified phishing domains.)",
            ParagraphStyle('Small', parent=normal, fontSize=7.5, textColor=colors.HexColor('#94a3b8'))))

    # --- Header trace ---
    elements.append(Paragraph("Full Header Relay Trace", h2))
    for hop in parsed.get('received_chain', []):
        line = f"Hop {hop['hop_number']}: from {hop.get('from_host')} by {hop.get('by_host')} | IPs: {', '.join(hop.get('ips', [])) or 'none'} | {hop.get('timestamp','')}"
        elements.append(Paragraph(line, mono))

    # --- Chain of custody ---
    custody = case.get('custody_record')
    if custody:
        elements.append(Paragraph("Chain of Custody & Evidence Integrity", h2))
        custody_rows = [
            ['Evidence File', os.path.basename(custody.get('evidence_file', ''))],
            ['Hash Algorithm', custody.get('hash_algorithm', 'SHA-256')],
            ['SHA-256 (at ingestion)', custody.get('sha256_at_ingestion', '') or ''],
            ['SHA-256 (at report time)', custody.get('sha256_at_report_time', '') or ''],
            ['Integrity Verified', 'YES — unmodified' if custody.get('integrity_verified') else 'NO — mismatch detected'],
            ['Custodian', custody.get('custodian', '')],
            ['Record Generated', custody.get('record_generated_at', '')],
        ]
        ct = Table(custody_rows, colWidths=[55 * mm, 105 * mm])
        ct.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.4, colors.HexColor('#e2e8f0')),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
        ]))
        elements.append(ct)
        elements.append(Spacer(1, 6))
        elements.append(Paragraph(custody.get('compliance_note', ''),
                                   ParagraphStyle('Compliance', parent=normal, fontSize=8, textColor=colors.HexColor('#475569'))))

    # --- Analyst notes ---
    elements.append(Paragraph("Analyst Notes", h2))
    elements.append(Paragraph(analyst_notes or "—", normal))

    doc.build(elements)
    return output_path
