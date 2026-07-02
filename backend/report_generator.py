"""
report_generator.py
---------------------
Génère un rapport PDF très professionnel pour un fichier spécifique
ou un cas complet, avec résumé exécutif, KPIs, IOCs, et recommandations.
"""

from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak, KeepTogether
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT

SEVERITY_COLORS = {
    "critical": colors.HexColor("#dc2626"),
    "high": colors.HexColor("#f97316"),
    "medium": colors.HexColor("#eab308"),
    "low": colors.HexColor("#22c55e"),
    "info": colors.HexColor("#3b82f6"),
}

def get_threat_level(alerts):
    if any(a.get("severity") == "critical" for a in alerts):
        return "CRITIQUE", SEVERITY_COLORS["critical"]
    if any(a.get("severity") == "high" for a in alerts):
        return "ÉLEVÉ", SEVERITY_COLORS["high"]
    if any(a.get("severity") == "medium" for a in alerts):
        return "MODÉRÉ", SEVERITY_COLORS["medium"]
    return "FAIBLE", SEVERITY_COLORS["low"]

def generate_report(case_id: str, alerts: list[dict], stats: dict, output_path: str, filename: str = None):
    doc = SimpleDocTemplate(
        output_path, 
        pagesize=A4,
        topMargin=1.5*cm, 
        bottomMargin=1.5*cm,
        leftMargin=1.5*cm,
        rightMargin=1.5*cm
    )
    styles = getSampleStyleSheet()
    
    # Styles personnalisés
    title_style = ParagraphStyle(
        "TitleCustom", parent=styles["Title"], 
        fontSize=24, textColor=colors.HexColor("#1e293b"), spaceAfter=0.5*cm
    )
    subtitle_style = ParagraphStyle(
        "SubtitleCustom", parent=styles["Normal"], 
        fontSize=12, textColor=colors.HexColor("#64748b"), alignment=TA_CENTER, spaceAfter=2*cm
    )
    h1_style = ParagraphStyle(
        "H1Custom", parent=styles["Heading1"],
        fontSize=16, textColor=colors.HexColor("#0f172a"),
        borderPadding=(0,0,5,0), spaceBefore=1*cm, spaceAfter=0.5*cm
    )
    h2_style = ParagraphStyle(
        "H2Custom", parent=styles["Heading2"],
        fontSize=14, textColor=colors.HexColor("#334155"), spaceBefore=0.5*cm, spaceAfter=0.3*cm
    )
    normal_style = ParagraphStyle("NormalCustom", parent=styles["Normal"], fontSize=10, textColor=colors.HexColor("#334155"), leading=14)
    alert_title_style = ParagraphStyle("AlertTitle", parent=styles["Normal"], fontSize=10, textColor=colors.HexColor("#0f172a"), fontName="Helvetica-Bold")
    
    story = []

    threat_label, threat_color = get_threat_level(alerts)
    report_date = datetime.now().strftime('%d/%m/%Y %H:%M')
    target_name = filename if filename else f"Dossier complet: {case_id}"

    # =========================================================================
    # PAGE DE GARDE
    # =========================================================================
    story.append(Spacer(1, 4*cm))
    story.append(Paragraph("<b>ForensiQ</b>", ParagraphStyle("Brand", parent=title_style, fontSize=28, textColor=colors.HexColor("#3b82f6"))))
    story.append(Paragraph("RAPPORT D'INVESTIGATION FORENSIQUE", title_style))
    story.append(Paragraph(f"Cible analysée : {target_name}", subtitle_style))
    
    # Box niveau de menace
    threat_data = [[Paragraph(f"<font color='white'><b>NIVEAU DE MENACE : {threat_label}</b></font>", ParagraphStyle("T", alignment=TA_CENTER))]]
    t_threat = Table(threat_data, colWidths=[10*cm], rowHeights=[1.5*cm])
    t_threat.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), threat_color),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ROUNDEDCORNERS", [10, 10, 10, 10]),
    ]))
    story.append(t_threat)
    story.append(Spacer(1, 2*cm))
    
    # Méta-données
    meta_data = [
        ["Référence", f"CASE-{case_id}"],
        ["Date du rapport", report_date],
        ["Classification", "CONFIDENTIEL"],
        ["Total alertes", str(len(alerts))]
    ]
    t_meta = Table(meta_data, colWidths=[5*cm, 8*cm])
    t_meta.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#64748b")),
        ("TEXTCOLOR", (1, 0), (1, -1), colors.HexColor("#0f172a")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LINEBELOW", (0, 0), (-1, -2), 0.5, colors.HexColor("#e2e8f0")),
    ]))
    story.append(t_meta)
    story.append(PageBreak())

    # =========================================================================
    # RÉSUMÉ EXÉCUTIF
    # =========================================================================
    story.append(Paragraph("1. Résumé exécutif", h1_style))
    
    crit_count = sum(1 for a in alerts if a.get("severity") == "critical")
    high_count = sum(1 for a in alerts if a.get("severity") == "high")
    
    exec_summary = (
        f"L'analyse forensique de <b>{target_name}</b> a mis en évidence un niveau de menace "
        f"<font color='{threat_color.hexval()}'><b>{threat_label}</b></font>. "
        f"Au total, <b>{len(alerts)} alertes</b> ont été générées par nos moteurs d'analyse. "
    )
    if crit_count > 0 or high_count > 0:
        exec_summary += (
            f"On dénombre notamment <b>{crit_count} alerte(s) critique(s)</b> et "
            f"<b>{high_count} alerte(s) de niveau élevé</b> nécessitant une attention particulière. "
        )
    exec_summary += "Les conclusions et recommandations ci-dessous sont basées sur l'extraction d'artefacts techniques (IOCs, logs)."
    story.append(Paragraph(exec_summary, normal_style))
    story.append(Spacer(1, 1*cm))

    # Tableau KPIs
    kpi_data = [
        ["CRITIQUES", "ÉLEVÉES", "MOYENNES", "FAIBLES", "INFO"],
        [
            str(crit_count),
            str(high_count),
            str(sum(1 for a in alerts if a.get("severity") == "medium")),
            str(sum(1 for a in alerts if a.get("severity") == "low")),
            str(sum(1 for a in alerts if a.get("severity") == "info")),
        ]
    ]
    t_kpi = Table(kpi_data, colWidths=[3.2*cm]*5)
    t_kpi.setStyle(TableStyle([
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 9),
        ("FONTSIZE", (0, 1), (-1, 1), 16),
        ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"),
        ("TEXTCOLOR", (0, 0), (0, -1), SEVERITY_COLORS["critical"]),
        ("TEXTCOLOR", (1, 0), (1, -1), SEVERITY_COLORS["high"]),
        ("TEXTCOLOR", (2, 0), (2, -1), SEVERITY_COLORS["medium"]),
        ("TEXTCOLOR", (3, 0), (3, -1), SEVERITY_COLORS["low"]),
        ("TEXTCOLOR", (4, 0), (4, -1), SEVERITY_COLORS["info"]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f8fafc")),
        ("PADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(t_kpi)
    story.append(Spacer(1, 1*cm))

    # =========================================================================
    # RECOMMANDATIONS
    # =========================================================================
    story.append(Paragraph("2. Recommandations prioritaires", h1_style))
    if crit_count > 0:
        story.append(Paragraph("<font color='#dc2626'><b>IMMÉDIAT (Menace Critique)</b></font>", normal_style))
        story.append(Paragraph("• Isoler immédiatement le système compromis du réseau de production.", normal_style))
        story.append(Paragraph("• Engager le plan de réponse aux incidents (CSIRT).", normal_style))
        story.append(Spacer(1, 0.3*cm))
    
    if high_count > 0 or crit_count > 0:
        story.append(Paragraph("<font color='#f97316'><b>COURT TERME (< 48h)</b></font>", normal_style))
        story.append(Paragraph("• Bloquer les IPs malveillantes extraites (IOCs) sur le pare-feu.", normal_style))
        story.append(Paragraph("• Collecter des images mémoire (RAM) et disque pour investigation approfondie.", normal_style))
        story.append(Spacer(1, 0.3*cm))
        
    story.append(Paragraph("<font color='#eab308'><b>MOYEN TERME</b></font>", normal_style))
    story.append(Paragraph("• Auditer les accès sur la période correspondant aux alertes.", normal_style))
    story.append(Paragraph("• Revoir les règles de détection et intégrer les nouveaux IOCs au SIEM.", normal_style))
    story.append(PageBreak())

    # =========================================================================
    # ALERTES DÉTAILLÉES
    # =========================================================================
    story.append(Paragraph("3. Top Alertes (Critiques et Élevées)", h1_style))
    
    priority_alerts = [a for a in alerts if a.get("severity") in ("critical", "high")]
    priority_alerts.sort(key=lambda a: a.get("score", 0), reverse=True)
    
    if not priority_alerts:
        story.append(Paragraph("Aucune alerte critique ou élevée détectée.", normal_style))
    
    for a in priority_alerts[:20]:  # Limité aux 20 plus graves
        sev = a.get("severity", "info")
        color = SEVERITY_COLORS.get(sev, colors.grey)
        
        # Titre de l'alerte
        header = f'<font color="{color.hexval()}">[{sev.upper()}]</font> {a.get("title", "Alerte de sécurité")}'
        
        # Construction d'un bloc solidaire (KeepTogether)
        alert_block = []
        alert_block.append(Paragraph(header, alert_title_style))
        
        # Tableau de détails
        details_data = [
            ["Source", (a.get("tool") or "—").upper(), "Horodatage", str(a.get("timestamp") or "—")[:19]],
            ["Cible / IP", str(a.get("target") or a.get("dst_ip") or "—"), "MITRE", a.get("mitre_attack") or "—"]
        ]
        t_det = Table(details_data, colWidths=[2.5*cm, 6.5*cm, 2.5*cm, 6.5*cm])
        t_det.setStyle(TableStyle([
            ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#475569")),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTNAME", (2, 0), (2, -1), "Helvetica-Bold"),
            ("LINEBELOW", (0, 0), (-1, -1), 0.25, colors.HexColor("#f1f5f9")),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        alert_block.append(Spacer(1, 0.1*cm))
        alert_block.append(t_det)
        
        if a.get("details"):
            alert_block.append(Spacer(1, 0.1*cm))
            alert_block.append(Paragraph(f"<font color='#64748b'>Détails :</font> {str(a['details'])[:250]}", ParagraphStyle("S", parent=normal_style, fontSize=8)))

        # VirusTotal intel
        if a.get("threat_intel"):
            for ti in a["threat_intel"][:2]:
                alert_block.append(Paragraph(
                    f"<font color='#ef4444'>⚠ VirusTotal : {ti['value']} signalé malveillant par {ti.get('malicious', 0)} moteurs.</font>", 
                    ParagraphStyle("TI", parent=normal_style, fontSize=8)
                ))

        alert_block.append(Spacer(1, 0.5*cm))
        story.append(KeepTogether(alert_block))

    doc.build(story)
    return output_path