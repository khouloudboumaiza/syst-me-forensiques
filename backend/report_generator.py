"""
report_generator.py
---------------------
Génère un rapport PDF complet pour un dossier d'investigation, à partir
des alertes stockées en base (Hayabusa, Loki, ML réseau) + enrichissement
threat intel.

Installation :
    pip install reportlab --break-system-packages
"""

from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

SEVERITY_COLORS = {
    "critical": colors.HexColor("#dc2626"),
    "high": colors.HexColor("#f97316"),
    "medium": colors.HexColor("#eab308"),
    "low": colors.HexColor("#22c55e"),
    "info": colors.HexColor("#94a3b8"),
}


def generate_report(case_id: str, alerts: list[dict], stats: dict, output_path: str):
    """
    alerts : liste de dicts (mélange Hayabusa/Loki/ML, déjà normalisée)
    stats  : dict avec files_analyzed, alerts, iocs, etc.
    output_path : chemin de sortie du PDF, ex: "reports/demo_report.pdf"
    """
    doc = SimpleDocTemplate(output_path, pagesize=A4,
                             topMargin=2*cm, bottomMargin=2*cm)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("TitleCustom", parent=styles["Title"], fontSize=20)
    story = []

    # --- Page de garde ---
    story.append(Paragraph("Rapport d'Investigation Forensique", title_style))
    story.append(Spacer(1, 0.5*cm))
    story.append(Paragraph(f"Dossier : {case_id}", styles["Normal"]))
    story.append(Paragraph(f"Généré le : {datetime.now().strftime('%d/%m/%Y %H:%M')}", styles["Normal"]))
    story.append(Spacer(1, 1*cm))

    # --- Résumé exécutif ---
    story.append(Paragraph("Résumé exécutif", styles["Heading2"]))
    summary_data = [
        ["Fichiers analysés", str(stats.get("files_analyzed", "—"))],
        ["Alertes totales", str(len(alerts))],
        ["Critiques", str(sum(1 for a in alerts if a.get("severity") == "critical"))],
        ["Élevées", str(sum(1 for a in alerts if a.get("severity") == "high"))],
        ["Confirmées par threat intel", str(sum(1 for a in alerts if a.get("threat_intel")))],
    ]
    t = Table(summary_data, colWidths=[8*cm, 6*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f1f5f9")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("PADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(t)
    story.append(Spacer(1, 1*cm))

    # --- Répartition par outil ---
    tools = {}
    for a in alerts:
        tools[a.get("tool", "unknown")] = tools.get(a.get("tool", "unknown"), 0) + 1
    story.append(Paragraph("Répartition par source", styles["Heading2"]))
    tool_data = [["Outil", "Nombre d'alertes"]] + [[k, str(v)] for k, v in tools.items()]
    t2 = Table(tool_data, colWidths=[8*cm, 6*cm])
    t2.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("PADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(t2)
    story.append(PageBreak())

    # --- Détail des alertes critiques et élevées ---
    story.append(Paragraph("Détail des alertes prioritaires", styles["Heading2"]))
    story.append(Spacer(1, 0.3*cm))

    priority_alerts = [a for a in alerts if a.get("severity") in ("critical", "high")]
    priority_alerts.sort(key=lambda a: a.get("score", 0), reverse=True)

    for a in priority_alerts[:50]:  # limite pour garder un PDF raisonnable
        sev = a.get("severity", "info")
        color = SEVERITY_COLORS.get(sev, colors.grey)

        header = f'<font color="{color.hexval()}"><b>[{sev.upper()}]</b></font> {a.get("title", "Alerte")}'
        story.append(Paragraph(header, styles["Heading4"]))
        story.append(Paragraph(f"Source : {a.get('tool', '—')} | Horodatage : {a.get('timestamp', '—')}", styles["Normal"]))
        story.append(Paragraph(f"Cible : {a.get('target', '—')}", styles["Normal"]))
        if a.get("details"):
            story.append(Paragraph(f"Détails : {a['details'][:300]}", styles["Normal"]))
        if a.get("mitre_attack"):
            story.append(Paragraph(f"MITRE ATT&CK : {a['mitre_attack']}", styles["Normal"]))
        if a.get("threat_intel"):
            for ti in a["threat_intel"]:
                story.append(Paragraph(
                    f'⚠ VirusTotal : {ti["type"]} {ti["value"]} → {ti["verdict"]} '
                    f'({ti.get("malicious", 0)} moteurs le signalent malveillant)',
                    styles["Normal"]
                ))
        story.append(Spacer(1, 0.4*cm))

    doc.build(story)
    return output_path