"""
report_generator.py
---------------------
Génère un rapport PDF très professionnel pour un fichier spécifique
ou un cas complet, avec explications détaillées, étapes d'attaque, et recommandations.
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

def generate_human_explanation(rule: str, target: str, tool: str) -> str:
    r = str(rule or "").lower()
    t = target or "la cible"
    if "logon" in r or "login" in r or "connexion" in r:
        return f"Une tentative de connexion a été identifiée sur {t}."
    if "process" in r or "execution" in r or "cmd" in r or "shell" in r:
        return f"L'exécution d'une commande ou d'un processus potentiellement malveillant ({t}) a été observée."
    if "malware" in r or "virus" in r or "trojan" in r or "backdoor" in r:
        return f"La présence d'un logiciel malveillant ou d'une porte dérobée a été détectée dans {t}."
    if "network" in r or "connection" in r or "traffic" in r or "port" in r:
        return f"Un trafic réseau anormal ou suspect a été initié en direction de {t}."
    if "privilege" in r or "admin" in r or "credential" in r:
        return f"Une activité liée à une potentielle élévation de privilèges ou un vol d'identifiants a été ciblée sur {t}."
    if "file" in r or "registry" in r:
        return f"Des modifications suspectes affectant un fichier ou le registre système ({t}) ont été enregistrées."
    return f"L'outil de détection ({tool}) a identifié un comportement système anormal concernant {t}."

def extract_structured_iocs(alerts: list[dict]):
    ioc_map = {}
    for a in alerts:
        timestamp = str(a.get("timestamp") or "Non horodaté")[:19]
        tool = (a.get("tool") or "Système").upper()
        
        # IP targets
        dst_ip = a.get("dst_ip")
        if dst_ip and dst_ip not in ("127.0.0.1", "0.0.0.0") and len(dst_ip) > 5:
            key = f"IP-{dst_ip}"
            if key not in ioc_map:
                ioc_map[key] = {"type": "IP", "value": dst_ip, "source": tool, "hits": 0, "firstSeen": timestamp}
            ioc_map[key]["hits"] += 1
            if timestamp < ioc_map[key]["firstSeen"]:
                ioc_map[key]["firstSeen"] = timestamp
                
        # Fichiers (Loki ou autres targets de chemins)
        target = a.get("target")
        if target and ("\\" in target or "/" in target):
            key = f"FILE-{target}"
            if key not in ioc_map:
                ioc_map[key] = {"type": "Fichier", "value": target, "source": tool, "hits": 0, "firstSeen": timestamp}
            ioc_map[key]["hits"] += 1
            if timestamp < ioc_map[key]["firstSeen"]:
                ioc_map[key]["firstSeen"] = timestamp
                
        # Hashes (Threat Intel)
        ti = a.get("threat_intel")
        if isinstance(ti, list):
            for t in ti:
                if t.get("type") == "hash":
                    h = t.get("value")
                    key = f"HASH-{h}"
                    if key not in ioc_map:
                        mal = t.get("malicious", 0)
                        sus = t.get("suspicious", 0)
                        har = t.get("harmless", 0)
                        tot = mal + sus + har
                        ioc_map[key] = {
                            "type": "Hash", 
                            "value": h, 
                            "source": tool, 
                            "hits": 0, 
                            "firstSeen": timestamp,
                            "vt_malicious": mal,
                            "vt_total": tot,
                            "vt_verdict": t.get("verdict", "unknown")
                        }
                    ioc_map[key]["hits"] += 1
                    if timestamp < ioc_map[key]["firstSeen"]:
                        ioc_map[key]["firstSeen"] = timestamp

    return sorted(list(ioc_map.values()), key=lambda x: x["hits"], reverse=True)

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
    
    title_style = ParagraphStyle("TitleCustom", parent=styles["Title"], fontSize=24, textColor=colors.HexColor("#1e293b"), spaceAfter=0.5*cm)
    subtitle_style = ParagraphStyle("SubtitleCustom", parent=styles["Normal"], fontSize=12, textColor=colors.HexColor("#64748b"), alignment=TA_CENTER, spaceAfter=2*cm)
    h1_style = ParagraphStyle("H1Custom", parent=styles["Heading1"], fontSize=16, textColor=colors.HexColor("#0f172a"), borderPadding=(0,0,5,0), spaceBefore=1*cm, spaceAfter=0.5*cm)
    h2_style = ParagraphStyle("H2Custom", parent=styles["Heading2"], fontSize=14, textColor=colors.HexColor("#334155"), spaceBefore=0.5*cm, spaceAfter=0.3*cm)
    normal_style = ParagraphStyle("NormalCustom", parent=styles["Normal"], fontSize=10, textColor=colors.HexColor("#334155"), leading=14, spaceAfter=0.2*cm)
    alert_title_style = ParagraphStyle("AlertTitle", parent=styles["Normal"], fontSize=10, textColor=colors.HexColor("#0f172a"), fontName="Helvetica-Bold")
    
    story = []

    threat_label, threat_color = get_threat_level(alerts)
    report_date = datetime.now().strftime('%d/%m/%Y %H:%M')
    target_name = filename if filename else f"Dossier complet: {case_id}"

    # PAGE DE GARDE
    story.append(Spacer(1, 4*cm))
    story.append(Paragraph("<b>ForensiQ</b>", ParagraphStyle("Brand", parent=title_style, fontSize=28, textColor=colors.HexColor("#3b82f6"))))
    story.append(Paragraph("RAPPORT D'INVESTIGATION FORENSIQUE", title_style))
    story.append(Paragraph(f"Fichier d'analyse : {target_name}", subtitle_style))
    
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
    
    meta_data = [
        ["Référence de l'incident", f"CASE-{case_id}"],
        ["Date du rapport", report_date],
        ["Classification", "CONFIDENTIEL"],
        ["Nombre total d'alertes", str(len(alerts))]
    ]
    t_meta = Table(meta_data, colWidths=[6*cm, 7*cm])
    t_meta.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#64748b")),
        ("TEXTCOLOR", (1, 0), (1, -1), colors.HexColor("#0f172a")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LINEBELOW", (0, 0), (-1, -2), 0.5, colors.HexColor("#e2e8f0")),
    ]))
    story.append(t_meta)
    story.append(PageBreak())

    crit_count = sum(1 for a in alerts if a.get("severity") == "critical")
    high_count = sum(1 for a in alerts if a.get("severity") == "high")
    tools_used = list(set([a.get("tool", "Inconnu") for a in alerts]))
    structured_iocs = extract_structured_iocs(alerts)

    # 1. EXPLICATION GÉNÉRALE DE L'INCIDENT
    story.append(Paragraph("1. Explication Générale de l'Incident", h1_style))
    general_summary = (
        f"Ce rapport détaille l'analyse forensique effectuée sur la source <b>{target_name}</b>. "
        f"L'investigation a révélé un niveau de compromission <font color='{threat_color.hexval()}'><b>{threat_label}</b></font>, "
        f"basé sur l'analyse de <b>{len(alerts)} événements distincts</b>. "
    )
    if crit_count > 0:
        general_summary += "Une attention immédiate est requise en raison de la présence d'indicateurs de compromission (IOCs) critiques suggérant une attaque active ou un système compromis."
    elif high_count > 0:
        general_summary += "Des comportements hautement suspects ont été repérés, pouvant indiquer une intrusion en cours ou la présence de logiciels malveillants dormants."
    else:
        general_summary += "La plupart des événements analysés correspondent à des activités système inhabituelles mais qui ne présentent pas de menace critique imminente."
    
    story.append(Paragraph(general_summary, normal_style))
    
    # 2. DÉTAILS DE L'INCIDENT
    story.append(Paragraph("2. Détails de l'Investigation", h1_style))
    story.append(Paragraph("<b>2.1 Méthodologie et Outils d'Analyse</b>", h2_style))
    tools_str = ", ".join([str(t).capitalize() for t in tools_used]) if tools_used else "Inconnu"
    story.append(Paragraph(f"Les logs et artefacts ont été soumis aux moteurs d'analyse suivants : <b>{tools_str}</b>.", normal_style))
    story.append(Paragraph("Ces outils ont permis d'extraire des comportements d'attaque (TTPs), de corréler des événements système et d'identifier les signatures de menaces connues.", normal_style))

    story.append(Paragraph("<b>2.2 Indicateurs de Compromission (IOCs) Extraits</b>", h2_style))
    if not structured_iocs:
        story.append(Paragraph("Aucun indicateur de compromission direct n'a été extrait.", normal_style))
    else:
        # Importer la classification IA
        from ai_explainer import classify_ioc_with_ai

        # Classifier tous les hash IOCs via IA
        hash_iocs = [ioc for ioc in structured_iocs if ioc["type"] == "Hash"]
        other_iocs = [ioc for ioc in structured_iocs if ioc["type"] != "Hash"]

        classified_hashes = []
        counts = {"true_positive": 0, "likely_false_positive": 0, "potential_false_negative": 0, "suspicious_review": 0, "clean": 0}
        STATUS_LABELS = {
            "true_positive": "VRAI POSITIF",
            "likely_false_positive": "FAUX POSITIF",
            "potential_false_negative": "FAUX NÉGATIF",
            "suspicious_review": "SUSPECT",
            "clean": "SAIN",
        }
        STATUS_COLORS = {
            "true_positive": colors.HexColor("#dc2626"),
            "likely_false_positive": colors.HexColor("#22c55e"),
            "potential_false_negative": colors.HexColor("#f97316"),
            "suspicious_review": colors.HexColor("#eab308"),
            "clean": colors.HexColor("#22c55e"),
        }

        for ioc in hash_iocs[:15]:  # Max 15 pour ne pas dépasser le timeout
            classification = classify_ioc_with_ai(
                hash_value=ioc["value"],
                file_path=ioc.get("file_path", ""),
                vt_malicious=ioc.get("vt_malicious", 0),
                vt_total=ioc.get("vt_total", 0),
                vt_verdict=ioc.get("vt_verdict", "unknown"),
                tool=ioc.get("source", "")
            )
            ioc["classification"] = classification
            classified_hashes.append(ioc)
            status = classification.get("status", "suspicious_review")
            if status in counts:
                counts[status] += 1

        # ── RÉSUMÉ GLOBAL DES HASHS ──────────────────────────────────────────
        story.append(Paragraph("<b>Résumé Global de la Classification des Hashs</b>", h2_style))

        summary_data = [
            [
                Paragraph("<b>Infectés (VP)</b>", ParagraphStyle("SH", parent=normal_style, fontSize=9, fontName="Helvetica-Bold", textColor=colors.HexColor("#dc2626"))),
                Paragraph("<b>Suspects</b>", ParagraphStyle("SH", parent=normal_style, fontSize=9, fontName="Helvetica-Bold", textColor=colors.HexColor("#eab308"))),
                Paragraph("<b>Faux Positifs</b>", ParagraphStyle("SH", parent=normal_style, fontSize=9, fontName="Helvetica-Bold", textColor=colors.HexColor("#22c55e"))),
                Paragraph("<b>Faux Négatifs</b>", ParagraphStyle("SH", parent=normal_style, fontSize=9, fontName="Helvetica-Bold", textColor=colors.HexColor("#f97316"))),
                Paragraph("<b>Sains</b>", ParagraphStyle("SH", parent=normal_style, fontSize=9, fontName="Helvetica-Bold", textColor=colors.HexColor("#22c55e"))),
            ],
            [
                Paragraph(str(counts["true_positive"]), ParagraphStyle("SV", parent=normal_style, fontSize=18, fontName="Helvetica-Bold", textColor=colors.HexColor("#dc2626"), alignment=TA_CENTER)),
                Paragraph(str(counts["suspicious_review"]), ParagraphStyle("SV", parent=normal_style, fontSize=18, fontName="Helvetica-Bold", textColor=colors.HexColor("#eab308"), alignment=TA_CENTER)),
                Paragraph(str(counts["likely_false_positive"]), ParagraphStyle("SV", parent=normal_style, fontSize=18, fontName="Helvetica-Bold", textColor=colors.HexColor("#22c55e"), alignment=TA_CENTER)),
                Paragraph(str(counts["potential_false_negative"]), ParagraphStyle("SV", parent=normal_style, fontSize=18, fontName="Helvetica-Bold", textColor=colors.HexColor("#f97316"), alignment=TA_CENTER)),
                Paragraph(str(counts["clean"]), ParagraphStyle("SV", parent=normal_style, fontSize=18, fontName="Helvetica-Bold", textColor=colors.HexColor("#22c55e"), alignment=TA_CENTER)),
            ]
        ]
        t_summary = Table(summary_data, colWidths=[3.6*cm]*5)
        t_summary.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f8fafc")),
            ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#ffffff")),
            ("LINEBELOW", (0, 0), (-1, 0), 1, colors.HexColor("#e2e8f0")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ]))
        story.append(t_summary)
        story.append(Spacer(1, 0.4*cm))

        # Actions globales recommandées
        if counts["true_positive"] > 0:
            story.append(Paragraph(f"⚠ <b>ACTION REQUISE :</b> {counts['true_positive']} hash(es) confirmé(s) malveillant(s). Isoler immédiatement les machines concernées et supprimer les fichiers infectés.", ParagraphStyle("Action", parent=normal_style, fontSize=9, textColor=colors.HexColor("#dc2626"), backColor=colors.HexColor("#fef2f2"))))
        if counts["suspicious_review"] > 0:
            story.append(Paragraph(f"🔍 <b>INVESTIGATION :</b> {counts['suspicious_review']} élément(s) suspects nécessitent une analyse manuelle approfondie.", ParagraphStyle("Action", parent=normal_style, fontSize=9, textColor=colors.HexColor("#92400e"), backColor=colors.HexColor("#fffbeb"))))
        if counts["potential_false_negative"] > 0:
            story.append(Paragraph(f"⚡ <b>ATTENTION :</b> {counts['potential_false_negative']} potentiel(s) faux négatif(s) identifié(s) — fichiers non détectés par les AV mais présentant des caractéristiques suspectes.", ParagraphStyle("Action", parent=normal_style, fontSize=9, textColor=colors.HexColor("#9a3412"), backColor=colors.HexColor("#fff7ed"))))

        story.append(Spacer(1, 0.5*cm))

        # ── TABLEAU DÉTAILLÉ DES HASHS CLASSIFIÉS ───────────────────────────
        if classified_hashes:
            story.append(Paragraph("<b>Détail des Hashs Analysés par l'IA</b>", h2_style))
            hash_table_data = [[
                Paragraph("<b>Hash</b>", ParagraphStyle("TH", parent=normal_style, fontSize=7, fontName="Helvetica-Bold")),
                Paragraph("<b>Chemin</b>", ParagraphStyle("TH", parent=normal_style, fontSize=7, fontName="Helvetica-Bold")),
                Paragraph("<b>Score VT</b>", ParagraphStyle("TH", parent=normal_style, fontSize=7, fontName="Helvetica-Bold")),
                Paragraph("<b>Statut IA</b>", ParagraphStyle("TH", parent=normal_style, fontSize=7, fontName="Helvetica-Bold")),
                Paragraph("<b>Explication & Recommandation</b>", ParagraphStyle("TH", parent=normal_style, fontSize=7, fontName="Helvetica-Bold")),
            ]]

            for ioc in classified_hashes:
                cl = ioc.get("classification", {})
                status = cl.get("status", "suspicious_review")
                sc = STATUS_COLORS.get(status, colors.HexColor("#eab308"))
                sl = STATUS_LABELS.get(status, "SUSPECT")

                # Hash tronqué
                hval = ioc["value"]
                hash_display = hval[:16] + "…" + hval[-8:] if len(hval) > 28 else hval

                # Chemin tronqué
                fpath = ioc.get("file_path") or ioc.get("value") or "—"
                if len(fpath) > 35:
                    fpath = "…" + fpath[-33:]

                vt_score = f"{ioc.get('vt_malicious', 0)}/{ioc.get('vt_total', 0)}" if ioc.get('vt_total', 0) > 0 else "N/A"
                explanation = cl.get("explanation", "—")
                recommendation = cl.get("recommendation", "—")

                td_style = ParagraphStyle("TD", parent=normal_style, fontSize=7)
                hash_table_data.append([
                    Paragraph(hash_display, ParagraphStyle("TDMono", parent=normal_style, fontSize=6, fontName="Courier")),
                    Paragraph(fpath, ParagraphStyle("TDMono", parent=normal_style, fontSize=6, fontName="Courier")),
                    Paragraph(vt_score, td_style),
                    Paragraph(f"<font color='{sc.hexval()}'><b>{sl}</b></font>", td_style),
                    Paragraph(f"{explanation}<br/><i>💡 {recommendation}</i>", ParagraphStyle("TDExp", parent=normal_style, fontSize=7, leading=10)),
                ])

            t_hash = Table(hash_table_data, colWidths=[2.8*cm, 2.8*cm, 1.5*cm, 2.3*cm, 8.6*cm])
            t_hash.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LINEBELOW", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(t_hash)

        # ── AUTRES IOCs (IP, Fichiers) ───────────────────────────────────────
        if other_iocs:
            story.append(Spacer(1, 0.4*cm))
            story.append(Paragraph("<b>Autres IOCs (IP, Fichiers)</b>", h2_style))
            ioc_table_data = [[
                Paragraph("<b>Type</b>", ParagraphStyle("TH", parent=normal_style, fontSize=8, fontName="Helvetica-Bold")),
                Paragraph("<b>Valeur</b>", ParagraphStyle("TH", parent=normal_style, fontSize=8, fontName="Helvetica-Bold")),
                Paragraph("<b>Source</b>", ParagraphStyle("TH", parent=normal_style, fontSize=8, fontName="Helvetica-Bold")),
                Paragraph("<b>Occurrences</b>", ParagraphStyle("TH", parent=normal_style, fontSize=8, fontName="Helvetica-Bold")),
                Paragraph("<b>1ère détection</b>", ParagraphStyle("TH", parent=normal_style, fontSize=8, fontName="Helvetica-Bold")),
            ]]
            for ioc in other_iocs[:20]:
                val = ioc["value"]
                if len(val) > 40:
                    val = val[:20] + "..." + val[-20:]
                ioc_table_data.append([
                    Paragraph(f"<b>{ioc['type'].upper()}</b>", ParagraphStyle("TD", parent=normal_style, fontSize=8, textColor=colors.HexColor("#64748b"))),
                    Paragraph(val, ParagraphStyle("TD", parent=normal_style, fontSize=8, fontName="Courier")),
                    Paragraph(ioc["source"], ParagraphStyle("TD", parent=normal_style, fontSize=8)),
                    Paragraph(str(ioc["hits"]), ParagraphStyle("TD", parent=normal_style, fontSize=8, alignment=TA_CENTER)),
                    Paragraph(ioc["firstSeen"], ParagraphStyle("TD", parent=normal_style, fontSize=8)),
                ])
            t_iocs = Table(ioc_table_data, colWidths=[2.5*cm, 7*cm, 2.5*cm, 2.5*cm, 3.5*cm])
            t_iocs.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LINEBELOW", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(t_iocs)

    story.append(PageBreak())

    story.append(Paragraph("<b>2.3 Chronologie et Détail des Événements Suspects</b>", h2_style))
    story.append(Paragraph("La section suivante détaille, en langage naturel, la nature des attaques et des événements critiques découverts au sein du système. Ces explications vulgarisent la donnée technique extraite.", normal_style))
    
    priority_alerts = [a for a in alerts if a.get("severity") in ("critical", "high")]
    priority_alerts.sort(key=lambda a: str(a.get("timestamp", "0")), reverse=False) # Tri chronologique
    
    if not priority_alerts:
        story.append(Paragraph("Aucune alerte critique ou élevée ne nécessite d'explication détaillée dans cette section.", normal_style))
    else:
        table_data = [
            [
                Paragraph("<b>Sévérité</b>", ParagraphStyle("TH", parent=normal_style, fontSize=8, fontName="Helvetica-Bold")),
                Paragraph("<b>Source</b>", ParagraphStyle("TH", parent=normal_style, fontSize=8, fontName="Helvetica-Bold")),
                Paragraph("<b>Règle & Cible</b>", ParagraphStyle("TH", parent=normal_style, fontSize=8, fontName="Helvetica-Bold")),
                Paragraph("<b>Explication (IA)</b>", ParagraphStyle("TH", parent=normal_style, fontSize=8, fontName="Helvetica-Bold")),
                Paragraph("<b>Horodatage</b>", ParagraphStyle("TH", parent=normal_style, fontSize=8, fontName="Helvetica-Bold"))
            ]
        ]
        
        for a in priority_alerts[:20]:
            sev = a.get("severity", "info")
            color = SEVERITY_COLORS.get(sev, colors.grey)
            rule = a.get("title") or a.get("rule") or "Événement"
            target = a.get("target") or a.get("dst_ip") or "—"
            tool = (a.get("tool") or "Système").upper()
            timestamp = str(a.get("timestamp") or "Non horodaté")[:19]
            
            explanation = generate_human_explanation(rule, target, tool)
            
            p_sev = Paragraph(f"<font color='{color.hexval()}'><b>{sev.upper()}</b></font>", ParagraphStyle("TD", parent=normal_style, fontSize=8))
            p_source = Paragraph(tool, ParagraphStyle("TD", parent=normal_style, fontSize=8))
            p_rule_target = Paragraph(f"<b>{rule}</b><br/><i>Cible: {target}</i>", ParagraphStyle("TD", parent=normal_style, fontSize=8))
            p_expl = Paragraph(f"<font color='#3b82f6'>{explanation}</font>", ParagraphStyle("TD", parent=normal_style, fontSize=8))
            p_time = Paragraph(timestamp, ParagraphStyle("TD", parent=normal_style, fontSize=8))
            
            table_data.append([p_sev, p_source, p_rule_target, p_expl, p_time])

        t_alerts = Table(table_data, colWidths=[2*cm, 2*cm, 5*cm, 6*cm, 3*cm])
        t_alerts.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LINEBELOW", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(t_alerts)

    # 3. RECOMMANDATIONS
    story.append(Paragraph("3. Recommandations de Remédiation", h1_style))
    
    if crit_count > 0:
        story.append(Paragraph("<font color='#dc2626'><b>ACTIONS IMMÉDIATES (URGENT)</b></font>", normal_style))
        story.append(Paragraph("• Isoler immédiatement la machine ou l'infrastructure affectée du réseau principal pour éviter tout mouvement latéral.", normal_style))
        story.append(Paragraph("• Geler l'état de la machine (création d'un snapshot) pour préserver les preuves en mémoire RAM.", normal_style))
        story.append(Paragraph("• Bloquer au niveau du pare-feu et de l'EDR l'ensemble des hachages et adresses IP listés dans la section IOCs.", normal_style))
        story.append(Spacer(1, 0.3*cm))
    
    if high_count > 0 or crit_count > 0:
        story.append(Paragraph("<font color='#f97316'><b>ACTIONS À COURT TERME (< 48H)</b></font>", normal_style))
        story.append(Paragraph("• Analyser l'étendue de l'incident (Patient Zéro) en cherchant les IOCs découverts sur le reste du parc informatique.", normal_style))
        story.append(Paragraph("• Réinitialiser tous les mots de passe et jetons de session potentiellement compromis des utilisateurs impliqués.", normal_style))
        story.append(Spacer(1, 0.3*cm))
        
    story.append(Paragraph("<font color='#eab308'><b>ACTIONS PRÉVENTIVES ET À MOYEN TERME</b></font>", normal_style))
    story.append(Paragraph("• Mener un audit complet des règles de privilèges (Active Directory ou IAM).", normal_style))
    story.append(Paragraph("• Déployer des règles de détection spécifiques (YARA/Sigma) sur votre SIEM basées sur les TTPs identifiés lors de cette attaque.", normal_style))
    story.append(Paragraph("• Renforcer la surface d'attaque en appliquant les derniers correctifs de sécurité (Patch Management) sur les vulnérabilités exploitées.", normal_style))
    story.append(PageBreak())

    # 4. CONCLUSION
    story.append(Paragraph("4. Conclusion", h1_style))
    if crit_count > 0:
        conclusion = (
            "L'analyse de l'évidence numérique montre très clairement qu'<b>un incident de sécurité majeur</b> s'est produit. "
            "Les traces récupérées confirment l'utilisation d'outils malveillants ou de techniques caractéristiques d'une intrusion "
            "active. Il est impératif d'exécuter le plan de réponse à incident (CSIRT) immédiatement pour endiguer la menace, éradiquer "
            "les portes dérobées (backdoors) et nettoyer le système avant d'envisager un retour en production."
        )
    elif high_count > 0:
        conclusion = (
            "L'investigation démontre un environnement exposant des vulnérabilités sérieuses et présentant des traces d'activité très suspectes. "
            "Bien que le système ne soit pas encore classé comme totalement corrompu, une vérification approfondie par l'équipe de sécurité est "
            "absolument nécessaire pour s'assurer de l'absence de compromission persistante."
        )
    else:
        conclusion = (
            "À l'issue de l'analyse, aucune menace critique n'a été directement identifiée dans l'échantillon fourni. "
            "L'environnement semble sain, bien que certaines anomalies mineures méritent d'être surveillées via des règles de routine."
        )
    
    story.append(Paragraph(conclusion, normal_style))
    story.append(Spacer(1, 1*cm))
    story.append(Paragraph("<i>Rapport généré automatiquement par la plateforme d'investigation ForensiQ.</i>", ParagraphStyle("Footer", parent=normal_style, fontSize=9, textColor=colors.HexColor("#94a3b8"), alignment=TA_CENTER)))

    doc.build(story)
    return output_path