"""
report_generator.py
─────────────────────────────────────────────────────────────────────────────
Génère un rapport PDF professionnel et STANDARDISÉ pour chaque fichier
analysé (Kuiper, Hayabusa, Loki, Autopsy, Zircolite, ML-Network, ...).

Garanties apportées par ce refactoring :
  1. Même titre, même ordre, même méthodologie pour CHAQUE incident,
     quel que soit l'outil source ou le contenu du fichier
     (voir SECTION_TITLES ci-dessous : source unique de vérité).
  2. Aucune section n'est jamais laissée vide : si une catégorie de données
     est absente, un message explicite est affiché (NO_DATA_* constants).
  3. Chaque alerte reçoit une explication IA RÉELLE (via ai_explainer, qui
     appelle l'API NVIDIA) ET son explication technique déterministe.
     Si l'IA est indisponible, un message de repli clair est affiché et le
     rapport continue de se générer normalement (jamais d'échec).
  4. La même logique d'appel IA que la page des alertes est réutilisée
     (module ai_explainer.py), donc les explications sont cohérentes
     partout dans l'application.
  5. Un "Résumé Global de la Classification" ET un verdict global sont
     produits par incident ET pour le dossier complet (fin de rapport).
"""

import os
import re
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Table, TableStyle, Paragraph,
    Spacer, PageBreak, KeepTogether, HRFlowable,
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER

from ai_explainer import (
    explain_alert,
    explain_incident_summary,
    explain_global_verdict,
    classify_ioc_with_ai,
)

# ── Palette noir et blanc professionnel ────────────────────────────────────
BLACK      = colors.black
DARK_GRAY  = colors.HexColor("#1f2937")
MID_GRAY   = colors.HexColor("#6b7280")
LIGHT_GRAY = colors.HexColor("#e5e7eb")
WHITE      = colors.white
ACCENT     = colors.HexColor("#111827")

SUSPICIOUS_PATHS = ["temp", "tmp", "appdata", "roaming", "downloads",
                     "public", "startup", "run", "winlogon", "users\\public"]
SYSTEM_PATHS     = ["system32", "windows\\system", "program files", "microsoft"]

STATUS_KEYS   = ["Critical", "Malicious", "Suspicious", "Benign", "Informational", "Unknown"]
STATUS_LABELS = {
    "Critical":      "Critique (Critical)",
    "Malicious":     "Malveillant (Malicious)",
    "Suspicious":    "Suspect (Suspicious)",
    "Benign":        "Légitime (Benign)",
    "Informational": "Informatif (Informational)",
    "Unknown":       "Inconnu (Unknown)",
}
STATUS_SHORT = {
    "Critical": "CRIT", "Malicious": "MAL", "Suspicious": "SUSP",
    "Benign": "BEN", "Informational": "INFO", "Unknown": "UNK",
}

# Verdicts globaux possibles, dans l'ordre croissant de gravité
VERDICTS = ["Insufficient Data", "Clean", "Mostly Clean", "Suspicious",
            "Potentially Compromised", "Compromised", "Critical Incident"]

# ── SOURCE UNIQUE DE VÉRITÉ : ordre et titres des 13 sections par incident ──
# Toute modification de structure du rapport se fait ICI, nulle part ailleurs.
SECTION_TITLES = {
    1:  "Informations Générales du Fichier",
    2:  "Méthodologie d'Analyse",
    3:  "Résumé Exécutif",
    4:  "Statistiques Générales",
    5:  "Verdict Global & Classification",
    6:  "Analyse Détaillée des Alertes",
    7:  "Analyse des Événements Suspects",
    8:  "Corrélations entre Événements",
    9:  "Extraction des IoC (Indicateurs de Compromission)",
    10: "Analyse des Utilisateurs, Machines, Processus et Commandes",
    11: "Analyse Temporelle et Timeline",
    12: "Recommandations Finales",
    13: "Limitations de l'Analyse",
}

# Messages standard affichés à la place d'une section vide (jamais de trou)
NO_DATA_ALERTS       = "Aucune donnée disponible dans le fichier analysé : aucune alerte n'a été générée."
NO_DATA_SUSPICIOUS   = "Aucun événement suspect ou malveillant identifié dans le fichier analysé."
NO_DATA_CORRELATIONS = "Aucune corrélation significative identifiée avec d'autres fichiers ou sources."
NO_DATA_IOC          = "Aucun Indicateur de Compromission (IoC) trouvé dans ce fichier."
NO_DATA_USERS        = "Aucune donnée disponible dans le fichier analysé concernant les utilisateurs, machines ou processus."
NO_DATA_TIMELINE     = "Aucune donnée temporelle exploitable (aucun horodatage critique ou élevé) dans ce fichier."
NO_DATA_MITRE        = "Aucune correspondance MITRE ATT&CK identifiée dans ce fichier."


# ── Utilitaires ───────────────────────────────────────────────────────────────

def _path_flags(file_path: str) -> tuple[bool, bool]:
    p = (file_path or "").lower()
    return (
        any(s in p for s in SUSPICIOUS_PATHS),
        any(s in p for s in SYSTEM_PATHS),
    )


def _path_context_label(file_path: str) -> str:
    is_susp, is_sys = _path_flags(file_path)
    if is_susp:
        return "Chemin suspect / temporaire"
    if is_sys:
        return "Chemin système / logiciel légitime"
    if file_path:
        return "Chemin standard"
    return "Chemin non renseigné"


def get_threat_level(alerts: list[dict]) -> str:
    for sev in ("critical", "high", "medium"):
        if any(a.get("severity") == sev for a in alerts):
            return {"critical": "CRITIQUE", "high": "ÉLEVÉ", "medium": "MODÉRÉ"}[sev]
    return "FAIBLE"


def _extract_hashes(a: dict) -> list[str]:
    found = []
    ti = a.get("threat_intel")
    if isinstance(ti, list):
        for t in ti:
            if t.get("type") == "hash" and t.get("value"):
                found.append(t["value"].lower())
    text = f"{a.get('details', '')} {a.get('target', '')}"
    found.extend(re.findall(r"\b[a-fA-F0-9]{32,64}\b", text))
    return list(dict.fromkeys(found))


def _extract_mitre(a: dict) -> list[str]:
    """MITRE ATT&CK techniques associées à une alerte, si présentes."""
    tags = []
    ti = a.get("threat_intel")
    if isinstance(ti, list):
        tags.extend(t.get("value") for t in ti if t.get("type") == "mitre" and t.get("value"))
    if a.get("mitre"):
        raw = a["mitre"]
        tags.extend(raw if isinstance(raw, list) else [raw])
    # Reconnaissance de motifs Txxxx dans les détails bruts, en dernier recours
    text = f"{a.get('details', '')} {a.get('title', '')}"
    tags.extend(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", text))
    return list(dict.fromkeys(tags))


def _vt_from_alert(a: dict) -> dict | None:
    ti = a.get("threat_intel")
    if not isinstance(ti, list):
        return None
    for t in ti:
        if t.get("type") == "hash" and t.get("found"):
            mal = t.get("malicious", 0)
            sus = t.get("suspicious", 0)
            har = t.get("harmless", 0)
            return {"hash": t.get("value"), "malicious": mal,
                    "total": mal + sus + har, "verdict": t.get("verdict", "unknown")}
    return None


def _classify_ioc(ioc: dict) -> dict:
    """Classifie un IOC via classify_ioc_with_ai (ai_explainer.py), qui s'appuie
    sur hash_verdict.classify_hash() + une reformulation IA de l'explication.
    Les statuts renvoyés (Verdict enum) sont mappés vers les 6 catégories du
    rapport (Benign/Suspicious/Malicious/Critical/Informational/Unknown)."""
    hash_val  = ioc.get("linked_hash") or (ioc["value"] if ioc["type"] == "Hash" else "")
    file_path = ioc.get("file_path") or (ioc["value"] if ioc["type"] == "File" else "")
    res = classify_ioc_with_ai(
        hash_value=hash_val,
        file_path=file_path,
        vt_malicious=ioc.get("vt_malicious", 0),
        vt_total=ioc.get("vt_total", 0),
        vt_verdict=ioc.get("vt_verdict", "unknown"),
        tool=ioc.get("source", ""),
    )
    st = res.get("status", "unknown")
    if st == "true_positive": res["status"] = "Malicious"
    elif st == "suspicious_review": res["status"] = "Suspicious"
    elif st in ("likely_false_positive", "clean"): res["status"] = "Benign"
    elif st == "potential_false_negative": res["status"] = "Unknown"
    else: res["status"] = "Unknown"
    return res


def _classify_event(a: dict, ioc_status: str = None) -> str:
    sev = str(a.get("severity") or "info").lower()
    if sev == "critical": return "Critical"
    if ioc_status == "Malicious" or (sev == "high" and any(k in str(a.get("title", "")).lower() for k in ["malware", "virus", "trojan", "exploit"])): return "Malicious"
    if ioc_status == "Suspicious" or sev in ("high", "medium"): return "Suspicious"
    if sev == "info": return "Informational"
    if ioc_status == "Benign" or sev == "low": return "Benign"
    return "Unknown"


def _pct(n: int, tot: int) -> str:
    return f"{n} ({n/tot*100:.0f}%)" if tot > 0 else f"{n} (—)"


def _compute_verdict(crit: int, malicious: int, high: int, suspicious: int, total_alerts: int) -> str:
    """Calcul déterministe du verdict global, harmonisé par incident et pour le dossier complet."""
    if total_alerts == 0:
        return "Insufficient Data"
    if crit > 0:
        return "Critical Incident"
    if malicious > 0:
        return "Compromised"
    if high > 0 and suspicious > 2:
        return "Potentially Compromised"
    if high > 0 or suspicious > 0:
        return "Suspicious"
    if total_alerts > 0:
        return "Mostly Clean"
    return "Clean"


def _classify_iocs(file_iocs: list[dict]) -> tuple[dict, dict, dict, list]:
    counts_all  = {k: 0 for k in STATUS_KEYS}
    counts_hash = {k: 0 for k in STATUS_KEYS}
    counts_file = {k: 0 for k in STATUS_KEYS}
    classified  = []
    for ioc in file_iocs:
        cl = _classify_ioc(ioc)
        ioc["classification"] = cl
        status = cl.get("status", "Unknown")
        if status not in counts_all:
            status = "Unknown"
        counts_all[status] += 1
        if ioc["type"] == "Hash":
            counts_hash[status] += 1
        elif ioc["type"] == "File":
            counts_file[status] += 1
        classified.append(ioc)
    return counts_all, counts_hash, counts_file, classified


# ── Extracteur IOC ─────────────────────────────────────────────────────────────

def extract_structured_iocs(alerts: list[dict], enrich_vt: bool = True) -> list[dict]:
    from threat_intel import enrich_hash
    ioc_map = {}

    for a in alerts:
        timestamp  = str(a.get("timestamp") or "—")[:19]
        tool       = (a.get("tool") or "Système").upper()
        alert_hash = _extract_hashes(a)
        vt_info    = _vt_from_alert(a)
        primary_h  = (vt_info or {}).get("hash") or (alert_hash[0] if alert_hash else None)

        for ip_key in ("dst_ip", "src_ip"):
            ip = a.get(ip_key)
            if ip and ip not in ("127.0.0.1", "0.0.0.0") and len(ip) > 5:
                k = f"IP-{ip}"
                if k not in ioc_map:
                    ioc_map[k] = {"type": "IP", "value": ip, "source": tool, "hits": 0, "firstSeen": timestamp}
                ioc_map[k]["hits"] += 1
                if timestamp < ioc_map[k]["firstSeen"]:
                    ioc_map[k]["firstSeen"] = timestamp

        file_path = a.get("file_path") or a.get("target")
        if file_path and ("\\" in file_path or "/" in file_path):
            k = f"FILE-{file_path}"
            if k not in ioc_map:
                entry = {"type": "File", "value": file_path, "file_path": file_path,
                         "linked_hash": primary_h, "source": tool, "hits": 0,
                         "firstSeen": timestamp, "vt_malicious": 0, "vt_total": 0, "vt_verdict": "unknown"}
                if vt_info:
                    entry.update({"linked_hash": vt_info["hash"], "vt_malicious": vt_info["malicious"],
                                  "vt_total": vt_info["total"], "vt_verdict": vt_info["verdict"]})
                elif primary_h and enrich_vt:
                    r = enrich_hash(primary_h)
                    if r and r.get("found"):
                        mal, sus, har = r.get("malicious", 0), r.get("suspicious", 0), r.get("harmless", 0)
                        entry.update({"linked_hash": primary_h, "vt_malicious": mal,
                                      "vt_total": mal + sus + har, "vt_verdict": r.get("verdict", "unknown")})
                ioc_map[k] = entry
            ioc_map[k]["hits"] += 1
            if timestamp < ioc_map[k]["firstSeen"]:
                ioc_map[k]["firstSeen"] = timestamp

        ti = a.get("threat_intel")
        if isinstance(ti, list):
            for t in ti:
                if t.get("type") == "hash":
                    h = t.get("value", "").lower()
                    if not h:
                        continue
                    k = f"HASH-{h}"
                    if k not in ioc_map:
                        mal = t.get("malicious", 0)
                        sus = t.get("suspicious", 0)
                        har = t.get("harmless", 0)
                        tot = mal + sus + har
                        entry = {"type": "Hash", "value": h,
                                 "file_path": file_path if file_path and ("\\" in file_path or "/" in file_path) else "",
                                 "source": tool, "hits": 0, "firstSeen": timestamp,
                                 "vt_malicious": mal, "vt_total": tot, "vt_verdict": t.get("verdict", "unknown")}
                        if not t.get("found") and enrich_vt:
                            r = enrich_hash(h)
                            if r and r.get("found"):
                                mal2, sus2, har2 = r.get("malicious", 0), r.get("suspicious", 0), r.get("harmless", 0)
                                entry.update({"vt_malicious": mal2, "vt_total": mal2 + sus2 + har2,
                                              "vt_verdict": r.get("verdict", "unknown")})
                        ioc_map[k] = entry
                    ioc_map[k]["hits"] += 1
                    if timestamp < ioc_map[k]["firstSeen"]:
                        ioc_map[k]["firstSeen"] = timestamp

    return sorted(list(ioc_map.values()), key=lambda x: x["hits"], reverse=True)


# ── Styles ReportLab ───────────────────────────────────────────────────────────

def _build_styles() -> dict:
    base = getSampleStyleSheet()
    return {
        "brand":    ParagraphStyle("Brand",    parent=base["Title"],   fontSize=30, textColor=BLACK,
                                   fontName="Helvetica-Bold", alignment=TA_CENTER),
        "title":    ParagraphStyle("Title",    parent=base["Title"],   fontSize=18, textColor=BLACK,
                                   alignment=TA_CENTER, spaceAfter=0.2*cm),
        "subtitle": ParagraphStyle("Subtitle", parent=base["Normal"],  fontSize=11, textColor=MID_GRAY,
                                   alignment=TA_CENTER, spaceAfter=1.5*cm),
        "h1":       ParagraphStyle("H1",       parent=base["Heading1"], fontSize=14, textColor=ACCENT,
                                   spaceBefore=0.8*cm, spaceAfter=0.3*cm, fontName="Helvetica-Bold"),
        "h2":       ParagraphStyle("H2",       parent=base["Heading2"], fontSize=11, textColor=DARK_GRAY,
                                   spaceBefore=0.4*cm, spaceAfter=0.2*cm, fontName="Helvetica-Bold"),
        "h3":       ParagraphStyle("H3",       parent=base["Heading3"], fontSize=9,  textColor=MID_GRAY,
                                   spaceBefore=0.2*cm, spaceAfter=0.1*cm, fontName="Helvetica-Bold"),
        "normal":   ParagraphStyle("Normal",   parent=base["Normal"],  fontSize=9,  textColor=BLACK,
                                   leading=13, spaceAfter=0.2*cm),
        "empty":    ParagraphStyle("Empty",    parent=base["Normal"],  fontSize=9,  textColor=MID_GRAY,
                                   leading=13, spaceAfter=0.2*cm, fontName="Helvetica-Oblique"),
        "td":       ParagraphStyle("TD",       parent=base["Normal"],  fontSize=8,  textColor=BLACK, leading=11),
        "td_mono":  ParagraphStyle("TDMono",   parent=base["Normal"],  fontSize=7,  fontName="Courier",
                                   textColor=BLACK, leading=10),
        "footer":   ParagraphStyle("Footer",   parent=base["Normal"],  fontSize=8,  textColor=MID_GRAY,
                                   alignment=TA_CENTER),
    }


def _table_style_header(row_color=True) -> TableStyle:
    cmds = [
        ("BACKGROUND",   (0, 0), (-1,  0), DARK_GRAY),
        ("TEXTCOLOR",    (0, 0), (-1,  0), WHITE),
        ("FONTNAME",     (0, 0), (-1,  0), "Helvetica-Bold"),
        ("FONTSIZE",     (0, 0), (-1, -1), 8),
        ("VALIGN",       (0, 0), (-1, -1), "TOP"),
        ("GRID",         (0, 0), (-1, -1), 0.4, LIGHT_GRAY),
        ("LINEBELOW",    (0, 0), (-1,  0), 1.0, BLACK),
        ("TOPPADDING",   (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 5),
        ("LEFTPADDING",  (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]
    if row_color:
        cmds.append(("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, colors.HexColor("#f9fafb")]))
    return TableStyle(cmds)


def _classification_summary_table(counts_all, counts_hash, counts_file, s) -> Table:
    total_all  = sum(counts_all.values())
    total_hash = sum(counts_hash.values())
    total_file = sum(counts_file.values())
    sum_header = [Paragraph("", s["td"])] + [Paragraph(f"<b>{STATUS_SHORT[k]}</b>", s["td"]) for k in STATUS_KEYS]
    sum_rows = [
        sum_header,
        [Paragraph(f"<b>Total ({total_all})</b>",   s["td"])] + [Paragraph(_pct(counts_all[k],  total_all),  s["td"]) for k in STATUS_KEYS],
        [Paragraph(f"Hash seuls ({total_hash})",     s["td"])] + [Paragraph(_pct(counts_hash[k], total_hash), s["td"]) for k in STATUS_KEYS],
        [Paragraph(f"Fichiers seuls ({total_file})", s["td"])] + [Paragraph(_pct(counts_file[k], total_file), s["td"]) for k in STATUS_KEYS],
    ]
    t = Table(sum_rows, colWidths=[3.8*cm] + [2.6*cm]*5)
    t.setStyle(TableStyle([
        ("GRID",         (0, 0), (-1, -1), 0.4, LIGHT_GRAY),
        ("BACKGROUND",   (0, 0), (-1,  0), DARK_GRAY),
        ("TEXTCOLOR",    (0, 0), (-1,  0), WHITE),
        ("FONTNAME",     (0, 0), (-1,  0), "Helvetica-Bold"),
        ("FONTNAME",     (0, 1), (0, -1),  "Helvetica-Bold"),
        ("FONTSIZE",     (0, 0), (-1, -1), 8),
        ("ALIGN",        (1, 0), (-1, -1), "CENTER"),
        ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",   (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 7),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [WHITE, colors.HexColor("#f3f4f6")]),
        ("LINEBELOW",    (0, 0), (-1,  0), 1, BLACK),
    ]))
    return t


# ── Sections par incident ───────────────────────────────────────────────────────

def _section_alerts(incident_alerts: list[dict], s: dict) -> list:
    """Chaque alerte : tableau technique + explication technique déterministe
    + explication IA réelle (via ai_explainer / API NVIDIA)."""
    story = []
    if not incident_alerts:
        story.append(Paragraph(NO_DATA_ALERTS, s["empty"]))
        return story

    story.append(Paragraph(
        f"{len(incident_alerts)} alerte(s) enregistrée(s) pour cet incident.", s["normal"]))

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_alerts = sorted(incident_alerts, key=lambda a: sev_order.get(a.get("severity", "info"), 9))

    expl_style = ParagraphStyle(
        "AIExpl", parent=s["normal"], fontSize=8, leading=11,
        textColor=DARK_GRAY, leftIndent=0.5*cm, rightIndent=0.5*cm,
        spaceBefore=0.1*cm, spaceAfter=0.05*cm,
        borderWidth=0.5, borderColor=LIGHT_GRAY, borderPadding=6,
        backColor=colors.HexColor("#f9fafb"),
    )
    tech_style = ParagraphStyle(
        "TechExpl", parent=s["normal"], fontSize=8, leading=11,
        textColor=MID_GRAY, leftIndent=0.5*cm, rightIndent=0.5*cm,
        spaceBefore=0.05*cm, spaceAfter=0.3*cm,
    )

    for idx, a in enumerate(sorted_alerts[:50]):
        rule    = str(a.get("title") or "—")[:80]
        target  = str(a.get("target") or a.get("dst_ip") or "—")[:50]
        ts      = str(a.get("timestamp") or "—")[:19]
        sev     = (a.get("severity") or "info").upper()
        tool    = str(a.get("tool") or "système")
        details = str(a.get("details") or a.get("description") or "")
        mitre_list = _extract_mitre(a)
        mitre_str  = ", ".join(mitre_list) if mitre_list else "—"
        vt_info = _vt_from_alert(a)
        vt_str  = f"{vt_info['malicious']}/{vt_info['total']} moteurs" if vt_info else ""

        # Explication technique déterministe (toujours présente, sans IA)
        tech_expl = _technical_explain(rule, target, tool, sev)

        # Explication IA réelle par alerte (appel direct API, repli géré en interne par ai_explainer).
        # explain_alert() n'a pas de paramètres mitre/vt dédiés : on les intègre à "details"
        # pour que l'IA garde ce contexte sans toucher à la signature existante.
        details_ctx = details
        if mitre_list:
            details_ctx += f"\nMITRE ATT&CK associé : {mitre_str}"
        if vt_info:
            details_ctx += f"\nScore VirusTotal : {vt_str}"

        ai_expl = a.get("explanation") or explain_alert(
            rule=rule, target=target, source=tool, details=details_ctx,
            severity=a.get("severity", "medium"),
        )

        alert_row = [[
            Paragraph(f"<b>{sev}</b>", s["td"]),
            Paragraph(f"<b>{rule}</b><br/><font color='gray'>MITRE: {mitre_str}</font>", s["td"]),
            Paragraph(target, s["td_mono"]),
            Paragraph(ts, s["td"]),
            Paragraph(tool.upper(), s["td"]),
        ]]
        if idx == 0:
            alert_row.insert(0, [
                Paragraph("<b>Sév.</b>", s["td"]), Paragraph("<b>Règle / Titre & MITRE</b>", s["td"]),
                Paragraph("<b>Cible</b>", s["td"]), Paragraph("<b>Horodatage</b>", s["td"]),
                Paragraph("<b>Outil</b>", s["td"]),
            ])
        t = Table(alert_row, colWidths=[1.5*cm, 5*cm, 3.5*cm, 3.5*cm, 2.5*cm])
        t.setStyle(_table_style_header() if idx == 0 else TableStyle([
            ("FONTSIZE", (0, 0), (-1, -1), 8), ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.4, LIGHT_GRAY),
            ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("BACKGROUND", (0, 0), (-1, -1), WHITE),
        ]))

        tech_para = Paragraph(f"<b>Explication technique :</b> {tech_expl}", tech_style)
        ai_para   = Paragraph(f"<b>Explication IA :</b> {ai_expl}", expl_style)

        story.append(KeepTogether([t, ai_para, tech_para]))
        story.append(Spacer(1, 0.1*cm))

    return story


def _technical_explain(rule: str, target: str, tool: str, severity: str) -> str:
    """Explication déterministe basée uniquement sur des règles, indépendante de l'IA."""
    r = rule.lower()
    t = target or "la cible"
    base = f"Détection « {rule} » remontée par {tool.upper()} avec une sévérité {severity}."
    if "logon" in r or "login" in r or "auth" in r:
        return base + f" Tentative d'authentification détectée sur {t}."
    if "process" in r or "cmd" in r or "shell" in r or "exec" in r:
        return base + f" Exécution d'un processus ou d'une commande sur {t}."
    if "malware" in r or "virus" in r or "trojan" in r or "yara" in r:
        return base + f" Signature correspondant à un profil de malware connu sur {t}."
    if "network" in r or "connection" in r or "port" in r:
        return base + f" Trafic réseau anormal impliquant {t}."
    if "privilege" in r or "credential" in r:
        return base + f" Élévation de privilèges ou manipulation d'identifiants ciblant {t}."
    if "registry" in r or "file" in r:
        return base + f" Modification du registre ou du système de fichiers sur {t}."
    return base + f" Comportement à examiner sur {t}."


def _section_iocs_classified(file_iocs: list[dict], s: dict) -> tuple[list, dict, dict, dict, list]:
    story = []
    counts_all, counts_hash, counts_file, classified = _classify_iocs(file_iocs)
    total_all = len(classified)

    story.append(Paragraph(
        f"<b>Résumé de la Classification des IoC — {total_all} élément(s) analysé(s)</b>", s["h2"]))
    if total_all == 0:
        story.append(Paragraph(NO_DATA_IOC, s["empty"]))
        return story, counts_all, counts_hash, counts_file, classified

    story.append(Paragraph(
        "Pourcentages calculés dynamiquement à partir des scores VirusTotal réels "
        "de chaque hash et chemin de fichier de cet incident.", s["normal"]))
    story.append(_classification_summary_table(counts_all, counts_hash, counts_file, s))
    story.append(Spacer(1, 0.3*cm))

    story.append(Paragraph("<b>Détail des éléments analysés (Hash et Fichiers)</b>", s["h2"]))
    det_header = [
        Paragraph("<b>Chemin / Fichier</b>", s["td"]), Paragraph("<b>Hash associé</b>", s["td"]),
        Paragraph("<b>Score VT</b>", s["td"]), Paragraph("<b>Classification IA</b>", s["td"]),
        Paragraph("<b>Confiance</b>", s["td"]), Paragraph("<b>Explication & Action</b>", s["td"]),
    ]
    det_rows = [det_header]
    for ioc in classified:
        path = ioc.get("file_path") or ioc["value"]
        if len(path) > 48:
            path = "…" + path[-45:]
        h_val = ioc.get("linked_hash") or (ioc["value"] if ioc["type"] == "Hash" else "—")
        h_disp = (h_val[:12] + "…" + h_val[-8:]) if h_val != "—" and len(h_val) > 24 else h_val
        vt_str = (f"{ioc.get('vt_malicious', 0)}/{ioc.get('vt_total', 0)}" if ioc.get("vt_total", 0) > 0 else "N/A")
        cl = ioc["classification"]
        status = cl.get("status", "Unknown")
        label = STATUS_LABELS.get(status, "Inconnu")
        conf = f"{cl.get('confidence', 0):.0f}%"
        expl = cl.get("explanation", "—")[:220]
        recom = cl.get("recommendation", "—")[:150]
        ctx = _path_context_label(path)
        det_rows.append([
            Paragraph(f"<b>{path}</b>", s["td_mono"]), Paragraph(h_disp, s["td_mono"]),
            Paragraph(vt_str, s["td"]), Paragraph(f"<b>{label}</b>", s["td"]), Paragraph(conf, s["td"]),
            Paragraph(f"{ctx}<br/>{expl}<br/><i>→ {recom}</i>", ParagraphStyle("Exp", parent=s["td"], leading=10)),
        ])
    col_w = [4.5*cm, 2.8*cm, 1.5*cm, 2.3*cm, 1.3*cm, 6.6*cm]
    t_det = Table(det_rows, colWidths=col_w, repeatRows=1)
    t_det.setStyle(_table_style_header())
    story.append(t_det)
    return story, counts_all, counts_hash, counts_file, classified


def _section_mitre_summary(incident_alerts: list[dict], s: dict) -> list:
    all_techniques = {}
    for a in incident_alerts:
        for tech in _extract_mitre(a):
            all_techniques.setdefault(tech, []).append(str(a.get("title", ""))[:40])
    if not all_techniques:
        return [Paragraph(NO_DATA_MITRE, s["empty"])]
    rows = [[Paragraph("<b>Technique</b>", s["td"]), Paragraph("<b>Occurrences liées</b>", s["td"])]]
    for tech, titles in sorted(all_techniques.items()):
        rows.append([Paragraph(tech, s["td_mono"]), Paragraph(f"{len(titles)} alerte(s) : " + ", ".join(titles[:3]), s["td"])])
    t = Table(rows, colWidths=[3*cm, 13*cm])
    t.setStyle(_table_style_header())
    return [Paragraph("<b>Correspondances MITRE ATT&CK identifiées</b>", s["h3"]), t]


def _section_users_machines(incident_alerts: list[dict], s: dict) -> list:
    users, machines, procs = set(), set(), set()
    for a in incident_alerts:
        det = str(a.get("details", ""))
        tgt = str(a.get("target", ""))
        users.update(re.findall(r"(?i)(?:user|utilisateur|account)[\s:=]+([a-zA-Z0-9_$-]+)", det))
        if a.get("computer"):
            machines.add(a.get("computer"))
        if any(x in tgt.lower() for x in ("exe", "sh", "cmd", "powershell")):
            procs.add(tgt[:50])

    if not users and not machines and not procs:
        return [Paragraph(NO_DATA_USERS, s["empty"])]

    data = [
        [Paragraph("<b>Utilisateurs identifiés</b>", s["td"]), Paragraph(", ".join(users) or "Aucun", s["td"])],
        [Paragraph("<b>Machines impliquées</b>", s["td"]), Paragraph(", ".join(machines) or "Aucune", s["td"])],
        [Paragraph("<b>Processus / Commandes clés</b>", s["td"]), Paragraph("<br/>".join(procs) or "Aucun", s["td"])],
    ]
    t = Table(data, colWidths=[5*cm, 11*cm])
    t.setStyle(_table_style_header())
    return [t]


def _section_timeline(incident_alerts: list[dict], s: dict) -> list:
    priority = [a for a in incident_alerts if a.get("severity") in ("critical", "high", "medium")]
    priority.sort(key=lambda a: str(a.get("timestamp", "0")))
    if not priority:
        return [Paragraph(NO_DATA_TIMELINE, s["empty"])]

    rows = [[Paragraph("<b>Horodatage</b>", s["td"]), Paragraph("<b>Sév.</b>", s["td"]),
             Paragraph("<b>Règle</b>", s["td"]), Paragraph("<b>Cible</b>", s["td"])]]
    for a in priority[:40]:
        rows.append([
            Paragraph(str(a.get("timestamp") or "—")[:19], s["td"]),
            Paragraph((a.get("severity") or "info").upper(), s["td"]),
            Paragraph(str(a.get("title") or "—")[:55], s["td"]),
            Paragraph(str(a.get("target") or a.get("dst_ip") or "—")[:32], s["td_mono"]),
        ])
    t = Table(rows, colWidths=[3.5*cm, 1.5*cm, 6*cm, 5*cm], repeatRows=1)
    t.setStyle(_table_style_header())
    return [t]


def _section_other_iocs(other_iocs: list[dict], s: dict) -> list:
    if not other_iocs:
        return []
    header = [Paragraph("<b>Type</b>", s["td"]), Paragraph("<b>Valeur</b>", s["td"]),
              Paragraph("<b>Occurrences</b>", s["td"]), Paragraph("<b>1ère détection</b>", s["td"])]
    rows = [header]
    for ioc in other_iocs[:30]:
        val = ioc["value"]
        if len(val) > 55:
            val = val[:26] + "…" + val[-26:]
        rows.append([Paragraph(ioc["type"], s["td"]), Paragraph(val, s["td_mono"]),
                     Paragraph(str(ioc["hits"]), s["td"]), Paragraph(ioc["firstSeen"], s["td"])])
    t = Table(rows, colWidths=[2.5*cm, 8.5*cm, 2.5*cm, 5.5*cm], repeatRows=1)
    t.setStyle(_table_style_header())
    return [Paragraph("<b>Autres indicateurs (IP, Domaines)</b>", s["h3"]), t]


def _section_suspicious_events(incident_alerts: list[dict], s: dict) -> list:
    susp_alerts = [a for a in incident_alerts if a.get("severity") in ("high", "critical")]
    if not susp_alerts:
        return [Paragraph(NO_DATA_SUSPICIOUS, s["empty"])]
    rows = [[Paragraph("<b>Sév.</b>", s["td"]), Paragraph("<b>Règle</b>", s["td"]), Paragraph("<b>Cible</b>", s["td"])]]
    for a in susp_alerts[:20]:
        rows.append([Paragraph(str(a.get("severity")).upper(), s["td"]),
                     Paragraph(str(a.get("title"))[:60], s["td"]), Paragraph(str(a.get("target"))[:50], s["td"])])
    t = Table(rows, colWidths=[2*cm, 7*cm, 7*cm])
    t.setStyle(_table_style_header())
    return [t]


def _section_correlations(incident_alerts: list[dict], all_alerts: list[dict], s: dict) -> list:
    import re as _re
    from collections import defaultdict
    import dateutil.parser

    def _normalize_hour(ts_str):
        if not ts_str:
            return None
        try:
            return dateutil.parser.parse(str(ts_str)).strftime("%Y-%m-%d %H:00")
        except Exception:
            return None

    if not incident_alerts:
        return [Paragraph(NO_DATA_CORRELATIONS, s["empty"])]

    IP_RE = _re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    HASH_RE = _re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b")
    SKIP_IPS = {"127.0.0.1", "0.0.0.0", "255.255.255.255"}

    ip_idx, hash_idx, target_idx, hour_idx, user_idx, mach_idx = (defaultdict(list) for _ in range(6))
    incident_file_ids = set(a.get("file_id") for a in incident_alerts)

    for a in all_alerts:
        for f in [a.get("src_ip"), a.get("dst_ip"), a.get("target"), a.get("details"), a.get("threat_intel")]:
            if f:
                for ip in IP_RE.findall(str(f)):
                    if ip not in SKIP_IPS:
                        ip_idx[ip].append(a)
        ti = a.get("threat_intel")
        if isinstance(ti, list):
            for entry in ti:
                if isinstance(entry, dict) and entry.get("value"):
                    v = entry["value"].strip().lower()
                    if len(v) in (32, 40, 64):
                        hash_idx[v].append(a)
        for f in [a.get("details"), a.get("target")]:
            if f:
                for h in HASH_RE.findall(str(f)):
                    hash_idx[h.lower()].append(a)
        tgt = a.get("target") or ""
        if tgt and len(tgt) > 3:
            if "\\" in tgt or "/" in tgt:
                bn = tgt.replace("\\", "/").split("/")[-1].lower()
                if bn and len(bn) > 3:
                    target_idx[bn].append(a)
            else:
                target_idx[tgt.lower().strip()].append(a)
        if a.get("timestamp"):
            h = _normalize_hour(a.get("timestamp"))
            if h:
                hour_idx[h].append(a)
        det = str(a.get("details", ""))
        for u in re.findall(r"(?i)(?:user|utilisateur|account)[\s:=]+([a-zA-Z0-9_$-]+)", det):
            user_idx[u.lower()].append(a)
        mach = a.get("computer")
        if mach:
            mach_idx[mach.lower()].append(a)

    correlations, seen = [], set()

    def _add(ctype, key, als):
        fids = set(x.get("file_id") for x in als)
        tools = set(x.get("tool") for x in als)
        if len(fids) < 2 and len(tools) < 2:
            return
        if not (fids & incident_file_ids):
            return
        pk = f"{ctype}:{key}"
        if pk in seen:
            return
        seen.add(pk)
        sevs = [x.get("severity") for x in als]
        risk = "critical" if "critical" in sevs else "high" if "high" in sevs else "medium"
        correlations.append({"type": ctype, "key": key[:60], "tools": list(tools), "count": len(als),
                              "risk": risk, "events": [(x.get("tool", ""), str(x.get("title", ""))[:50]) for x in als[:4]]})

    for k, als in ip_idx.items():
        if len(als) >= 2: _add("IP", k, als)
    for k, als in hash_idx.items():
        if len(als) >= 2: _add("Hash", k, als)
    for k, als in target_idx.items():
        if len(als) >= 2: _add("Process/Fichier", k, als)
    for k, als in hour_idx.items():
        if len(set(x.get("tool") for x in als)) >= 2: _add("Temporel", k, als)
    for k, als in user_idx.items():
        if len(als) >= 2: _add("Utilisateur", k, als)
    for k, als in mach_idx.items():
        if len(als) >= 2: _add("Machine", k, als)

    if not correlations:
        return [Paragraph(NO_DATA_CORRELATIONS, s["empty"])]

    story = [Paragraph("Alerte corrélée entre plusieurs outils, hôtes ou sur plusieurs jours.", s["normal"])]
    c_header = [Paragraph("<b>Dimension</b>", s["td"]), Paragraph("<b>Clé</b>", s["td"]),
                Paragraph("<b>Outils croisés</b>", s["td"]), Paragraph("<b>Risque</b>", s["td"]),
                Paragraph("<b>Exemples d'événements</b>", s["td"])]
    rows = [c_header]
    for c in correlations[:15]:
        tools_str = ", ".join(t.upper() for t in c["tools"] if t)
        ev_str = "<br/>".join(f"• [{t.upper()}] {tit}" for t, tit in c["events"])
        rows.append([Paragraph(c["type"], s["td"]), Paragraph(c["key"], s["td_mono"]),
                     Paragraph(tools_str, s["td"]), Paragraph(c["risk"].upper(), s["td"]), Paragraph(ev_str, s["td"])])
    t = Table(rows, colWidths=[2.2*cm, 3.5*cm, 3.2*cm, 1.8*cm, 6.3*cm])
    t.setStyle(_table_style_header())
    story.append(t)
    return story


def _build_incident_section(incident_alerts: list[dict], all_alerts: list[dict], incident_name: str,
                             incident_tool: str, s: dict) -> tuple[list, dict]:
    """Construit les 13 sections standardisées pour un incident. Retourne
    (story, stats_pour_agrégation_globale)."""
    story = []
    structured_iocs = extract_structured_iocs(incident_alerts)
    file_iocs = [i for i in structured_iocs if i["type"] in ("Hash", "File")]
    other_iocs = [i for i in structured_iocs if i["type"] not in ("Hash", "File")]

    threat = get_threat_level(incident_alerts)
    crit = sum(1 for a in incident_alerts if a.get("severity") == "critical")
    high = sum(1 for a in incident_alerts if a.get("severity") == "high")
    med = sum(1 for a in incident_alerts if a.get("severity") == "medium")
    info = sum(1 for a in incident_alerts if a.get("severity") == "info")
    low = sum(1 for a in incident_alerts if a.get("severity") == "low")
    tool_lbl = incident_tool.upper() if incident_tool else "Inconnu"

    story.append(HRFlowable(width="100%", thickness=2, color=DARK_GRAY, spaceAfter=0.2*cm))
    story.append(Paragraph(f"<b>Rapport d'analyse du fichier : {incident_name}</b>", s["title"]))
    story.append(Spacer(1, 0.5*cm))

    # 1. Informations Générales
    story.append(Paragraph(f"<b>1. {SECTION_TITLES[1]}</b>", s["h2"]))
    meta = [
        ["Nom du fichier", incident_name],
        ["Outil source", tool_lbl],
        ["Total alertes générées", str(len(incident_alerts))],
        ["Date d'analyse", datetime.now().strftime("%d/%m/%Y %H:%M")],
    ]
    t_meta = Table(meta, colWidths=[5*cm, 11*cm])
    t_meta.setStyle(_table_style_header())
    story.append(t_meta)
    story.append(Spacer(1, 0.3*cm))

    # 2. Méthodologie d'Analyse (texte fixe, identique pour tous les outils)
    story.append(Paragraph(f"<b>2. {SECTION_TITLES[2]}</b>", s["h2"]))
    story.append(Paragraph(
        "Chaque fichier uploadé est analysé par le parseur correspondant à l'outil source "
        "(Hayabusa, Loki, Kuiper, Zircolite, Autopsy, ML-Network, etc.). Les événements sont "
        "extraits, normalisés puis enrichis (ex. scores VirusTotal pour les hashs, correspondances "
        "MITRE ATT&CK lorsque disponibles). Une classification déterministe est appliquée "
        "(Benign, Suspicious, Malicious, Critical, Informational, Unknown), suivie d'une analyse "
        "sémantique par IA (Llama-3.1 via l'API NVIDIA) pour interpréter chaque alerte, dégager des "
        "corrélations et produire un verdict global. Cette méthodologie est identique quel que soit "
        "l'outil source du fichier analysé.", s["normal"]))
    story.append(Spacer(1, 0.3*cm))

    # 3. Résumé Exécutif
    ioc_section, c_all, c_hash, c_file, classified = _section_iocs_classified(file_iocs, s)
    story.append(Paragraph(f"<b>3. {SECTION_TITLES[3]}</b>", s["h2"]))
    ai_summary = explain_incident_summary(incident_name, threat, incident_alerts, classified, [])
    story.append(Paragraph(f"<i>{ai_summary}</i>", s["normal"]))
    story.append(Spacer(1, 0.3*cm))

    # 4. Statistiques Générales
    story.append(Paragraph(f"<b>4. {SECTION_TITLES[4]}</b>", s["h2"]))
    stat_data = [
        [Paragraph("<b>Critique</b>", s["td"]), Paragraph(str(crit), s["td"]),
         Paragraph("<b>Élevée</b>", s["td"]), Paragraph(str(high), s["td"])],
        [Paragraph("<b>Moyenne</b>", s["td"]), Paragraph(str(med), s["td"]),
         Paragraph("<b>Faible/Info</b>", s["td"]), Paragraph(str(low + info), s["td"])],
    ]
    t_stat = Table(stat_data, colWidths=[4*cm, 4*cm, 4*cm, 4*cm])
    t_stat.setStyle(_table_style_header())
    story.append(t_stat)
    story.append(Spacer(1, 0.3*cm))

    # 5. Verdict Global & Classification
    story.append(Paragraph(f"<b>5. {SECTION_TITLES[5]}</b>", s["h2"]))
    malicious_n = c_all.get("Malicious", 0)
    suspicious_n = c_all.get("Suspicious", 0) + high
    verdict_lbl = _compute_verdict(crit, malicious_n, high, suspicious_n, len(incident_alerts))
    v_stats = {"critical": crit, "malicious": malicious_n, "suspicious": suspicious_n,
               "benign": c_all.get("Benign", 0) + low, "info": info, "correlations": 0}
    v_expl = explain_global_verdict(verdict_lbl, v_stats)
    story.append(Paragraph(f"<b>Verdict : {verdict_lbl.upper()}</b>", s["h3"]))
    story.append(Paragraph(v_expl, s["normal"]))
    story.append(Spacer(1, 0.2*cm))

    cat_counts = {k: 0 for k in STATUS_KEYS}
    for a in incident_alerts:
        ioc_cl = None
        for cl in classified:
            if cl.get("value") in str(a):
                ioc_cl = cl.get("status")
        cat = _classify_event(a, ioc_cl)
        if cat in cat_counts:
            cat_counts[cat] += 1
    tot = len(incident_alerts)
    sum_header = [Paragraph("", s["td"])] + [Paragraph(f"<b>{STATUS_SHORT[k]}</b>", s["td"]) for k in STATUS_KEYS]
    sum_rows = [sum_header, [Paragraph("<b>Total Événements</b>", s["td"])] +
                [Paragraph(_pct(cat_counts[k], tot), s["td"]) for k in STATUS_KEYS]]
    t_sum = Table(sum_rows, colWidths=[3.8*cm] + [2.6*cm]*5)
    t_sum.setStyle(_table_style_header())
    story.append(t_sum)
    story.append(Spacer(1, 0.2*cm))
    story.extend(_section_mitre_summary(incident_alerts, s))
    story.append(Spacer(1, 0.4*cm))

    # 6. Alertes (explication technique + IA réelle par alerte)
    story.append(Paragraph(f"<b>6. {SECTION_TITLES[6]}</b>", s["h2"]))
    story.extend(_section_alerts(incident_alerts, s))
    story.append(Spacer(1, 0.4*cm))

    # 7. Événements Suspects
    story.append(Paragraph(f"<b>7. {SECTION_TITLES[7]}</b>", s["h2"]))
    story.extend(_section_suspicious_events(incident_alerts, s))
    story.append(Spacer(1, 0.4*cm))

    # 8. Corrélations
    story.append(Paragraph(f"<b>8. {SECTION_TITLES[8]}</b>", s["h2"]))
    story.extend(_section_correlations(incident_alerts, all_alerts, s))
    story.append(Spacer(1, 0.4*cm))

    # 9. IOCs
    story.append(Paragraph(f"<b>9. {SECTION_TITLES[9]}</b>", s["h2"]))
    story.extend(ioc_section[2:] if len(ioc_section) > 2 else ioc_section)
    story.extend(_section_other_iocs(other_iocs, s))
    story.append(Spacer(1, 0.4*cm))

    # 10. Utilisateurs, Machines, Processus
    story.append(Paragraph(f"<b>10. {SECTION_TITLES[10]}</b>", s["h2"]))
    story.extend(_section_users_machines(incident_alerts, s))
    story.append(Spacer(1, 0.4*cm))

    # 11. Timeline
    story.append(Paragraph(f"<b>11. {SECTION_TITLES[11]}</b>", s["h2"]))
    story.extend(_section_timeline(incident_alerts, s))
    story.append(Spacer(1, 0.4*cm))

    # 12. Recommandations Finales
    story.append(Paragraph(f"<b>12. {SECTION_TITLES[12]}</b>", s["h2"]))
    if crit > 0:
        story.append(Paragraph("<b>[Critique] Actions Immédiates :</b> Isoler le système, préserver les preuves, bloquer les IOCs.", s["normal"]))
    if high > 0:
        story.append(Paragraph("<b>[Haute] Actions à Court Terme :</b> Rechercher la compromission sur le parc, réinitialiser les identifiants.", s["normal"]))
    story.append(Paragraph("<b>[Moyenne] Actions Préventives :</b> Auditer les privilèges, mettre à jour les systèmes.", s["normal"]))
    story.append(Paragraph("<b>[Faible] Améliorations :</b> Renforcer la journalisation et la surveillance SOC.", s["normal"]))
    story.append(Spacer(1, 0.4*cm))

    # 13. Limitations
    story.append(Paragraph(f"<b>13. {SECTION_TITLES[13]}</b>", s["h2"]))
    story.append(Paragraph(
        "<i>Note : Ce rapport se base exclusivement sur les événements présents dans le fichier "
        "analysé. L'absence de preuves de compromission ne garantit pas l'innocuité absolue du "
        "système (des traces peuvent avoir été effacées ou non journalisées). Les explications IA "
        "sont générées dynamiquement à partir des données réelles du fichier et doivent être "
        "validées par un analyste humain.</i>", s["normal"]))
    story.append(PageBreak())

    incident_stats = {"crit": crit, "high": high, "med": med, "low": low, "info": info,
                       "malicious": malicious_n, "suspicious": suspicious_n,
                       "total_alerts": len(incident_alerts), "verdict": verdict_lbl,
                       "cat_counts": cat_counts}
    return story, incident_stats


# ── Section finale agrégée sur TOUT le dossier ──────────────────────────────

def _build_global_summary_section(all_alerts: list[dict], per_incident_stats: list[dict], s: dict) -> list:
    story = []
    story.append(HRFlowable(width="100%", thickness=2, color=DARK_GRAY, spaceAfter=0.2*cm))
    story.append(Paragraph("Résumé Global de la Classification de l'Analyse du Fichier", s["title"]))
    story.append(Spacer(1, 0.3*cm))

    cat_counts = {k: 0 for k in STATUS_KEYS}
    for st in per_incident_stats:
        for k in STATUS_KEYS:
            cat_counts[k] += st["cat_counts"].get(k, 0)
    total = sum(cat_counts.values())

    story.append(Paragraph(
        f"Agrégation sur {len(per_incident_stats)} fichier(s) analysé(s) et {total} événement(s) au total.",
        s["normal"]))
    sum_header = [Paragraph("", s["td"])] + [Paragraph(f"<b>{STATUS_SHORT[k]}</b>", s["td"]) for k in STATUS_KEYS]
    sum_rows = [sum_header, [Paragraph("<b>Total Global</b>", s["td"])] +
                [Paragraph(_pct(cat_counts[k], total), s["td"]) for k in STATUS_KEYS]]
    t_sum = Table(sum_rows, colWidths=[3.8*cm] + [2.6*cm]*5)
    t_sum.setStyle(_table_style_header())
    story.append(t_sum)
    story.append(Spacer(1, 0.4*cm))

    crit = sum(st["crit"] for st in per_incident_stats)
    high = sum(st["high"] for st in per_incident_stats)
    malicious = sum(st["malicious"] for st in per_incident_stats)
    suspicious = sum(st["suspicious"] for st in per_incident_stats)
    global_verdict = _compute_verdict(crit, malicious, high, suspicious, total)

    story.append(Paragraph(f"<b>Verdict Global du Dossier : {global_verdict.upper()}</b>", s["h2"]))
    v_stats = {"critical": crit, "malicious": malicious, "suspicious": suspicious,
               "benign": cat_counts.get("Benign", 0), "info": cat_counts.get("Informational", 0),
               "incidents_analyses": len(per_incident_stats)}
    v_expl = explain_global_verdict(global_verdict, v_stats)
    story.append(Paragraph(v_expl, s["normal"]))
    story.append(Spacer(1, 0.3*cm))

    story.append(Paragraph("<b>Détail par fichier analysé</b>", s["h3"]))
    rows = [[Paragraph("<b>Fichier / Incident</b>", s["td"]), Paragraph("<b>Alertes</b>", s["td"]),
             Paragraph("<b>Critiques</b>", s["td"]), Paragraph("<b>Verdict</b>", s["td"])]]
    for i, st in enumerate(per_incident_stats):
        rows.append([Paragraph(st.get("name", f"Incident {i+1}"), s["td"]),
                     Paragraph(str(st["total_alerts"]), s["td"]),
                     Paragraph(str(st["crit"]), s["td"]),
                     Paragraph(st["verdict"], s["td"])])
    t = Table(rows, colWidths=[7*cm, 2.5*cm, 2.5*cm, 4*cm])
    t.setStyle(_table_style_header())
    story.append(t)

    return story


# ── Point d'entrée principal ───────────────────────────────────────────────────

def generate_report(case_id: str, alerts: list[dict], stats: dict,
                    output_path: str, filename: str = None,
                    files_meta: list[dict] = None):

    doc = SimpleDocTemplate(
        output_path, pagesize=A4,
        topMargin=1.5*cm, bottomMargin=1.5*cm, leftMargin=1.5*cm, rightMargin=1.5*cm,
    )
    s = _build_styles()
    story = []

    threat_label = get_threat_level(alerts)
    report_date = datetime.now().strftime("%d/%m/%Y %H:%M")
    target_name = filename if filename else f"Dossier complet — {case_id}"
    tools_used = list(dict.fromkeys(a.get("tool", "Inconnu") for a in alerts))

    # ── PAGE DE GARDE ─────────────────────────────────────────────────────────
    story.append(Spacer(1, 3*cm))
    story.append(Paragraph("ForensiQ", s["brand"]))
    story.append(Paragraph("RAPPORT D'INVESTIGATION FORENSIQUE", s["title"]))
    story.append(Paragraph(f"Source analysée : {target_name}", s["subtitle"]))

    threat_box = Table(
        [[Paragraph(f"<b>NIVEAU DE MENACE : {threat_label}</b>",
                    ParagraphStyle("TB", alignment=TA_CENTER, fontSize=13, fontName="Helvetica-Bold"))]],
        colWidths=[14*cm], rowHeights=[1.3*cm])
    threat_box.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 2, BLACK), ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
    story.append(threat_box)
    story.append(Spacer(1, 1.5*cm))

    meta = [
        ["Référence", f"CASE-{case_id}"], ["Date du rapport", report_date],
        ["Classification", "CONFIDENTIEL"], ["Total alertes", str(len(alerts))],
        ["Incidents analysés", str(len(files_meta) if files_meta else 1)],
        ["Outils d'analyse", ", ".join(t.capitalize() for t in tools_used if t)],
    ]
    t_meta = Table(meta, colWidths=[5*cm, 9*cm])
    t_meta.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"), ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("TEXTCOLOR", (0, 0), (-1, -1), BLACK), ("LINEBELOW", (0, 0), (-1, -2), 0.5, LIGHT_GRAY),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
    story.append(t_meta)
    story.append(PageBreak())

    # ── ANALYSE PAR INCIDENT (structure identique garantie pour chacun) ────────
    per_incident_stats = []
    if files_meta:
        for fm in files_meta:
            fid = fm["id"]
            inc_alerts = [a for a in alerts if a.get("file_id") == fid]
            if not inc_alerts:
                # Même un fichier sans alerte reçoit un rapport standardisé, pas d'omission silencieuse
                inc_alerts = []
            sec_story, sec_stats = _build_incident_section(
                inc_alerts, alerts, fm.get("filename", f"Incident #{fid}"), fm.get("tool", ""), s)
            sec_stats["name"] = fm.get("filename", f"Incident #{fid}")
            story.extend(sec_story)
            per_incident_stats.append(sec_stats)
    else:
        sec_story, sec_stats = _build_incident_section(
            alerts, alerts, target_name, tools_used[0] if tools_used else "", s)
        sec_stats["name"] = target_name
        story.extend(sec_story)
        per_incident_stats.append(sec_stats)

    # ── RÉSUMÉ GLOBAL DE CLASSIFICATION (obligatoire, fin de rapport) ──────────
    story.extend(_build_global_summary_section(alerts, per_incident_stats, s))

    story.append(Spacer(1, 0.4*cm))
    story.append(HRFlowable(width="100%", thickness=1, color=LIGHT_GRAY))
    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph(
        f"<i>Rapport généré automatiquement par ForensiQ le {report_date} — Document CONFIDENTIEL.</i>",
        s["footer"]))

    doc.build(story)
    return output_path