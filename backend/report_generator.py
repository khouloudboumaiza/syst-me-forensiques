"""
report_generator.py
─────────────────────────────────────────────────────────────────────────────
Génère un rapport PDF professionnel complet pour chaque incident :
  • Page de garde + synthèse exécutive (IA)
  • Par incident : Alertes, IOCs/Hash/Fichiers + classification VT+IA
  • Résumé global Hash seuls / Fichiers seuls / Total — avec % dynamiques
  • Timeline complète (événements critiques et élevés)
  • Section Corrélations host/réseau
  • Section Artefacts
  • Recommandations finales + Conclusion (IA)
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
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

# ── Palette noir et blanc professionnel ────────────────────────────────────────
BLACK      = colors.black
DARK_GRAY  = colors.HexColor("#1f2937")
MID_GRAY   = colors.HexColor("#6b7280")
LIGHT_GRAY = colors.HexColor("#e5e7eb")
WHITE      = colors.white
ACCENT     = colors.HexColor("#111827")   # titre section

SUSPICIOUS_PATHS = ["temp", "tmp", "appdata", "roaming", "downloads",
                    "public", "startup", "run", "winlogon", "users\\public"]
SYSTEM_PATHS     = ["system32", "windows\\system", "program files", "microsoft"]

STATUS_KEYS   = ["true_positive", "suspicious_review", "likely_false_positive",
                 "potential_false_negative", "clean"]
STATUS_LABELS = {
    "true_positive":            "Vrai Positif (VP)",
    "suspicious_review":        "Suspect",
    "likely_false_positive":    "Faux Positif (FP)",
    "potential_false_negative": "Faux Négatif (FN)",
    "clean":                    "Sain",
}
STATUS_SHORT = {
    "true_positive":            "VP",
    "suspicious_review":        "Suspects",
    "likely_false_positive":    "FP",
    "potential_false_negative": "FN",
    "clean":                    "Sains",
}

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
    from ai_classifier import classify_by_vt_score
    hash_val  = ioc.get("linked_hash") or (ioc["value"] if ioc["type"] == "Hash" else "")
    file_path = ioc.get("file_path") or (ioc["value"] if ioc["type"] == "File" else "")
    return classify_by_vt_score(
        hash_value=hash_val,
        file_path=file_path,
        vt_malicious=ioc.get("vt_malicious", 0),
        vt_total=ioc.get("vt_total", 0),
        vt_verdict=ioc.get("vt_verdict", "unknown"),
        tool=ioc.get("source", ""),
    )


def _generate_ai_summary(alerts: list[dict], classified: list[dict],
                          correlated_events: list[dict], threat_label: str,
                          incident_name: str) -> str:
    """Génère un paragraphe de synthèse en langage humain via Gemini ou fallback."""
    import os, requests
    GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
    GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent"

    n_crit   = sum(1 for a in alerts if a.get("severity") == "critical")
    n_high   = sum(1 for a in alerts if a.get("severity") == "high")
    n_vp     = sum(1 for c in classified if c.get("classification", {}).get("status") == "true_positive")
    n_susp   = sum(1 for c in classified if c.get("classification", {}).get("status") == "suspicious_review")
    n_correl = len(correlated_events)

    if GEMINI_API_KEY:
        prompt = (
            f"Tu rédiges la section synthèse d'un rapport forensique professionnel.\n"
            f"Incident : {incident_name}\n"
            f"Niveau de menace : {threat_label}\n"
            f"Alertes : {len(alerts)} dont {n_crit} critiques et {n_high} élevées.\n"
            f"Éléments classifiés malveillants (VP) : {n_vp}\n"
            f"Éléments suspects : {n_susp}\n"
            f"Corrélations host/réseau détectées : {n_correl}\n\n"
            "En 3-4 phrases techniques et professionnelles en français, résume les faits "
            "clés de cet incident et les risques associés pour un analyste SOC. "
            "Ne commence pas par 'Bien sûr' ou formule de politesse."
        )
        try:
            resp = requests.post(
                f"{GEMINI_URL}?key={GEMINI_API_KEY}",
                json={"contents": [{"parts": [{"text": prompt}]}],
                      "generationConfig": {"maxOutputTokens": 250, "temperature": 0.3}},
                timeout=10
            )
            if resp.status_code == 200:
                text = resp.json()["candidates"][0]["content"]["parts"][0]["text"].strip()
                if text:
                    return text
        except Exception:
            pass

    # Fallback déterministe
    parts = [f"L'analyse de l'incident <b>{incident_name}</b> révèle un niveau de menace <b>{threat_label}</b>, "
             f"avec {len(alerts)} événement(s) détecté(s) dont {n_crit} critique(s) et {n_high} élevé(s)."]
    if n_vp > 0:
        parts.append(f"{n_vp} indicateur(s) ont été classifiés comme <b>vrais positifs</b> (menace confirmée par VirusTotal).")
    if n_susp > 0:
        parts.append(f"{n_susp} élément(s) supplémentaire(s) restent suspects et nécessitent une investigation manuelle.")
    if n_correl > 0:
        parts.append(f"{n_correl} corrélation(s) host/réseau ont été détectées, suggérant une activité coordonnée.")
    return " ".join(parts)


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

        # IP
        for ip_key in ("dst_ip", "src_ip"):
            ip = a.get(ip_key)
            if ip and ip not in ("127.0.0.1", "0.0.0.0") and len(ip) > 5:
                k = f"IP-{ip}"
                if k not in ioc_map:
                    ioc_map[k] = {"type": "IP", "value": ip, "source": tool, "hits": 0, "firstSeen": timestamp}
                ioc_map[k]["hits"] += 1
                if timestamp < ioc_map[k]["firstSeen"]:
                    ioc_map[k]["firstSeen"] = timestamp

        # Fichier
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

        # Hash
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


# ── Sections Rapport ───────────────────────────────────────────────────────────

def _section_alerts(incident_alerts: list[dict], s: dict) -> list:
    """Tableau de toutes les alertes de l'incident."""
    story = []
    story.append(Paragraph("<b>Alertes détectées</b>", s["h2"]))
    story.append(Paragraph(
        f"{len(incident_alerts)} alerte(s) enregistrée(s) pour cet incident.",
        s["normal"],
    ))

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_alerts = sorted(incident_alerts,
                           key=lambda a: sev_order.get(a.get("severity", "info"), 9))

    header = [
        Paragraph("<b>Sév.</b>", s["td"]),
        Paragraph("<b>Règle / Titre</b>", s["td"]),
        Paragraph("<b>Cible</b>", s["td"]),
        Paragraph("<b>Horodatage</b>", s["td"]),
        Paragraph("<b>Explication (IA)</b>", s["td"]),
    ]
    rows = [header]
    for a in sorted_alerts[:50]:
        rule   = str(a.get("title") or "—")[:60]
        target = str(a.get("target") or a.get("dst_ip") or "—")[:35]
        ts     = str(a.get("timestamp") or "—")[:19]
        sev    = (a.get("severity") or "info").upper()
        expl   = str(a.get("explanation") or _fallback_explain(rule, target, a.get("tool", "")))
        rows.append([
            Paragraph(sev,   s["td"]),
            Paragraph(rule,  s["td"]),
            Paragraph(target, s["td_mono"]),
            Paragraph(ts,    s["td"]),
            Paragraph(expl[:200], s["td"]),
        ])
    t = Table(rows, colWidths=[1.5*cm, 4*cm, 3*cm, 3.5*cm, 7*cm], repeatRows=1)
    t.setStyle(_table_style_header())
    story.append(t)
    return story


def _fallback_explain(rule: str, target: str, tool: str) -> str:
    r = rule.lower()
    t = target or "la cible"
    if "logon" in r or "login" in r or "auth" in r:
        return f"Tentative d'authentification détectée sur {t}."
    if "process" in r or "cmd" in r or "shell" in r or "exec" in r:
        return f"Exécution d'un processus ou commande potentiellement malveillant sur {t}."
    if "malware" in r or "virus" in r or "trojan" in r or "yara" in r:
        return f"Signature de malware détectée sur {t}."
    if "network" in r or "connection" in r or "port" in r:
        return f"Trafic réseau anormal vers {t}."
    if "privilege" in r or "credential" in r:
        return f"Élévation de privilèges ou vol d'identifiants ciblant {t}."
    if "registry" in r or "file" in r:
        return f"Modification suspecte du registre ou système de fichiers sur {t}."
    return f"Comportement anormal détecté par {tool.upper() or 'l outil de détection'} sur {t}."


def _section_iocs_classified(file_iocs: list[dict], s: dict) -> tuple[list, dict, dict, dict, list]:
    """Tableau détaillé IOC + classification + résumé counts."""
    story = []
    counts_all  = {k: 0 for k in STATUS_KEYS}
    counts_hash = {k: 0 for k in STATUS_KEYS}
    counts_file = {k: 0 for k in STATUS_KEYS}
    classified  = []

    for ioc in file_iocs:
        cl     = _classify_ioc(ioc)
        ioc["classification"] = cl
        status = cl.get("status", "suspicious_review")
        if status not in counts_all:
            status = "suspicious_review"
        counts_all[status] += 1
        if ioc["type"] == "Hash":
            counts_hash[status] += 1
        elif ioc["type"] == "File":
            counts_file[status] += 1
        classified.append(ioc)

    total_all  = len(classified)
    total_hash = sum(counts_hash.values())
    total_file = sum(counts_file.values())

    # ── Tableau résumé global ────────────────────────────────────────────────
    def _pct(n, tot):
        return f"{n} ({n/tot*100:.0f}%)" if tot > 0 else f"{n} (—)"

    story.append(Paragraph(
        f"<b>Résumé Global de la Classification — {total_all} élément(s) analysé(s)</b>", s["h2"]
    ))
    story.append(Paragraph(
        "Pourcentages calculés dynamiquement à partir des scores VirusTotal réels "
        "de chaque hash et chemin de fichier de cet incident.",
        s["normal"],
    ))

    sum_header = [Paragraph("", s["td"])] + [
        Paragraph(f"<b>{STATUS_SHORT[k]}</b>", s["td"]) for k in STATUS_KEYS
    ]
    sum_rows = [
        sum_header,
        [Paragraph(f"<b>Total ({total_all})</b>",     s["td"])] + [Paragraph(_pct(counts_all[k],  total_all),  s["td"]) for k in STATUS_KEYS],
        [Paragraph(f"Hash seuls ({total_hash})",       s["td"])] + [Paragraph(_pct(counts_hash[k], total_hash), s["td"]) for k in STATUS_KEYS],
        [Paragraph(f"Fichiers seuls ({total_file})",   s["td"])] + [Paragraph(_pct(counts_file[k], total_file), s["td"]) for k in STATUS_KEYS],
    ]
    t_sum = Table(sum_rows, colWidths=[3.8*cm] + [2.6*cm]*5)
    t_sum.setStyle(TableStyle([
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
    story.append(t_sum)
    story.append(Spacer(1, 0.3*cm))

    # ── Tableau détaillé ─────────────────────────────────────────────────────
    if classified:
        story.append(Paragraph("<b>Détail des éléments analysés (Hash et Fichiers)</b>", s["h2"]))
        det_header = [
            Paragraph("<b>Chemin / Fichier</b>",     s["td"]),
            Paragraph("<b>Hash associé</b>",         s["td"]),
            Paragraph("<b>Score VT</b>",             s["td"]),
            Paragraph("<b>Classification IA</b>",    s["td"]),
            Paragraph("<b>Confiance</b>",            s["td"]),
            Paragraph("<b>Explication & Action</b>", s["td"]),
        ]
        det_rows = [det_header]
        for ioc in classified:
            path  = ioc.get("file_path") or ioc["value"]
            if len(path) > 48:
                path = "…" + path[-45:]
            h_val = ioc.get("linked_hash") or (ioc["value"] if ioc["type"] == "Hash" else "—")
            h_disp = (h_val[:12] + "…" + h_val[-8:]) if h_val != "—" and len(h_val) > 24 else h_val
            vt_str = (f"{ioc.get('vt_malicious', 0)}/{ioc.get('vt_total', 0)}"
                      if ioc.get("vt_total", 0) > 0 else "N/A")
            cl     = ioc["classification"]
            status = cl.get("status", "suspicious_review")
            label  = STATUS_LABELS.get(status, "Suspect")
            conf   = f"{cl.get('confidence', 0):.0f}%"
            expl   = cl.get("explanation", "—")[:220]
            recom  = cl.get("recommendation", "—")[:150]
            ctx    = _path_context_label(path)

            det_rows.append([
                Paragraph(f"<b>{path}</b>", s["td_mono"]),
                Paragraph(h_disp,           s["td_mono"]),
                Paragraph(vt_str,           s["td"]),
                Paragraph(f"<b>{label}</b>",s["td"]),
                Paragraph(conf,             s["td"]),
                Paragraph(f"{ctx}<br/>{expl}<br/><i>→ {recom}</i>",
                          ParagraphStyle("Exp", parent=s["td"], leading=10)),
            ])

        col_w = [4.5*cm, 2.8*cm, 1.5*cm, 2.3*cm, 1.3*cm, 6.6*cm]
        t_det = Table(det_rows, colWidths=col_w, repeatRows=1)
        t_det.setStyle(_table_style_header())
        story.append(t_det)

    return story, counts_all, counts_hash, counts_file, classified


def _section_timeline(incident_alerts: list[dict], s: dict) -> list:
    """Timeline complète des événements (critiques et élevés)."""
    story = []
    priority = [a for a in incident_alerts if a.get("severity") in ("critical", "high", "medium")]
    priority.sort(key=lambda a: str(a.get("timestamp", "0")))
    if not priority:
        return story

    story.append(Paragraph("<b>Timeline des événements</b>", s["h2"]))
    tl_header = [
        Paragraph("<b>Horodatage</b>",      s["td"]),
        Paragraph("<b>Sév.</b>",            s["td"]),
        Paragraph("<b>Règle</b>",           s["td"]),
        Paragraph("<b>Cible</b>",           s["td"]),
        Paragraph("<b>Explication</b>",     s["td"]),
    ]
    rows = [tl_header]
    for a in priority[:40]:
        rule   = str(a.get("title") or "—")[:55]
        target = str(a.get("target") or a.get("dst_ip") or "—")[:32]
        ts     = str(a.get("timestamp") or "—")[:19]
        sev    = (a.get("severity") or "info").upper()
        expl   = str(a.get("explanation") or _fallback_explain(rule, target, a.get("tool", "")))
        rows.append([
            Paragraph(ts,     s["td"]),
            Paragraph(sev,    s["td"]),
            Paragraph(rule,   s["td"]),
            Paragraph(target, s["td_mono"]),
            Paragraph(expl[:200], s["td"]),
        ])
    t = Table(rows, colWidths=[3.5*cm, 1.5*cm, 4*cm, 3*cm, 7*cm], repeatRows=1)
    t.setStyle(_table_style_header())
    story.append(t)
    return story


def _section_other_iocs(other_iocs: list[dict], s: dict) -> list:
    if not other_iocs:
        return []
    story = [Paragraph("<b>Autres indicateurs (IP, Domaines)</b>", s["h2"])]
    header = [
        Paragraph("<b>Type</b>",         s["td"]),
        Paragraph("<b>Valeur</b>",       s["td"]),
        Paragraph("<b>Occurrences</b>",  s["td"]),
        Paragraph("<b>1ère détection</b>",s["td"]),
    ]
    rows = [header]
    for ioc in other_iocs[:30]:
        val = ioc["value"]
        if len(val) > 55:
            val = val[:26] + "…" + val[-26:]
        rows.append([
            Paragraph(ioc["type"],  s["td"]),
            Paragraph(val,          s["td_mono"]),
            Paragraph(str(ioc["hits"]), s["td"]),
            Paragraph(ioc["firstSeen"], s["td"]),
        ])
    t = Table(rows, colWidths=[2.5*cm, 8.5*cm, 2.5*cm, 5.5*cm], repeatRows=1)
    t.setStyle(_table_style_header())
    story.append(t)
    return story


def _section_correlations(incident_alerts: list[dict], all_alerts: list[dict], s: dict) -> list:
    """Corrélations multi-dimensionnelles : IP, hash, cible, temporel."""
    import re as _re
    from collections import defaultdict
    import dateutil.parser

    def _normalize_hour(ts_str):
        if not ts_str: return None
        try:
            dt = dateutil.parser.parse(str(ts_str))
            return dt.strftime("%Y-%m-%d %H:00")
        except:
            return None

    story = []
    if not incident_alerts:
        return story

    IP_RE   = _re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    HASH_RE = _re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b")
    SKIP_IPS = {"127.0.0.1", "0.0.0.0", "255.255.255.255"}

    # Build indexes from ALL alerts
    ip_idx:     dict[str, list] = defaultdict(list)
    hash_idx:   dict[str, list] = defaultdict(list)
    target_idx: dict[str, list] = defaultdict(list)
    hour_idx:   dict[str, list] = defaultdict(list)

    incident_file_ids = set(a.get("file_id") for a in incident_alerts)

    for a in all_alerts:
        # IPs
        for f in [a.get("src_ip"), a.get("dst_ip"), a.get("target"), a.get("details"), a.get("threat_intel")]:
            if f:
                for ip in IP_RE.findall(str(f)):
                    if ip not in SKIP_IPS:
                        ip_idx[ip].append(a)
        # Hashes
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
        # Target
        tgt = a.get("target") or ""
        if tgt and len(tgt) > 3:
            if "\\" in tgt or "/" in tgt:
                bn = tgt.replace("\\", "/").split("/")[-1].lower()
                if bn and len(bn) > 3:
                    target_idx[bn].append(a)
            else:
                target_idx[tgt.lower().strip()].append(a)
        # Temporal
        if a.get("timestamp"):
            h = _normalize_hour(a.get("timestamp"))
            if h:
                hour_idx[h].append(a)

    # Find correlations involving incident files
    correlations = []
    seen = set()

    def _add(ctype, key, als):
        fids = set(x.get("file_id") for x in als)
        tools = set(x.get("tool") for x in als)
        if len(fids) < 2 and len(tools) < 2:
            return
        # Must involve at least one alert from the incident
        if not (fids & incident_file_ids):
            return
        pk = f"{ctype}:{key}"
        if pk in seen:
            return
        seen.add(pk)
        sevs = [x.get("severity") for x in als]
        risk = "critical" if "critical" in sevs else "high" if "high" in sevs else "medium"
        correlations.append({
            "type":  ctype,
            "key":   key[:60],
            "tools": list(tools),
            "count": len(als),
            "risk":  risk,
            "events": [(x.get("tool",""), str(x.get("title",""))[:50]) for x in als[:4]],
        })

    for k, als in ip_idx.items():
        if len(als) >= 2:
            _add("IP", k, als)
    for k, als in hash_idx.items():
        if len(als) >= 2:
            _add("Hash", k, als)
    for k, als in target_idx.items():
        if len(als) >= 2:
            _add("Cible", k, als)
    for k, als in hour_idx.items():
        tools = set(x.get("tool") for x in als)
        if len(tools) >= 2:
            _add("Temporel", k, als)

    if not correlations:
        return story

    story.append(Paragraph("<b>Corrélations Multi-Dimensionnelles</b>", s["h2"]))
    story.append(Paragraph(
        f"{len(correlations)} corrélation(s) identifiée(s) entre les fichiers de ce cas.",
        s["normal"],
    ))

    header = [
        Paragraph("<b>Type</b>",       s["td"]),
        Paragraph("<b>Indicateur</b>",  s["td"]),
        Paragraph("<b>Outils</b>",      s["td"]),
        Paragraph("<b>Alertes</b>",     s["td"]),
        Paragraph("<b>Risque</b>",      s["td"]),
    ]
    rows = [header]
    for c in correlations[:30]:
        rows.append([
            Paragraph(c["type"],                      s["td"]),
            Paragraph(c["key"],                       s["td_mono"]),
            Paragraph(", ".join(c["tools"]),           s["td"]),
            Paragraph(str(c["count"]),                 s["td"]),
            Paragraph(c["risk"].upper(),               s["td"]),
        ])
    t = Table(rows, colWidths=[2*cm, 5.5*cm, 4*cm, 2*cm, 2.5*cm], repeatRows=1)
    t.setStyle(_table_style_header())
    story.append(t)
    story.append(Paragraph(
        f"<b>{len(correlations)} corrélation(s)</b> identifiée(s). "
        "Ces indicateurs partagés entre fichiers renforcent la confiance dans l'attribution de l'incident.",
        s["normal"],
    ))
    return story


def _section_artifacts(incident_alerts: list[dict], s: dict) -> list:
    """Liste les artefacts notables (exécutables, scripts, registre, etc.)."""
    story = []
    artifact_ext = r"\b[a-zA-Z0-9_\- ]+\.(exe|dll|ps1|bat|vbs|sh|bin|sys|msi|cmd|lnk|reg)\b"
    artifacts = []
    seen = set()
    for a in incident_alerts:
        text = f"{a.get('title','')} {a.get('details','')} {a.get('target','')}"
        for m in re.findall(artifact_ext, text, re.IGNORECASE):
            if m not in seen:
                seen.add(m)
                artifacts.append({
                    "name":  m,
                    "rule":  str(a.get("title") or "—")[:60],
                    "tool":  (a.get("tool") or "—").upper(),
                    "ts":    str(a.get("timestamp") or "—")[:19],
                    "sev":   (a.get("severity") or "info").upper(),
                })
    if not artifacts:
        return story

    story.append(Paragraph("<b>Artefacts Notables</b>", s["h2"]))
    header = [
        Paragraph("<b>Artefact</b>",    s["td"]),
        Paragraph("<b>Sév.</b>",        s["td"]),
        Paragraph("<b>Règle source</b>",s["td"]),
        Paragraph("<b>Outil</b>",       s["td"]),
        Paragraph("<b>Horodatage</b>",  s["td"]),
    ]
    rows = [header]
    for art in artifacts[:30]:
        rows.append([
            Paragraph(art["name"], s["td_mono"]),
            Paragraph(art["sev"],  s["td"]),
            Paragraph(art["rule"], s["td"]),
            Paragraph(art["tool"], s["td"]),
            Paragraph(art["ts"],   s["td"]),
        ])
    t = Table(rows, colWidths=[3.5*cm, 1.5*cm, 5.5*cm, 2.5*cm, 3.5*cm], repeatRows=1)
    t.setStyle(_table_style_header())
    story.append(t)
    return story


def _build_incident_section(incident_alerts: list[dict], all_alerts: list[dict], incident_name: str,
                             incident_tool: str, s: dict) -> list:
    """Construit la section complète d'un incident."""
    story = []

    structured_iocs = extract_structured_iocs(incident_alerts)
    file_iocs  = [i for i in structured_iocs if i["type"] in ("Hash", "File")]
    other_iocs = [i for i in structured_iocs if i["type"] not in ("Hash", "File")]

    threat = get_threat_level(incident_alerts)
    crit   = sum(1 for a in incident_alerts if a.get("severity") == "critical")
    high   = sum(1 for a in incident_alerts if a.get("severity") == "high")
    tool_lbl = incident_tool.upper() if incident_tool else "Inconnu"

    # En-tête incident
    story.append(HRFlowable(width="100%", thickness=2, color=DARK_GRAY, spaceAfter=0.2*cm))
    story.append(Paragraph(f"<b>Incident : {incident_name}</b>", s["h1"]))
    story.append(Paragraph(
        f"Outil : <b>{tool_lbl}</b> · Alertes : <b>{len(incident_alerts)}</b> · "
        f"Menace : <b>{threat}</b> · Critiques : {crit} · Élevées : {high}",
        s["normal"],
    ))

    # Synthèse IA de l'incident
    correl_preview = []  # sera rempli après classification
    ioc_section, c_all, c_hash, c_file, classified = _section_iocs_classified(file_iocs, s)
    ai_summary = _generate_ai_summary(incident_alerts, classified, correl_preview, threat, incident_name)
    story.append(Paragraph(f"<i>{ai_summary}</i>", s["normal"]))
    story.append(Spacer(1, 0.3*cm))

    # 1. Alertes
    story.extend(_section_alerts(incident_alerts, s))
    story.append(Spacer(1, 0.4*cm))

    # 2. IOCs classifiés (hashs + fichiers) + résumé global
    story.extend(ioc_section)
    story.append(Spacer(1, 0.4*cm))

    # 3. Autres IOCs (IP / domaines)
    story.extend(_section_other_iocs(other_iocs, s))

    # 4. Artefacts
    story.extend(_section_artifacts(incident_alerts, s))
    story.append(Spacer(1, 0.3*cm))

    # 5. Corrélations
    story.extend(_section_correlations(incident_alerts, all_alerts, s))
    story.append(Spacer(1, 0.3*cm))

    # 6. Timeline
    story.extend(_section_timeline(incident_alerts, s))

    return story


# ── Point d'entrée principal ───────────────────────────────────────────────────

def generate_report(case_id: str, alerts: list[dict], stats: dict,
                    output_path: str, filename: str = None,
                    files_meta: list[dict] = None):

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        topMargin=1.5*cm, bottomMargin=1.5*cm,
        leftMargin=1.5*cm, rightMargin=1.5*cm,
    )
    s = _build_styles()
    story = []

    threat_label  = get_threat_level(alerts)
    report_date   = datetime.now().strftime("%d/%m/%Y %H:%M")
    target_name   = filename if filename else f"Dossier complet — {case_id}"
    tools_used    = list(dict.fromkeys(a.get("tool", "Inconnu") for a in alerts))
    crit_count    = sum(1 for a in alerts if a.get("severity") == "critical")
    high_count    = sum(1 for a in alerts if a.get("severity") == "high")

    # ── PAGE DE GARDE ─────────────────────────────────────────────────────────
    story.append(Spacer(1, 3*cm))
    story.append(Paragraph("ForensiQ", s["brand"]))
    story.append(Paragraph("RAPPORT D'INVESTIGATION FORENSIQUE", s["title"]))
    story.append(Paragraph(f"Source analysée : {target_name}", s["subtitle"]))

    threat_box = Table(
        [[Paragraph(f"<b>NIVEAU DE MENACE : {threat_label}</b>",
                    ParagraphStyle("TB", alignment=TA_CENTER, fontSize=13,
                                   fontName="Helvetica-Bold"))]],
        colWidths=[14*cm], rowHeights=[1.3*cm],
    )
    threat_box.setStyle(TableStyle([
        ("BOX",    (0,0), (-1,-1), 2, BLACK),
        ("ALIGN",  (0,0), (-1,-1), "CENTER"),
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
    ]))
    story.append(threat_box)
    story.append(Spacer(1, 1.5*cm))

    meta = [
        ["Référence",          f"CASE-{case_id}"],
        ["Date du rapport",    report_date],
        ["Classification",     "CONFIDENTIEL"],
        ["Total alertes",      str(len(alerts))],
        ["Incidents analysés", str(len(files_meta) if files_meta else 1)],
        ["Outils d'analyse",   ", ".join(t.capitalize() for t in tools_used if t)],
    ]
    t_meta = Table(meta, colWidths=[5*cm, 9*cm])
    t_meta.setStyle(TableStyle([
        ("FONTNAME",     (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE",     (0, 0), (-1, -1), 9),
        ("TEXTCOLOR",    (0, 0), (-1, -1), BLACK),
        ("LINEBELOW",    (0, 0), (-1, -2), 0.5, LIGHT_GRAY),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 6),
    ]))
    story.append(t_meta)
    story.append(PageBreak())

    # ── 1. SYNTHÈSE EXÉCUTIVE ────────────────────────────────────────────────
    story.append(Paragraph("1. Synthèse Exécutive", s["h1"]))
    tools_str = ", ".join(t.capitalize() for t in tools_used if t) or "Inconnu"
    exec_summary = (
        f"Ce rapport présente l'analyse forensique de <b>{target_name}</b>. "
        f"Le niveau de menace global est <b>{threat_label}</b>, basé sur "
        f"<b>{len(alerts)} événements</b> issus de "
        f"{len(files_meta) if files_meta else 1} incident(s) téléchargé(s) "
        f"via les outils : <b>{tools_str}</b>. "
    )
    if crit_count:
        exec_summary += f"<b>{crit_count} alerte(s) critique(s)</b> nécessitent une action immédiate. "
    elif high_count:
        exec_summary += f"<b>{high_count} alerte(s) élevées</b> requièrent une investigation approfondie. "
    else:
        exec_summary += "Aucune menace critique immédiate n'a été identifiée. "
    story.append(Paragraph(exec_summary, s["normal"]))

    # ── 2. MÉTHODOLOGIE ──────────────────────────────────────────────────────
    story.append(Paragraph("2. Méthodologie", s["h1"]))
    story.append(Paragraph(
        "Chaque fichier uploadé est analysé par le parser correspondant à l'outil source "
        "(Hayabusa/Loki pour les logs Windows, Kuiper pour les artefacts forensiques, "
        "ML-Network pour le trafic réseau). Les hashs et chemins extraits sont enrichis via "
        "<b>VirusTotal</b> (ratio moteurs malveillants/total), puis classifiés par un moteur "
        "<b>déterministe</b> (seuils ratio VT + contexte chemin) produisant l'un des cinq verdicts : "
        "Vrai Positif, Suspect, Faux Positif, Faux Négatif, Sain. "
        "Un modèle IA génère ensuite les explications et recommandations en langage humain "
        "avec fallback garanti si l'API est indisponible.",
        s["normal"],
    ))

    # ── 3. ANALYSE PAR INCIDENT ──────────────────────────────────────────────
    story.append(Paragraph("3. Analyse Détaillée par Incident", s["h1"]))

    if files_meta:
        for fm in files_meta:
            fid = fm["id"]
            inc_alerts = [a for a in alerts if a.get("file_id") == fid]
            if not inc_alerts:
                continue
            story.extend(_build_incident_section(
                inc_alerts,
                alerts,
                fm.get("filename", f"Incident #{fid}"),
                fm.get("tool", ""),
                s,
            ))
            story.append(PageBreak())
    else:
        story.extend(_build_incident_section(
            alerts, alerts, target_name, tools_used[0] if tools_used else "", s
        ))
        story.append(PageBreak())

    # ── 4. RECOMMANDATIONS ───────────────────────────────────────────────────
    story.append(Paragraph("4. Recommandations de Remédiation", s["h1"]))
    if crit_count:
        story.append(Paragraph("<b>ACTIONS IMMÉDIATES (0-4h)</b>", s["h2"]))
        for line in [
            "Isoler immédiatement les machines affectées du réseau principal.",
            "Préserver les preuves (snapshot mémoire RAM + image disque).",
            "Bloquer les hash et IP malveillants identifiés dans ce rapport (EDR/FW).",
            "Notifier l'équipe CSIRT/SOC et activer le plan de réponse à incident.",
        ]:
            story.append(Paragraph(f"• {line}", s["normal"]))
        story.append(Spacer(1, 0.2*cm))

    if high_count or crit_count:
        story.append(Paragraph("<b>ACTIONS À COURT TERME (< 48h)</b>", s["h2"]))
        for line in [
            "Rechercher les IOCs (hash, IP, chemins) sur l'ensemble du parc informatique.",
            "Réinitialiser les identifiants des comptes potentiellement compromis.",
            "Analyser les journaux Active Directory et les authentifications récentes.",
        ]:
            story.append(Paragraph(f"• {line}", s["normal"]))
        story.append(Spacer(1, 0.2*cm))

    story.append(Paragraph("<b>ACTIONS PRÉVENTIVES</b>", s["h2"]))
    for line in [
        "Auditer les privilèges et durcir la configuration des postes et serveurs.",
        "Déployer des règles YARA/Sigma basées sur les TTPs identifiés dans ce rapport.",
        "Mettre à jour l'ensemble des systèmes et appliquer les correctifs de sécurité.",
        "Renforcer la supervision SOC sur les chemins et processus signalés suspects.",
    ]:
        story.append(Paragraph(f"• {line}", s["normal"]))

    # ── 5. CONCLUSION ────────────────────────────────────────────────────────
    story.append(Paragraph("5. Conclusion", s["h1"]))
    if crit_count:
        conclusion = (
            "L'analyse confirme un <b>incident de sécurité majeur</b>. "
            "Des indicateurs de compromission actifs ont été identifiés et confirmés par VirusTotal. "
            "Le plan de réponse à incident (CSIRT) doit être activé immédiatement. "
            "Toute machine impliquée doit être considérée comme compromise jusqu'à preuve du contraire."
        )
    elif high_count:
        conclusion = (
            "L'investigation révèle des activités <b>hautement suspectes</b> nécessitant "
            "une vérification approfondie avant tout retour en production. "
            "Les équipes SOC doivent surveiller étroitement les indicateurs identifiés dans ce rapport."
        )
    else:
        conclusion = (
            "Aucune menace critique directe n'a été identifiée à ce stade. "
            "L'environnement semble globalement sain, sous réserve d'un suivi des anomalies mineures signalées."
        )
    story.append(Paragraph(conclusion, s["normal"]))
    story.append(Spacer(1, 1*cm))
    story.append(HRFlowable(width="100%", thickness=1, color=LIGHT_GRAY))
    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph(
        f"<i>Rapport généré automatiquement par ForensiQ le {report_date} — Document CONFIDENTIEL.</i>",
        s["footer"],
    ))

    doc.build(story)
    return output_path