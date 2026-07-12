"""
ForensiQ Backend — API complète connectée à SQLite + Hayabusa + Loki +
module ML réseau + enrichissement VirusTotal + rapport PDF.

Lancer avec : uvicorn main:app --reload --port 8000
"""
import json
import os
import threading
from pathlib import Path
from typing import List, Optional

from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from sqlalchemy import func

from parsers.identifier import detect_tool
from parsers import loki_parser, hayabusa_parser, kuiper_parser
from network_analyzer import analyze_network_csv, is_network_csv
import pandas as pd
from threat_intel import enrich_alerts
from report_generator import generate_report
from ai_explainer import explain_alert
from database import init_db, get_db, SessionLocal, CaseFile, Alert
from typing import Optional

app = FastAPI(title="ForensiQ Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)

init_db()  # crée forensiq.db et les tables au démarrage si elles n'existent pas


@app.get("/")
def root():
    return {"message": "ForensiQ backend en ligne"}


# ─────────────────────────────────────────────────────────────────────────────
# Traitement réel du fichier — exécuté dans un thread séparé
# pour ne PAS bloquer uvicorn pendant l'analyse (peut durer plusieurs secondes).
# ─────────────────────────────────────────────────────────────────────────────
def _process_file_background(case_id: str, file_id: int, saved_path: str,
                              filename: str, tool: str, content: bytes):
    """
    Tourne dans un thread daemon. Ouvre sa propre session SQLAlchemy,
    insère les alertes au fur et à mesure, puis met à jour le statut.
    """
    db = SessionLocal()
    try:
        case_file = db.query(CaseFile).filter(CaseFile.id == file_id).first()
        if not case_file:
            return

        raw_alerts = []
        try:
            if tool == "hayabusa":
                raw_alerts = hayabusa_parser.parse_hayabusa_csv(content)
                # On limite l'enrichissement VT à 10 pour accélérer
                raw_alerts = enrich_alerts(raw_alerts, max_enrichments=10)
            elif tool == "loki":
                raw_alerts = loki_parser.parse_loki_log(content)
                raw_alerts = enrich_alerts(raw_alerts, max_enrichments=15)
            elif tool == "ml-network":
                raw_alerts = analyze_network_csv(saved_path)
            elif tool == "kuiper":
                if saved_path.endswith(".xlsx") or saved_path.endswith(".csv"):
                    try:
                        df = pd.read_excel(saved_path) if saved_path.endswith(".xlsx") else pd.read_csv(saved_path)
                        raw_alerts = kuiper_parser.parse_kuiper(df=df)
                    except Exception as e:
                        print(f"[Kuiper] Erreur de lecture pandas ({saved_path}): {e}")
                        raw_alerts = kuiper_parser.parse_kuiper(content=content)
                else:
                    raw_alerts = kuiper_parser.parse_kuiper(content=content)
            else:
                case_file.status = "unsupported"
                db.commit()
                return
        except Exception as e:
            print(f"[ForensiQ] Erreur lors du parsing : {e}")
            case_file.status = "error"
            db.commit()
            return

        # Insertion par batch de 100 pour ne pas surcharger SQLite
        BATCH = 100
        try:
            for i in range(0, len(raw_alerts), BATCH):
                batch = raw_alerts[i : i + BATCH]
                for a in batch:
                    # Protection contre des types bizarres qui font planter SQLite
                    target_val = a.get("target") or a.get("dst_ip") or ""
                    ts_val = a.get("timestamp")
                    
                    db.add(Alert(
                        case_id=case_id,
                        file_id=file_id,
                        tool=str(a.get("tool", tool))[:50],
                        severity=str(a.get("severity", "info"))[:20],
                        score=int(a.get("score", 0)) if str(a.get("score")).isdigit() else 0,
                        title=str(a.get("title", ""))[:255],
                        target=str(target_val)[:255],
                        details=str(a.get("details", ""))[:5000],
                        timestamp=str(ts_val) if ts_val else None,
                        event_id=str(a.get("event_id"))[:50] if a.get("event_id") else None,
                        channel=str(a.get("channel"))[:100] if a.get("channel") else None,
                        mitre_attack=str(a.get("mitre_attack"))[:100] if a.get("mitre_attack") else None,
                        record_id=str(a.get("record_id"))[:100] if a.get("record_id") else None,
                        rule_path=str(a.get("rule_path"))[:255] if a.get("rule_path") else None,
                        computer=str(a.get("computer"))[:100] if a.get("computer") else None,
                        file_path=str(a.get("file_path"))[:500] if a.get("file_path") else None,
                        raw_data=str(a.get("raw_data"))[:5000] if a.get("raw_data") else None,
                        src_ip=str(a.get("src_ip"))[:50] if a.get("src_ip") else None,
                        dst_ip=str(a.get("dst_ip"))[:50] if a.get("dst_ip") else None,
                        confidence=str(a.get("confidence"))[:20] if a.get("confidence") else None,
                        threat_intel=json.dumps(a["threat_intel"]) if a.get("threat_intel") else None,
                    ))
                db.commit()

            case_file.status = "parsed"
            case_file.alert_count = len(raw_alerts)
            db.commit()
            print(f"[ForensiQ] {filename} → {len(raw_alerts)} alertes insérées.")
            
        except Exception as e:
            print(f"[ForensiQ] Erreur insertion base de données ({filename}) : {e}")
            case_file.status = "error"
            db.commit()
            
    except Exception as e:
        print(f"[ForensiQ] Erreur inattendue globale : {e}")
        try:
            if case_file:
                case_file.status = "error"
                db.commit()
        except:
            pass
    finally:
        db.close()


# ─────────────────────────────────────────────────────────────────────────────
# 1. UPLOAD (réponse immédiate + traitement en arrière-plan)
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/cases/{case_id}/upload")
async def upload_file(case_id: str, file: UploadFile = File(...),
                      db: Session = Depends(get_db)):
    content = await file.read()

    saved_path = UPLOAD_DIR / f"{case_id}_{file.filename}"
    saved_path.write_bytes(content)

    # Détection du type (rapide)
    try:
        if is_network_csv(str(saved_path)):
            tool = "ml-network"
        else:
            tool = detect_tool(file.filename, content)
    except Exception:
        tool = detect_tool(file.filename, content)

    # Enregistrement immédiat en base avec status="processing"
    case_file = CaseFile(
        case_id=case_id,
        filename=file.filename,
        tool=tool,
        status="processing",
    )
    db.add(case_file)
    db.commit()
    db.refresh(case_file)
    file_id = case_file.id

    # Lancement du traitement dans un thread daemon — ne bloque PAS uvicorn
    t = threading.Thread(
        target=_process_file_background,
        args=(case_id, file_id, str(saved_path), file.filename, tool, content),
        daemon=True,
    )
    t.start()

    # Réponse immédiate : le frontend sait que l'analyse a commencé
    return {
        "filename": file.filename,
        "tool_detected": tool,
        "status": "processing",
        "file_id": file_id,
        "message": "Analyse lancée en arrière-plan. Interrogez /cases/{id}/files pour suivre la progression.",
    }


# ─────────────────────────────────────────────────────────────────────────────
# 1b. UPLOAD MULTIPLE (plusieurs fichiers en une seule requête)
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/cases/{case_id}/upload-multi")
async def upload_multiple_files(case_id: str, files: List[UploadFile] = File(...),
                                db: Session = Depends(get_db)):
    results = []
    for uploaded_file in files:
        content = await uploaded_file.read()
        saved_path = UPLOAD_DIR / f"{case_id}_{uploaded_file.filename}"
        saved_path.write_bytes(content)

        try:
            if is_network_csv(str(saved_path)):
                tool = "ml-network"
            else:
                tool = detect_tool(uploaded_file.filename, content)
        except Exception:
            tool = detect_tool(uploaded_file.filename, content)

        case_file = CaseFile(
            case_id=case_id,
            filename=uploaded_file.filename,
            tool=tool,
            status="processing",
        )
        db.add(case_file)
        db.commit()
        db.refresh(case_file)
        file_id = case_file.id

        t = threading.Thread(
            target=_process_file_background,
            args=(case_id, file_id, str(saved_path), uploaded_file.filename, tool, content),
            daemon=True,
        )
        t.start()

        results.append({
            "filename": uploaded_file.filename,
            "tool_detected": tool,
            "status": "processing",
            "file_id": file_id,
        })

    return {
        "count": len(results),
        "files": results,
        "message": f"{len(results)} fichier(s) envoyé(s) en analyse.",
    }


# ─────────────────────────────────────────────────────────────────────────────
# 2. STATUT RAPIDE (polling léger pendant l'analyse)
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/cases/{case_id}/status")
def get_status(case_id: str, db: Session = Depends(get_db)):
    """
    Endpoint ultra-léger : renvoie juste le statut de chaque fichier
    + le nombre d'alertes déjà insérées. Idéal pour le polling.
    """
    files = db.query(CaseFile).filter(CaseFile.case_id == case_id).all()
    alerts_count = db.query(func.count(Alert.id)).filter(Alert.case_id == case_id).scalar()
    processing = any(f.status == "processing" for f in files)
    return {
        "processing": processing,
        "alerts_so_far": alerts_count,
        "files": [
            {"id": f.id, "filename": f.filename, "status": f.status, "alert_count": f.alert_count or 0}
            for f in files
        ],
    }


def alert_to_dict(a: Alert, upload_filename: str = None) -> dict:
    d = {
        "id":           a.id,
        "file_id":      a.file_id,
        "tool":         a.tool,
        "severity":     a.severity,
        "score":        a.score,
        "title":        a.title,
        "target":       a.target,
        "file_path":    a.file_path or (
            a.target if a.target and ("\\" in a.target or "/" in a.target) else None
        ),
        "details":      a.details,
        "timestamp":    a.timestamp,
        "mitre_attack": a.mitre_attack,
        "src_ip":       a.src_ip,
        "dst_ip":       a.dst_ip,
        "confidence":   a.confidence,
        "computer":     a.computer,
        "explanation":  None,   # Sera enrichi à la demande via /explain-alert
        "threat_intel": json.loads(a.threat_intel) if a.threat_intel else None,
    }
    if upload_filename:
        d["upload_filename"] = upload_filename
    return d


# ─────────────────────────────────────────────────────────────────────────────
# 3. LISTE DES FICHIERS
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/cases/{case_id}/files")
def list_files(case_id: str, db: Session = Depends(get_db)):
    files = db.query(CaseFile).filter(CaseFile.case_id == case_id).all()
    return [
        {
            "id":          f.id,
            "filename":    f.filename,
            "tool":        f.tool,
            "status":      f.status,
            "alert_count": f.alert_count,
            "uploaded_at": f.uploaded_at.isoformat(),
        }
        for f in files
    ]


# ─────────────────────────────────────────────────────────────────────────────
# 4. STATS
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/cases/{case_id}/stats")
def get_stats(case_id: str, file_id: Optional[int] = None, db: Session = Depends(get_db)):
    file_query = db.query(CaseFile).filter(CaseFile.case_id == case_id)
    alert_query = db.query(Alert).filter(Alert.case_id == case_id)
    
    if file_id:
        file_query = file_query.filter(CaseFile.id == file_id)
        alert_query = alert_query.filter(Alert.file_id == file_id)

    files_count   = file_query.count()
    alerts_count  = alert_query.count()
    sources       = alert_query.with_entities(Alert.tool).distinct().count()
    iocs          = alert_query.filter(Alert.threat_intel.isnot(None)).count()
    processing    = file_query.filter(CaseFile.status == "processing").count()
    
    return {
        "files_analyzed": files_count,
        "alerts":         alerts_count,
        "iocs":           iocs,
        "artifacts":      alerts_count,
        "sources":        sources,
        "correlations":   0,
        "processing":     processing > 0,
    }


# ─────────────────────────────────────────────────────────────────────────────
# 5. ALERTES (avec limit + offset pour la pagination)
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/cases/{case_id}/alerts")
def get_alerts(
    case_id: str,
    file_id: Optional[int] = None,
    limit:  int = Query(default=300, le=2000),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
):
    query = db.query(Alert).filter(Alert.case_id == case_id)
    if file_id:
        query = query.filter(Alert.file_id == file_id)
        
    alerts = query.order_by(Alert.score.desc()).offset(offset).limit(limit).all()
    return [alert_to_dict(a) for a in alerts]


# ─────────────────────────────────────────────────────────────────────────────
# 5b. EXPLICATION IA D'UNE ALERTE
# ─────────────────────────────────────────────────────────────────────────────
from pydantic import BaseModel

class ExplainRequest(BaseModel):
    rule: str
    target: str = ""
    source: str = ""
    details: str = ""

@app.post("/explain-alert")
def explain_alert_endpoint(req: ExplainRequest):
    """Appelle l'IA (Gemini) pour expliquer une alerte en langage humain."""
    explanation = explain_alert(
        rule=req.rule,
        target=req.target,
        source=req.source,
        details=req.details
    )
    return {"explanation": explanation}


# ─────────────────────────────────────────────────────────────────────────────
# 5c. CLASSIFICATION IA D'UN IOC (Hash)
# ─────────────────────────────────────────────────────────────────────────────
from ai_explainer import classify_ioc_with_ai

class ClassifyIocRequest(BaseModel):
    hash_value: str
    file_path: str = ""
    vt_malicious: int = 0
    vt_total: int = 0
    vt_verdict: str = "unknown"
    tool: str = ""

@app.post("/classify-ioc")
def classify_ioc_endpoint(req: ClassifyIocRequest):
    """Classe un hash IOC via l'IA (vrai positif / faux positif / suspect / sain)."""
    result = classify_ioc_with_ai(
        hash_value=req.hash_value,
        file_path=req.file_path,
        vt_malicious=req.vt_malicious,
        vt_total=req.vt_total,
        vt_verdict=req.vt_verdict,
        tool=req.tool
    )
    return result


# ─────────────────────────────────────────────────────────────────────────────
# 6. DISTRIBUTION DE SÉVÉRITÉ
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/cases/{case_id}/severity-distribution")
def get_severity_distribution(case_id: str, file_id: Optional[int] = None, db: Session = Depends(get_db)):
    query = db.query(Alert.severity, func.count(Alert.id)).filter(Alert.case_id == case_id)
    if file_id:
        query = query.filter(Alert.file_id == file_id)
    rows = query.group_by(Alert.severity).all()
    counts = {sev: count for sev, count in rows}
    return [
        {"level": "Critical", "count": counts.get("critical", 0), "color": "#dc2626"},
        {"level": "High",     "count": counts.get("high",     0), "color": "#f97316"},
        {"level": "Medium",   "count": counts.get("medium",   0), "color": "#eab308"},
        {"level": "Low",      "count": counts.get("low",      0), "color": "#22c55e"},
    ]


# ─────────────────────────────────────────────────────────────────────────────
# 7. DISTRIBUTION PAR OUTIL
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/cases/{case_id}/tool-distribution")
def get_tool_distribution(case_id: str, file_id: Optional[int] = None, db: Session = Depends(get_db)):
    query = db.query(Alert.tool, func.count(Alert.id)).filter(Alert.case_id == case_id)
    if file_id:
        query = query.filter(Alert.file_id == file_id)
    rows = query.group_by(Alert.tool).all()
    return [{"tool": (tool or "unknown").capitalize(), "alerts": count} for tool, count in rows]


# ─────────────────────────────────────────────────────────────────────────────
# 8. CORRÉLATIONS (optimisées : groupement par heure en SQL)
# ─────────────────────────────────────────────────────────────────────────────
from dateutil import parser as date_parser

def _normalize_hour(ts_str: str) -> str:
    if not ts_str:
        return ""
    try:
        dt = date_parser.parse(str(ts_str), fuzzy=True)
        return dt.strftime("%Y-%m-%d %H")
    except:
        return str(ts_str)[:13]

@app.get("/cases/{case_id}/correlations")
def get_correlations(case_id: str, file_id: Optional[int] = None, db: Session = Depends(get_db)):
    """
    Moteur de corrélation multi-dimensionnel.
    Corrèle les alertes entre fichiers uploadés selon 5 axes :
      1. IP partagées (src_ip / dst_ip / target)
      2. Hashs partagés (threat_intel)
      3. Cibles communes (target / computer)
      4. Croisement inter-outils (même fichier cité par 2+ outils)
      5. Proximité temporelle (même fenêtre horaire)
    """
    import re
    from collections import defaultdict

    HASH_RE = re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b")
    IP_RE   = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    PRIVATE_IPS = {"127.0.0.1", "0.0.0.0", "255.255.255.255"}

    def _is_private(ip: str) -> bool:
        if ip in PRIVATE_IPS:
            return False  # exclude loopback but keep for correlation
        return False  # keep all IPs for correlation

    # ── Récupérer les alertes ──────────────────────────────────────────────
    q = db.query(Alert).filter(Alert.case_id == case_id)
    if file_id:
        # On garde TOUTES les alertes du case pour pouvoir croiser,
        # mais on marquera celles du fichier sélectionné
        pass
    all_alerts = q.order_by(Alert.id.desc()).limit(50000).all()

    if not all_alerts:
        return {
            "combined_risk_score": 0,
            "correlated_events": [],
            "total_host_alerts": 0,
            "total_network_alerts": 0,
            "correlation_types": [],
        }

    # ── Construire les index ──────────────────────────────────────────────
    # Chaque index mappe une clé (IP, hash, target) → liste d'alertes
    ip_index:     dict[str, list] = defaultdict(list)
    hash_index:   dict[str, list] = defaultdict(list)
    target_index: dict[str, list] = defaultdict(list)
    hour_index:   dict[str, list] = defaultdict(list)

    host_count = 0
    net_count = 0

    files_map = {f.id: f.filename for f in db.query(CaseFile).filter(CaseFile.case_id == case_id).all()}

    for a in all_alerts:
        is_host = a.tool in ("hayabusa", "loki", "kuiper", "autopsy")
        is_net  = a.tool == "ml-network"
        if is_host:
            host_count += 1
        if is_net:
            net_count += 1

        # 1. Index par IP
        ips_found = set()
        for ip_field in [a.src_ip, a.dst_ip, a.target, a.details]:
            if ip_field:
                for ip in IP_RE.findall(str(ip_field)):
                    if ip not in PRIVATE_IPS:
                        ips_found.add(ip)
        for ip in ips_found:
            ip_index[ip].append(a)

        # 2. Index par hash
        hashes_found = set()
        if a.threat_intel:
            try:
                ti = json.loads(a.threat_intel) if isinstance(a.threat_intel, str) else a.threat_intel
                if isinstance(ti, list):
                    for entry in ti:
                        if isinstance(entry, dict) and entry.get("value"):
                            v = entry["value"].strip()
                            if len(v) in (32, 40, 64):
                                hashes_found.add(v.lower())
            except:
                pass
        # Also extract hashes from details/raw_data
        for field in [a.details, a.target]:
            if field:
                for h in HASH_RE.findall(str(field)):
                    hashes_found.add(h.lower())
        for h in hashes_found:
            hash_index[h].append(a)

        # 3. Index par cible (fichier exécutable ou hostname)
        target_val = a.target or ""
        if target_val and len(target_val) > 3:
            # Normaliser : basename pour les chemins de fichiers
            if "\\" in target_val or "/" in target_val:
                basename = target_val.replace("\\", "/").split("/")[-1].lower()
                if basename and len(basename) > 3:
                    target_index[basename].append(a)
            else:
                target_index[target_val.lower().strip()].append(a)

        # 4. Index temporel
        if a.timestamp:
            hour = _normalize_hour(a.timestamp)
            if hour:
                hour_index[hour].append(a)

    # ── Générer les corrélations ──────────────────────────────────────────
    correlated_events = []
    seen_pairs = set()  # Éviter les doublons

    def _add_correlation(corr_type: str, key: str, alerts_list: list, risk: str = "high"):
        """Ajoute une corrélation si elle implique 2+ fichiers/outils différents."""
        # Grouper par file_id
        by_file = defaultdict(list)
        by_tool = defaultdict(list)
        for al in alerts_list:
            by_file[al.file_id].append(al)
            by_tool[al.tool].append(al)

        # Une corrélation nécessite 2+ fichiers OU 2+ outils
        if len(by_file) < 2 and len(by_tool) < 2:
            return

        # Clé de dédup
        pair_key = f"{corr_type}:{key}"
        if pair_key in seen_pairs:
            return
        seen_pairs.add(pair_key)

        # Construire l'événement de corrélation
        tools_involved = list(by_tool.keys())
        files_involved = [files_map.get(fid, f"File #{fid}") for fid in by_file.keys()]
        sample_alerts = alerts_list[:6]

        # Déterminer le risque
        severities = [al.severity for al in alerts_list if al.severity]
        if "critical" in severities:
            risk = "critical"
        elif "high" in severities:
            risk = "high"

        correlated_events.append({
            "type":            corr_type,
            "indicator":       key[:80],
            "host_event":      f"[{corr_type.upper()}] {key[:60]}",
            "risk":            risk,
            "tools":           tools_involved,
            "files":           files_involved,
            "alert_count":     len(alerts_list),
            "time_window":     ", ".join(sorted({_normalize_hour(al.timestamp) for al in sample_alerts if al.timestamp})) or "—",
            "network_events":  [
                f"{al.tool}: {(al.title or '')[:50]}" for al in sample_alerts
            ],
            "details": [
                {
                    "tool":     al.tool,
                    "title":    al.title or "",
                    "target":   al.target or "",
                    "severity": al.severity or "info",
                    "file":     files_map.get(al.file_id, ""),
                }
                for al in sample_alerts
            ],
        })

    # 1. Corrélations par IP
    for ip, alerts_list in ip_index.items():
        if len(alerts_list) >= 2:
            _add_correlation("ip", ip, alerts_list)

    # 2. Corrélations par Hash
    for h, alerts_list in hash_index.items():
        if len(alerts_list) >= 2:
            _add_correlation("hash", h, alerts_list, risk="critical")

    # 3. Corrélations par Cible
    for tgt, alerts_list in target_index.items():
        if len(alerts_list) >= 2:
            _add_correlation("target", tgt, alerts_list)

    # 4. Corrélations temporelles (cross-tool dans la même heure)
    for hour, alerts_list in hour_index.items():
        tools_in_hour = set(al.tool for al in alerts_list)
        if len(tools_in_hour) >= 2:
            _add_correlation("temporal", hour, alerts_list)

    # ── Trier par risque (critical > high > medium > low) puis par nombre d'alertes
    risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    correlated_events.sort(key=lambda c: (risk_order.get(c["risk"], 9), -c["alert_count"]))

    # Limiter à 50 corrélations max pour la perf
    correlated_events = correlated_events[:50]

    # Score combiné
    combined_score = sum(
        20 if c["risk"] == "critical" else 10 if c["risk"] == "high" else 5
        for c in correlated_events
    )

    return {
        "combined_risk_score":  combined_score,
        "correlated_events":    correlated_events,
        "total_host_alerts":    host_count,
        "total_network_alerts": net_count,
        "correlation_types":    list(set(c["type"] for c in correlated_events)),
    }


# ─────────────────────────────────────────────────────────────────────────────
# 9. RAPPORT JSON
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/cases/{case_id}/report")
def get_report(case_id: str, file_id: Optional[int] = None, db: Session = Depends(get_db)):
    q_alerts = db.query(Alert).filter(Alert.case_id == case_id)
    q_files = db.query(CaseFile).filter(CaseFile.case_id == case_id)
    
    if file_id:
        q_alerts = q_alerts.filter(Alert.file_id == file_id)
        q_files = q_files.filter(CaseFile.id == file_id)
        
    alerts = q_alerts.limit(500).all()
    files  = q_files.all()
    return {
        "case_id": case_id,
        "files":   [{"filename": f.filename, "tool": f.tool} for f in files],
        "alerts":  [alert_to_dict(a) for a in alerts],
    }


# ─────────────────────────────────────────────────────────────────────────────
# 10. RAPPORT PDF (Global)
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/cases/{case_id}/report/pdf")
def get_report_pdf(case_id: str, db: Session = Depends(get_db)):
    files = db.query(CaseFile).filter(CaseFile.case_id == case_id).all()
    files_map = {f.id: f.filename for f in files}
    # N'inclure que les fichiers correctement analysés
    files_meta = [
        {"id": f.id, "filename": f.filename, "tool": f.tool}
        for f in files if f.status in ("parsed", "done", "completed")
    ]
    if not files_meta:
        # Fallback : inclure tous les fichiers quand même
        files_meta = [{"id": f.id, "filename": f.filename, "tool": f.tool} for f in files]
    alerts = [
        alert_to_dict(a, upload_filename=files_map.get(a.file_id))
        for a in db.query(Alert).filter(Alert.case_id == case_id).limit(1000).all()
    ]
    stats = get_stats(case_id, db)

    os.makedirs("reports", exist_ok=True)
    output_path = f"reports/{case_id}_report.pdf"
    if os.path.exists(output_path):
        return FileResponse(output_path, media_type="application/pdf",
                            filename=f"forensiq_{case_id}_report.pdf")
    generate_report(case_id, alerts, stats, output_path, files_meta=files_meta)

    return FileResponse(output_path, media_type="application/pdf",
                        filename=f"forensiq_{case_id}_report.pdf")


# ─────────────────────────────────────────────────────────────────────────────
# 11. RAPPORT PDF (Spécifique à un fichier)
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/cases/{case_id}/files/{file_id}/report/pdf")
def get_file_report_pdf(case_id: str, file_id: int, db: Session = Depends(get_db)):
    file_obj = db.query(CaseFile).filter(CaseFile.id == file_id, CaseFile.case_id == case_id).first()
    if not file_obj:
        raise HTTPException(status_code=404, detail="Fichier introuvable")

    # On récupère en priorité TOUTES les alertes de CE fichier
    file_alerts_query = db.query(Alert).filter(Alert.case_id == case_id, Alert.file_id == file_id).all()
    # On prend un gros échantillon des dernières alertes pour corréler les fichiers récemment uploadés
    q = db.query(Alert).filter(Alert.case_id == case_id).order_by(Alert.id.desc()).limit(50000)
    alerts = q.all()
    
    alerts_query = file_alerts_query + alerts

    # files_map pour résoudre les noms de fichiers
    files = db.query(CaseFile).filter(CaseFile.case_id == case_id).all()
    files_map = {f.id: f.filename for f in files}
    alerts = [alert_to_dict(a, upload_filename=files_map.get(a.file_id)) for a in alerts_query]
    
    # Mais on ne génère le rapport QUE pour ce fichier spécifique
    files_meta = [{"id": file_obj.id, "filename": file_obj.filename, "tool": file_obj.tool}]
    
    # Fake stats spécifiques au fichier si nécessaire par le générateur
    stats = {
        "files_analyzed": 1,
        "alerts": len(alerts),
    }

    os.makedirs("reports", exist_ok=True)
    output_path = f"reports/{case_id}_file_{file_id}_report.pdf"
    if os.path.exists(output_path):
        return FileResponse(output_path, media_type="application/pdf",
                            filename=f"forensiq_{file_obj.filename}_report.pdf")
    generate_report(case_id, alerts, stats, output_path, filename=file_obj.filename, files_meta=files_meta)

    return FileResponse(output_path, media_type="application/pdf",
                        filename=f"forensiq_{file_obj.filename}_report.pdf")

# ─────────────────────────────────────────────────────────────────────────────
# 12. VIRUSTOTAL DYNAMIQUE
# ─────────────────────────────────────────────────────────────────────────────
from threat_intel import enrich_hash, enrich_ip

@app.get("/vt/hash/{hash_val}")
def check_hash_vt(hash_val: str):
    res = enrich_hash(hash_val)
    if not res:
        return {"error": "VT API non configurée"}
    return res

@app.get("/vt/ip/{ip_val}")
def check_ip_vt(ip_val: str):
    res = enrich_ip(ip_val)
    if not res:
        return {"error": "VT API non configurée"}
    return res