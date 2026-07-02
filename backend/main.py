"""
ForensiQ Backend — API complète connectée à SQLite + Hayabusa + Loki +
module ML réseau + enrichissement VirusTotal + rapport PDF.

Lancer avec : uvicorn main:app --reload --port 8000
"""
import json
import os
from pathlib import Path

from fastapi import FastAPI, UploadFile, File, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from sqlalchemy import func

from parsers.identifier import detect_tool
from parsers import loki_parser, hayabusa_parser
from network_analyzer import analyze_network_csv, is_network_csv
from threat_intel import enrich_alerts
from report_generator import generate_report
from database import init_db, get_db, CaseFile, Alert

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


# ---------- 1. UPLOAD ----------
@app.post("/cases/{case_id}/upload")
async def upload_file(case_id: str, file: UploadFile = File(...), db: Session = Depends(get_db)):
    content = await file.read()

    saved_path = UPLOAD_DIR / f"{case_id}_{file.filename}"
    saved_path.write_bytes(content)

    # Le module réseau est vérifié en premier : il sait reconnaître ses
    # propres colonnes de façon fiable (retourne False si le modèle n'est
    # pas encore entraîné, donc sans danger si vous n'avez pas fait cette
    # partie).
    if is_network_csv(str(saved_path)):
        tool = "ml-network"
    else:
        tool = detect_tool(file.filename, content)

    case_file = CaseFile(case_id=case_id, filename=file.filename, tool=tool, status="processing")
    db.add(case_file)
    db.commit()
    db.refresh(case_file)

    raw_alerts = []
    try:
        if tool == "hayabusa":
            raw_alerts = hayabusa_parser.parse_hayabusa_csv(content)
            raw_alerts = enrich_alerts(raw_alerts, max_enrichments=20)
        elif tool == "loki":
            raw_alerts = loki_parser.parse_loki_log(content)
        elif tool == "ml-network":
            raw_alerts = analyze_network_csv(str(saved_path))
        else:
            case_file.status = "unsupported"
            db.commit()
            return {
                "filename": file.filename,
                "tool_detected": tool,
                "alerts_extracted": 0,
                "note": "Format non reconnu.",
            }
    except Exception as e:
        case_file.status = "error"
        db.commit()
        raise HTTPException(500, f"Erreur d'analyse : {e}")

    for a in raw_alerts:
        db.add(Alert(
            case_id=case_id,
            file_id=case_file.id,
            tool=a.get("tool", tool),
            severity=a.get("severity", "info"),
            score=a.get("score", 0),
            title=a.get("title", ""),
            target=a.get("target") or a.get("dst_ip") or "",
            details=a.get("details", ""),
            timestamp=a.get("timestamp"),
            event_id=a.get("event_id"),
            channel=a.get("channel"),
            mitre_attack=a.get("mitre_attack"),
            record_id=a.get("record_id"),
            rule_path=a.get("rule_path"),
            computer=a.get("computer"),
            file_path=a.get("file_path"),
            raw_data=a.get("raw_data"),
            src_ip=a.get("src_ip"),
            dst_ip=a.get("dst_ip"),
            confidence=a.get("confidence"),
            threat_intel=json.dumps(a["threat_intel"]) if a.get("threat_intel") else None,
        ))

    case_file.status = "parsed"
    case_file.alert_count = len(raw_alerts)
    db.commit()

    return {"filename": file.filename, "tool_detected": tool, "alerts_extracted": len(raw_alerts)}


def alert_to_dict(a: Alert) -> dict:
    return {
        "id": a.id,
        "tool": a.tool,
        "severity": a.severity,
        "score": a.score,
        "title": a.title,
        "target": a.target,
        "details": a.details,
        "timestamp": a.timestamp,
        "mitre_attack": a.mitre_attack,
        "src_ip": a.src_ip,
        "dst_ip": a.dst_ip,
        "confidence": a.confidence,
        "threat_intel": json.loads(a.threat_intel) if a.threat_intel else None,
    }


@app.get("/cases/{case_id}/files")
def list_files(case_id: str, db: Session = Depends(get_db)):
    files = db.query(CaseFile).filter(CaseFile.case_id == case_id).all()
    return [
        {
            "id": f.id,
            "filename": f.filename,
            "tool": f.tool,
            "status": f.status,
            "alert_count": f.alert_count,
            "uploaded_at": f.uploaded_at.isoformat(),
        }
        for f in files
    ]


# ---------- 2. STATS ----------
@app.get("/cases/{case_id}/stats")
def get_stats(case_id: str, db: Session = Depends(get_db)):
    files_count = db.query(CaseFile).filter(CaseFile.case_id == case_id).count()
    alerts_count = db.query(Alert).filter(Alert.case_id == case_id).count()
    sources = db.query(Alert.tool).filter(Alert.case_id == case_id).distinct().count()
    iocs = db.query(Alert).filter(Alert.case_id == case_id, Alert.threat_intel.isnot(None)).count()
    return {
        "files_analyzed": files_count,
        "alerts": alerts_count,
        "iocs": iocs,
        "artifacts": alerts_count,
        "sources": sources,
        "correlations": 0,
    }


# ---------- 3. ALERTS ----------
@app.get("/cases/{case_id}/alerts")
def get_alerts(case_id: str, db: Session = Depends(get_db)):
    alerts = db.query(Alert).filter(Alert.case_id == case_id).order_by(Alert.score.desc()).all()
    return [alert_to_dict(a) for a in alerts]


# ---------- 4. SEVERITY DISTRIBUTION ----------
@app.get("/cases/{case_id}/severity-distribution")
def get_severity_distribution(case_id: str, db: Session = Depends(get_db)):
    rows = (
        db.query(Alert.severity, func.count(Alert.id))
        .filter(Alert.case_id == case_id)
        .group_by(Alert.severity)
        .all()
    )
    counts = {sev: count for sev, count in rows}
    return [
        {"level": "Critical", "count": counts.get("critical", 0), "color": "#dc2626"},
        {"level": "High", "count": counts.get("high", 0), "color": "#f97316"},
        {"level": "Medium", "count": counts.get("medium", 0), "color": "#eab308"},
        {"level": "Low", "count": counts.get("low", 0), "color": "#22c55e"},
    ]


# ---------- 5. TOOL DISTRIBUTION ----------
@app.get("/cases/{case_id}/tool-distribution")
def get_tool_distribution(case_id: str, db: Session = Depends(get_db)):
    rows = (
        db.query(Alert.tool, func.count(Alert.id))
        .filter(Alert.case_id == case_id)
        .group_by(Alert.tool)
        .all()
    )
    return [{"tool": (tool or "unknown").capitalize(), "alerts": count} for tool, count in rows]


# ---------- 6. CORRELATIONS ----------
@app.get("/cases/{case_id}/correlations")
def get_correlations(case_id: str, db: Session = Depends(get_db)):
    host_alerts = db.query(Alert).filter(Alert.case_id == case_id, Alert.tool.in_(["hayabusa", "loki"])).all()
    network_alerts = db.query(Alert).filter(Alert.case_id == case_id, Alert.tool == "ml-network").all()

    combined_score = 0
    correlated_events = []
    for h in host_alerts:
        h_hour = (h.timestamp or "")[:13]
        matches = [n for n in network_alerts if h_hour and (n.timestamp or "")[:13] == h_hour]
        if matches:
            correlated_events.append({
                "host_event": h.title,
                "network_events": [n.title for n in matches],
                "time_window": h_hour,
                "risk": "critical",
            })
            combined_score += 10
        else:
            combined_score += 1

    return {
        "combined_risk_score": combined_score,
        "correlated_events": correlated_events,
        "total_host_alerts": len(host_alerts),
        "total_network_alerts": len(network_alerts),
    }


# ---------- 7. RAPPORT JSON ----------
@app.get("/cases/{case_id}/report")
def get_report(case_id: str, db: Session = Depends(get_db)):
    alerts = db.query(Alert).filter(Alert.case_id == case_id).all()
    files = db.query(CaseFile).filter(CaseFile.case_id == case_id).all()
    return {
        "case_id": case_id,
        "files": [{"filename": f.filename, "tool": f.tool} for f in files],
        "alerts": [alert_to_dict(a) for a in alerts],
    }


# ---------- 8. RAPPORT PDF ----------
@app.get("/cases/{case_id}/report/pdf")
def get_report_pdf(case_id: str, db: Session = Depends(get_db)):
    alerts = [alert_to_dict(a) for a in db.query(Alert).filter(Alert.case_id == case_id).all()]
    stats = get_stats(case_id, db)

    os.makedirs("reports", exist_ok=True)
    output_path = f"reports/{case_id}_report.pdf"
    generate_report(case_id, alerts, stats, output_path)

    return FileResponse(output_path, media_type="application/pdf", filename=f"forensiq_{case_id}_report.pdf")