"""
Parse les fichiers CSV produits par Hayabusa (csv-timeline).
Colonnes réelles observées :
Timestamp,Computer,Channel,EventID,Level,MitreAttack,RecordID,RuleTitle,Details,RulePath,FilePath
(l'ordre/le nombre de colonnes peut varier légèrement selon la version -> on utilise DictReader)
"""
import csv
import io

LEVEL_MAP = {
    "crit": "critical",
    "critical": "critical",
    "high": "high",
    "med": "medium",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "informational": "info",
}

LEVEL_SCORE = {
    "critical": 100,
    "high": 80,
    "medium": 50,
    "low": 20,
    "info": 5,
}


def parse_hayabusa_csv(raw_bytes: bytes) -> list[dict]:
    text = raw_bytes.decode("utf-8", errors="ignore")
    reader = csv.DictReader(io.StringIO(text))
    alerts = []

    for row in reader:
        # Les noms de colonnes varient un peu selon la version d'Hayabusa,
        # donc on cherche insensible à la casse.
        row_lower = {k.lower(): v for k, v in row.items() if k}

        level_raw = (row_lower.get("level") or "info").strip().lower()
        severity = LEVEL_MAP.get(level_raw, "info")

        rule_title = row_lower.get("ruletitle") or "Unknown rule"
        details = row_lower.get("details") or ""
        computer = row_lower.get("computer") or ""
        file_path = row_lower.get("filepath") or row_lower.get("evtxfile") or ""
        timestamp = row_lower.get("timestamp") or ""

        alerts.append({
            "tool": "hayabusa",
            "severity": severity,
            "score": LEVEL_SCORE.get(severity, 5),
            "title": rule_title,
            "target": computer or file_path,
            "details": details,
            "timestamp": timestamp,
        })

    return alerts
