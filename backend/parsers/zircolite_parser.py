"""
Parse les fichiers JSON et CSV produits par Zircolite.
Zircolite utilise des règles Sigma pour générer des alertes depuis des EVTX.
"""
import csv
import io
import json

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


def parse_zircolite(raw_bytes: bytes) -> list[dict]:
    """Parse le contenu Zircolite, essaie d'abord JSON, puis CSV."""
    text = raw_bytes.decode("utf-8", errors="ignore")
    text_stripped = text.strip()
    
    if text_stripped.startswith("{") or text_stripped.startswith("["):
        try:
            return parse_zircolite_json(text_stripped)
        except Exception:
            pass
            
    # Si ce n'est pas du JSON ou si l'analyse JSON a échoué, on tente le CSV
    return parse_zircolite_csv(text)


def parse_zircolite_json(text: str) -> list[dict]:
    data = json.loads(text)
    alerts = []
    
    # Zircolite peut renvoyer soit une liste d'alertes, soit un dict contenant une liste (ex: dans 'matches' ou autre)
    if isinstance(data, dict):
        # Chercher une clé contenant une liste (souvent 'matches' ou 'alerts')
        for k, v in data.items():
            if isinstance(v, list) and v and isinstance(v[0], dict):
                data = v
                break
        if not isinstance(data, list):
            data = [data] # Fallback si c'est un seul objet
            
    for item in data:
        if not isinstance(item, dict):
            continue
            
        level_raw = (item.get("level") or "info").lower().strip()
        severity = LEVEL_MAP.get(level_raw, "info")
        
        title = item.get("title") or item.get("rule") or "Zircolite Alert"
        description = item.get("description") or ""
        
        # Extraction du timestamp, target (computer/IP) depuis le match si présent
        matches = item.get("matches", [])
        if not isinstance(matches, list):
            matches = [matches]
            
        timestamp = item.get("timestamp") or ""
        target = item.get("computer") or ""
        
        # S'il n'y a pas de cible à la racine, on cherche dans le premier match
        if matches and isinstance(matches[0], dict):
            first_match = matches[0]
            if not target:
                target = first_match.get("Computer") or first_match.get("computer") or ""
                # Si imbriqué dans System
                if not target and isinstance(first_match.get("System"), dict):
                    target = first_match["System"].get("Computer") or ""
                    
            if not timestamp:
                timestamp = first_match.get("TimeCreated") or first_match.get("timestamp") or ""
                if not timestamp and isinstance(first_match.get("System"), dict):
                    tc = first_match["System"].get("TimeCreated")
                    if isinstance(tc, dict):
                        timestamp = tc.get("SystemTime") or ""
                    else:
                        timestamp = str(tc)
                        
            # Ajouter les données d'événement aux détails
            if not description:
                description = str(first_match.get("EventData", first_match))
        
        alerts.append({
            "tool": "zircolite",
            "severity": severity,
            "score": LEVEL_SCORE.get(severity, 5),
            "title": title,
            "target": target,
            "details": description,
            "timestamp": str(timestamp),
        })
        
    return alerts


def parse_zircolite_csv(text: str) -> list[dict]:
    reader = csv.DictReader(io.StringIO(text))
    alerts = []

    for row in reader:
        row_lower = {k.lower(): v for k, v in row.items() if k}

        level_raw = (row_lower.get("level") or "info").strip().lower()
        severity = LEVEL_MAP.get(level_raw, "info")

        rule_title = row_lower.get("title") or row_lower.get("rule") or "Zircolite Alert"
        details = row_lower.get("description") or row_lower.get("matches") or ""
        computer = row_lower.get("computer") or row_lower.get("system.computer") or ""
        timestamp = row_lower.get("timestamp") or row_lower.get("timecreated") or ""

        alerts.append({
            "tool": "zircolite",
            "severity": severity,
            "score": LEVEL_SCORE.get(severity, 5),
            "title": rule_title,
            "target": computer,
            "details": details,
            "timestamp": timestamp,
        })

    return alerts
