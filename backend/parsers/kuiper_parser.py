"""
kuiper_parser.py
Parser pour les exports de la plateforme Kuiper.
Gère les données JSON et les DataFrames pandas (si extrait d'un CSV/XLSX).
"""
import json
import pandas as pd

def parse_kuiper(content: bytes = None, df: pd.DataFrame = None) -> list[dict]:
    alerts = []
    
    # 1. Parsing via DataFrame (CSV/XLSX pré-chargé)
    if df is not None:
        # Convertir le dataframe en liste de dicts
        records = df.to_dict(orient="records")
        for idx, row in enumerate(records):
            # Tente de trouver les colonnes typiques de Kuiper
            title = row.get("msg") or row.get("message") or row.get("title") or row.get("artifact") or row.get("description") or "Événement Kuiper"
            severity = row.get("level") or row.get("severity") or row.get("risk") or "info"
            target = row.get("host") or row.get("computer") or row.get("target") or row.get("source") or ""
            timestamp = row.get("timestamp") or row.get("date") or row.get("@timestamp")
            
            # Normalisation de la sévérité
            sev = str(severity).lower()
            if "crit" in sev or "high" in sev or "3" in sev or "elev" in sev:
                sev = "high"
            elif "med" in sev or "2" in sev or "warn" in sev or "moyen" in sev:
                sev = "medium"
            elif "low" in sev or "1" in sev or "faibl" in sev:
                sev = "low"
            else:
                sev = "info"
                
            alert = {
                "tool": "kuiper",
                "severity": sev,
                "title": str(title),
                "target": str(target),
                "timestamp": str(timestamp) if pd.notna(timestamp) else None,
                "details": str({k:v for k,v in row.items() if pd.notna(v)})[:1000], # Garde le contexte brut, vire les NaN
                "threat_intel": []
            }
            # Extract basic hashes if present in columns
            hashes = []
            for k, v in row.items():
                k_lower = str(k).lower()
                if pd.notna(v) and isinstance(v, str) and ("md5" in k_lower or "sha1" in k_lower or "sha256" in k_lower or "hash" in k_lower):
                    # verifier que ca ressemble a un hash (longueur hexa)
                    v_clean = v.strip()
                    if len(v_clean) in (32, 40, 64) and all(c in "0123456789abcdefABCDEF" for c in v_clean):
                        hashes.append({"type": "hash", "value": v_clean, "source": "kuiper_excel"})
            alert["threat_intel"] = hashes
            
            alerts.append(alert)
        return alerts

    # 2. Parsing via JSON Brut
    if content:
        try:
            data = json.loads(content)
            # Kuiper exporte souvent une liste d'objets
            if not isinstance(data, list):
                data = [data]
                
            for item in data:
                if not isinstance(item, dict):
                    continue
                
                title = item.get("msg") or item.get("message") or item.get("artifact") or item.get("name") or "Événement Kuiper"
                severity = item.get("level") or item.get("severity") or item.get("risk") or "info"
                target = item.get("host") or item.get("computer") or item.get("target") or item.get("source") or ""
                timestamp = item.get("timestamp") or item.get("@timestamp") or item.get("date")
                
                sev = str(severity).lower()
                if "crit" in sev or "high" in sev or "3" in sev or "elev" in sev:
                    sev = "high"
                elif "med" in sev or "warn" in sev or "2" in sev or "moyen" in sev:
                    sev = "medium"
                elif "low" in sev or "1" in sev or "faibl" in sev:
                    sev = "low"
                else:
                    sev = "info"
                    
                alert = {
                    "tool": "kuiper",
                    "severity": sev,
                    "title": str(title),
                    "target": str(target),
                    "timestamp": str(timestamp) if timestamp else None,
                    "details": json.dumps(item)[:1000],
                    "threat_intel": []
                }
                
                # Check for hashes
                hashes = []
                for k, v in item.items():
                    k_lower = str(k).lower()
                    if isinstance(v, str) and ("md5" in k_lower or "sha1" in k_lower or "sha256" in k_lower or "hash" in k_lower):
                        v_clean = v.strip()
                        if len(v_clean) in (32, 40, 64) and all(c in "0123456789abcdefABCDEF" for c in v_clean):
                            hashes.append({"type": "hash", "value": v_clean, "source": "kuiper_json"})
                alert["threat_intel"] = hashes
                
                alerts.append(alert)
        except Exception as e:
            print(f"[Kuiper Parser] Erreur JSON parsing: {e}")
            
    return alerts
