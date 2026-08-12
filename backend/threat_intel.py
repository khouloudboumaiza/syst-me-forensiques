"""
threat_intel.py
-----------------
Enrichit les alertes Hayabusa avec des données de threat intelligence
via l'API gratuite VirusTotal (v3).

Quota gratuit VirusTotal : 4 requêtes/minute, 500/jour. Le module respecte
ce quota avec un throttle automatique et un cache pour ne jamais interroger
deux fois le même hash/IP.

Configuration :
    set VT_API_KEY=votre_cle_virustotal   (PowerShell : $env:VT_API_KEY="...")
"""

import os
import re
import time
import requests
VT_API_KEY = "6379530ccb506878d88036bd1b2becd120a6eb43b20807010786fb08b873a5ef"
VT_BASE_URL = "https://www.virustotal.com/api/v3"

_cache: dict[str, dict] = {}
_rate_limited_until = 0


HASH_PATTERN = re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b")
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

def _query_vt(endpoint: str, resource: str) -> dict | None:
    global _rate_limited_until
    if not VT_API_KEY:
        return None
    if resource in _cache:
        return _cache[resource]
        
    if time.time() < _rate_limited_until:
        return None  # On skip instantanément si le quota VT a été atteint récemment

    try:
        resp = requests.get(
            f"{VT_BASE_URL}/{endpoint}/{resource}",
            headers={"x-apikey": VT_API_KEY},
            timeout=5,
        )
        if resp.status_code == 200:
            data = resp.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            result = {
                "found": True,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "verdict": "malicious" if stats.get("malicious", 0) > 0 else "clean",
            }
        elif resp.status_code == 429:
            # Quota dépassé (4 req/min), on bloque les appels pendant 60 secondes 
            # pour ne pas ralentir le traitement des fichiers
            _rate_limited_until = time.time() + 60
            return None
        elif resp.status_code == 404:
            result = {"found": False, "verdict": "unknown"}
        else:
            result = {"found": False, "verdict": "error", "status_code": resp.status_code}
            
        _cache[resource] = result
        return result
    except requests.RequestException as e:
        result = {"found": False, "verdict": "error", "error": str(e)}
        _cache[resource] = result
        return result


def enrich_hash(file_hash: str) -> dict | None:
    """Vérifie un hash de fichier (MD5/SHA1/SHA256) sur VirusTotal."""
    return _query_vt("files", file_hash)


def enrich_ip(ip: str) -> dict | None:
    """Vérifie une adresse IP sur VirusTotal."""
    return _query_vt("ip_addresses", ip)


def extract_indicators(text: str) -> dict:
    """Extrait les hashs et IPs présents dans un champ texte (ex: 'details')."""
    return {
        "hashes": list(set(HASH_PATTERN.findall(text or ""))),
        "ips": list(set(IP_PATTERN.findall(text or ""))),
    }


def enrich_alerts(alerts: list[dict], max_enrichments: int = 20) -> list[dict]:
    """
    Enrichit une liste d'alertes avec les résultats VirusTotal.
    Limité à max_enrichments par upload pour respecter le quota gratuit
    (20 alertes x ~16s = ~5min max par fichier analysé).
    """
    if not VT_API_KEY:
        print("VT_API_KEY non définie — enrichissement threat intel désactivé.")
        return alerts

    enriched_count = 0
    for alert in alerts:
        if enriched_count >= max_enrichments:
            break

        # Hashes déjà extraits par le parser (ex: Loki MD5/SHA256)
        existing_ti = alert.get("threat_intel") or []
        if isinstance(existing_ti, list):
            updated_ti = []
            for entry in existing_ti:
                if entry.get("type") == "hash" and entry.get("value") and not entry.get("found"):
                    if enriched_count >= max_enrichments:
                        updated_ti.append(entry)
                        continue
                    r = enrich_hash(entry["value"])
                    if r:
                        updated_ti.append({"type": "hash", "value": entry["value"], **r})
                        if r.get("found"):
                            enriched_count += 1
                    else:
                        updated_ti.append(entry)
                else:
                    updated_ti.append(entry)
            if updated_ti:
                alert["threat_intel"] = updated_ti

        indicators = extract_indicators(
            (alert.get("details") or "") + " " + (alert.get("raw_data") or "") + " " + (alert.get("target") or "")
        )
        threat_info = list(alert.get("threat_intel") or [])
        existing_values = {t.get("value") for t in threat_info if t.get("value")}

        for h in indicators["hashes"][:1]:
            if h in existing_values:
                continue
            if enriched_count >= max_enrichments:
                break
            r = enrich_hash(h)
            if r and r.get("found"):
                threat_info.append({"type": "hash", "value": h, **r})
                enriched_count += 1

        for ip in indicators["ips"][:1]:
            if ip in existing_values:
                continue
            if enriched_count >= max_enrichments:
                break
            r = enrich_ip(ip)
            if r and r.get("found"):
                threat_info.append({"type": "ip", "value": ip, **r})
                enriched_count += 1

        if threat_info:
            alert["threat_intel"] = threat_info
            if any(t.get("verdict") == "malicious" for t in threat_info):
                alert["severity"] = "critical"
                alert["score"] = 100

    return alerts