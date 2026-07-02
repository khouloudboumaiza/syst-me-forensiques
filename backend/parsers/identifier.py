"""
Identification automatique de l'outil source d'un fichier uploadé.
Etape 5.2 du cahier des charges.
"""
import json

# Colonnes caractéristiques d'un CSV de flux réseau (CICIDS2017 / UNSW-NB15)
NETWORK_FLOW_MARKERS = [
    "flow duration", "flow bytes/s", "total fwd packets",
    "src ip", "dst ip", "sbytes", "dbytes", "dur",
]


def detect_tool(filename: str, content: bytes) -> str:
    """Retourne 'loki' | 'hayabusa' | 'ml-network' | 'autopsy' | 'kuiper' | 'unknown'"""
    name = filename.lower()
    try:
        text = content[:20000].decode("utf-8", errors="ignore")
    except Exception:
        text = ""

    # 1. Indices sur le nom de fichier
    if "hayabusa" in name:
        return "hayabusa"
    if "loki" in name:
        return "loki"
    if "autopsy" in name:
        return "autopsy"
    if "kuiper" in name:
        return "kuiper"

    lowered = text.lower()

    # 2. CSV de flux réseau (CICIDS2017 / UNSW-NB15) : vérifié AVANT hayabusa
    # car ce sont aussi des CSV et il faut les distinguer en premier.
    if name.endswith(".csv"):
        header_line = lowered.splitlines()[0] if lowered.splitlines() else ""
        marker_hits = sum(1 for m in NETWORK_FLOW_MARKERS if m in header_line)
        if marker_hits >= 2:
            return "ml-network"

    # 3. Hayabusa: colonnes caractéristiques CSV/JSONL
    if "ruletitle" in lowered and ("timestamp" in lowered or "computer" in lowered):
        return "hayabusa"
    if "mitretactics" in lowered:
        return "hayabusa"

    # 4. Loki: mots-clés d'alertes
    if "alert:" in lowered or "yara" in lowered or "iocmatch" in lowered:
        return "loki"

    # 5. Autopsy
    if "blackboard_artifacts" in lowered or "autopsy" in lowered:
        return "autopsy"

    # 6. Kuiper: JSON d'événements corrélés
    if name.endswith(".json"):
        try:
            data = json.loads(content)
            if isinstance(data, list) and data and isinstance(data[0], dict):
                keys = set(data[0].keys())
                if {"artifact", "correlation_id"} & keys:
                    return "kuiper"
        except Exception:
            pass

    return "unknown"