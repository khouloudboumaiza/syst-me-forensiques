"""
network_analyzer.py
--------------------
Charge le modèle entraîné (network_ids_model.pkl) et analyse un fichier CSV
de flux réseau uploadé par l'utilisateur. Retourne une liste d'alertes au
même format que vos alertes Hayabusa/Loki, pour insertion en base.

À placer dans votre dossier backend, à côté de hayabusa_parser.py et loki_parser.py.
"""

import os
import joblib
import pandas as pd

MODEL_DIR = os.environ.get("ML_MODEL_DIR", "./model")

_model = None
_features = None


def _load_model():
    global _model, _features
    if _model is None:
        _model = joblib.load(os.path.join(MODEL_DIR, "network_ids_model.pkl"))
        _features = joblib.load(os.path.join(MODEL_DIR, "model_features.pkl"))
    return _model, _features


# Colonnes possibles pour IP source/destination et timestamp selon le dataset
IP_SRC_CANDIDATES = ["Src IP", "Source IP", "srcip", "src_ip"]
IP_DST_CANDIDATES = ["Dst IP", "Destination IP", "dstip", "dst_ip"]
TS_CANDIDATES = ["Timestamp", "timestamp", "Stime", "flow_start"]


def _find_col(df, candidates):
    for c in candidates:
        if c in df.columns:
            return c
    return None


def is_network_csv(filepath: str) -> bool:
    """Détection rapide : ce CSV a-t-il les colonnes attendues d'un dataset de flux réseau ?"""
    try:
        sample = pd.read_csv(filepath, nrows=5, encoding="latin1")
        sample.columns = sample.columns.str.strip()
        _, features = _load_model()
        overlap = set(features) & set(sample.columns)
        return len(overlap) > (len(features) * 0.5)  # au moins 50% des features présentes
    except Exception:
        return False


def analyze_network_csv(filepath: str) -> list[dict]:
    """
    Analyse le fichier et retourne uniquement les lignes classées ATTACK,
    sous forme de liste de dicts prêts à insérer en base.
    """
    model, features = _load_model()

    df = pd.read_csv(filepath, encoding="latin1", low_memory=False)
    df.columns = df.columns.str.strip()

    src_col = _find_col(df, IP_SRC_CANDIDATES)
    dst_col = _find_col(df, IP_DST_CANDIDATES)
    ts_col = _find_col(df, TS_CANDIDATES)

    missing = [f for f in features if f not in df.columns]
    for f in missing:
        df[f] = 0  # colonnes absentes -> valeur neutre

    X = df[features].apply(pd.to_numeric, errors="coerce").fillna(0)
    X = X.replace([float("inf"), float("-inf")], 0)

    predictions = model.predict(X)
    probabilities = model.predict_proba(X)[:, 1]  # proba classe ATTACK

    df["prediction"] = ["ATTACK" if p == 1 else "BENIGN" for p in predictions]
    df["confidence"] = probabilities

    attacks = df[df["prediction"] == "ATTACK"].copy()

    alerts = []
    for _, row in attacks.iterrows():
        alerts.append({
            "tool": "ml-network",
            "timestamp": str(row[ts_col]) if ts_col else None,
            "src_ip": str(row[src_col]) if src_col else None,
            "dst_ip": str(row[dst_col]) if dst_col else None,
            "severity": "high" if row["confidence"] > 0.85 else "medium",
            "confidence": round(float(row["confidence"]), 3),
            "title": "Trafic réseau suspect détecté (ML)",
            "details": f"Classifié ATTACK avec confiance {row['confidence']:.2f}",
        })

    print(f"{len(alerts)} alertes réseau détectées sur {len(df)} flux analysés.")
    return alerts