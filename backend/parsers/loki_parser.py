"""
Parse les logs texte produits par Loki (Neo23x0).
Loki écrit des lignes du type :
2024-01-01 12:00:00 ALERT: FILE: C:\\path\\file.exe SCORE: 100 TYPE: FileScan
REASON_1: Yara Rule MATCH: Mimikatz_Generic SUBSCORE: 100 MD5: ... SHA1: ...

Comme le format exact varie selon la version, on utilise une extraction
par paires clé: valeur, tolérante aux variations.
"""
import re

# Liste fermée des clés connues dans les lignes ALERT de Loki.
# On évite un pattern générique [A-Z_]+: car il confondrait "C:" (lettre de
# lecteur Windows) ou "D:" avec une clé.
KNOWN_KEYS = [
    "ALERT", "WARNING", "FILE", "FILENAME", "HOST", "SCORE", "SUBSCORE",
    "TYPE", "REASON_1", "REASON_2", "REASON_3", "MATCH", "MD5", "SHA1",
    "SHA256", "FIRST_BYTES", "SIZE", "MODULE",
]
_KEYS_ALT = "|".join(KNOWN_KEYS)
KV_PATTERN = re.compile(rf"\b({_KEYS_ALT}):(.*?)(?=\s+(?:{_KEYS_ALT}):|$)")
TIMESTAMP_PATTERN = re.compile(r"^(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})")

SCORE_SEVERITY = [
    (100, "critical"),
    (75, "high"),
    (40, "medium"),
    (0, "low"),
]


def score_to_severity(score: float) -> str:
    for threshold, sev in SCORE_SEVERITY:
        if score >= threshold:
            return sev
    return "info"


def parse_loki_log(raw_bytes: bytes) -> list[dict]:
    text = raw_bytes.decode("utf-8", errors="ignore")
    alerts = []

    for line in text.splitlines():
        if "ALERT" not in line and "WARNING" not in line:
            continue

        ts_match = TIMESTAMP_PATTERN.match(line.strip())
        timestamp = ts_match.group(1) if ts_match else ""

        fields = dict(KV_PATTERN.findall(line))
        fields = {k.strip(): v.strip() for k, v in fields.items()}

        score_raw = fields.get("SCORE") or fields.get("SUBSCORE") or "0"
        try:
            score = float(re.sub(r"[^\d.]", "", score_raw) or 0)
        except ValueError:
            score = 0

        target = fields.get("FILE") or fields.get("FILENAME") or fields.get("HOST") or "N/A"
        reason = fields.get("REASON_1") or fields.get("REASON") or "Loki detection"

        alerts.append({
            "tool": "loki",
            "severity": score_to_severity(score),
            "score": score,
            "title": reason,
            "target": target,
            "details": line.strip(),
            "timestamp": timestamp,
        })

    return alerts
