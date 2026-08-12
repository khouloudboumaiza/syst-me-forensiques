from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional

class Verdict(str, Enum):
    TRUE_POSITIVE = "true_positive"
    LIKELY_FALSE_POSITIVE = "likely_false_positive"
    POTENTIAL_FALSE_NEGATIVE = "potential_false_negative"
    SUSPICIOUS_REVIEW = "suspicious_review"
    CLEAN = "clean"

VERDICT_LABELS_FR = {
    Verdict.TRUE_POSITIVE: "Vrai positif (malveillant confirmé)",
    Verdict.LIKELY_FALSE_POSITIVE: "Faux positif probable",
    Verdict.POTENTIAL_FALSE_NEGATIVE: "Faux négatif potentiel — vérification manuelle requise",
    Verdict.SUSPICIOUS_REVIEW: "Suspect — revue manuelle requise",
    Verdict.CLEAN: "Sain",
}

@dataclass
class VTResult:
    malicious: int = 0
    suspicious: int = 0
    undetected: int = 0
    harmless: int = 0
    total_engines: int = 0
    is_signed: bool = False
    signer_trusted: bool = False
    known_distributor: bool = False
    first_submission_days_ago: Optional[int] = None
    popular_threat_names: List[str] = field(default_factory=list)

    @property
    def malicious_ratio(self) -> float:
        if self.total_engines == 0:
            return 0.0
        return self.malicious / self.total_engines

@dataclass
class FileContext:
    file_path: str
    suspicious_path: bool = False
    suspicious_name_pattern: bool = False
    spawned_suspicious_process: bool = False
    known_legitimate_software: bool = False

@dataclass
class HashVerdict:
    file_hash: str
    file_path: str
    verdict: Verdict
    confidence_score: float
    triggered_rules: List[str]
    explanation: Optional[str] = None
    recommendation: Optional[str] = None

    @property
    def verdict_label(self) -> str:
        return VERDICT_LABELS_FR[self.verdict]

RATIO_MALICIOUS_CONFIRMED = 0.15
RATIO_SUSPICIOUS_LOW = 0.03

def classify_hash(file_hash: str, vt: VTResult, ctx: FileContext) -> HashVerdict:
    rules: List[str] = []
    ratio = vt.malicious_ratio
    rules.append(f"Ratio moteurs malveillants VirusTotal : {vt.malicious}/{vt.total_engines} ({ratio:.1%})")

    if ratio >= RATIO_MALICIOUS_CONFIRMED:
        rules.append(f"Ratio >= seuil de confirmation ({RATIO_MALICIOUS_CONFIRMED:.0%})")
        confidence = min(100.0, 60 + ratio * 100)
        if ctx.spawned_suspicious_process:
            rules.append("Contexte aggravant : processus suspect enfant observé")
            confidence = min(100.0, confidence + 10)
        return HashVerdict(file_hash, ctx.file_path, Verdict.TRUE_POSITIVE, confidence, rules)

    if ratio > 0 and (vt.signer_trusted or ctx.known_legitimate_software):
        rules.append("Score positif mais éditeur de confiance / logiciel légitime connu")
        confidence = max(0.0, 70 - ratio * 200)
        return HashVerdict(file_hash, ctx.file_path, Verdict.LIKELY_FALSE_POSITIVE, confidence, rules)

    if ratio < RATIO_SUSPICIOUS_LOW and not vt.signer_trusted:
        aggravating = sum([
            ctx.suspicious_path,
            ctx.suspicious_name_pattern,
            ctx.spawned_suspicious_process,
        ])
        if aggravating >= 2:
            rules.append(
                f"Score VT faible ({ratio:.1%}) mais {aggravating} indicateurs de contexte "
                "suspects réunis (chemin, nom, comportement)"
            )
            confidence = 30 + aggravating * 10
            return HashVerdict(file_hash, ctx.file_path, Verdict.POTENTIAL_FALSE_NEGATIVE, confidence, rules)

    if RATIO_SUSPICIOUS_LOW <= ratio < RATIO_MALICIOUS_CONFIRMED:
        rules.append("Ratio en zone intermédiaire, ni confirmé ni clairement bénin")
        return HashVerdict(file_hash, ctx.file_path, Verdict.SUSPICIOUS_REVIEW, 50.0, rules)

    rules.append("Aucun indicateur significatif détecté")
    return HashVerdict(file_hash, ctx.file_path, Verdict.CLEAN, 5.0, rules)

def aggregate_verdicts(verdicts: List[HashVerdict]) -> dict:
    total = len(verdicts)
    if total == 0:
        return {"total": 0}
    counts = {v: 0 for v in Verdict}
    for verdict in verdicts:
        counts[verdict.verdict] += 1
    return {
        "total": total,
        "counts": {v.value: c for v, c in counts.items()},
        "percentages": {v.value: round(c / total * 100, 1) for v, c in counts.items()},
    }
