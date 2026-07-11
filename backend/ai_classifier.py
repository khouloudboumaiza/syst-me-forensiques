"""
ai_classifier.py
----------------
Moteur de classification autonome des IOCs (hash + fichiers), basé sur :
  - le score VirusTotal réel de chaque hash/fichier (ratio malicious/total)
  - le contexte du chemin de fichier (emplacement suspect vs système/légitime)

Contrairement à une dépendance externe (ai_explainer, hash_verdict...) qui peut
être absente ou lever une exception silencieuse, ce module ne dépend d'aucun
fichier externe et garantit TOUJOURS un statut parmi les 5 catégories valides :
    true_positive, likely_false_positive, potential_false_negative,
    suspicious_review, clean

Ce module est appelé une fois par IOC (hash ou fichier) et par incident,
ce qui rend les pourcentages du résumé global 100% dynamiques et propres
à chaque incident analysé.
"""

SUSPICIOUS_PATHS = ["temp", "tmp", "appdata", "roaming", "downloads", "public", "startup", "run", "winlogon"]
SYSTEM_PATHS = ["system32", "windows", "program files", "microsoft"]

VALID_STATUSES = {
    "true_positive",
    "likely_false_positive",
    "potential_false_negative",
    "suspicious_review",
    "clean",
}


def _path_flags(file_path: str) -> tuple[bool, bool]:
    p = (file_path or "").lower()
    is_suspicious = any(s in p for s in SUSPICIOUS_PATHS)
    is_system = any(s in p for s in SYSTEM_PATHS)
    return is_suspicious, is_system


def classify_by_vt_score(
    hash_value: str = "",
    file_path: str = "",
    vt_malicious: int = 0,
    vt_total: int = 0,
    vt_verdict: str = "unknown",
    tool: str = "",
) -> dict:
    """
    Classifie un IOC (hash ou fichier) à partir de son score VirusTotal réel
    et du contexte de son chemin. Retourne toujours un dict avec un statut
    valide, une confiance, une explication et une recommandation.
    """
    vt_malicious = vt_malicious or 0
    vt_total = vt_total or 0
    is_suspicious_path, is_system_path = _path_flags(file_path)
    path_display = file_path or "chemin non renseigné"

    ratio = (vt_malicious / vt_total) if vt_total > 0 else None

    if ratio is not None:
        pct = ratio * 100

        if ratio >= 0.5:
            status = "true_positive"
            confidence = min(99, 60 + pct * 0.4)
            explanation = (
                f"{vt_malicious} moteur(s) antivirus sur {vt_total} détectent ce hash comme "
                f"malveillant (ratio {pct:.0f}%). Consensus VirusTotal fort en faveur d'une menace confirmée."
            )
            recommendation = "Isoler immédiatement le fichier/l'hôte concerné et bloquer le hash sur l'ensemble du parc."

        elif ratio >= 0.15:
            if is_suspicious_path:
                status = "suspicious_review"
                confidence = 55 + pct * 0.3
                explanation = (
                    f"{vt_malicious}/{vt_total} moteurs signalent ce hash comme suspect, et son emplacement "
                    f"({path_display}) est un chemin typiquement utilisé pour héberger du code malveillant."
                )
                recommendation = "Analyse manuelle approfondie recommandée ; envisager une mise en quarantaine préventive."
            else:
                status = "potential_false_negative"
                confidence = 50 + pct * 0.2
                explanation = (
                    f"{vt_malicious}/{vt_total} moteurs détectent une activité suspecte, bien que le chemin "
                    f"({path_display}) semble légitime. Risque de détection incomplète par les autres outils."
                )
                recommendation = "Vérifier la signature numérique et l'intégrité du fichier avant de l'écarter des investigations."

        elif ratio > 0:
            if is_system_path:
                status = "likely_false_positive"
                confidence = 70
                explanation = (
                    f"Seulement {vt_malicious}/{vt_total} moteur(s) signalent ce hash, et le chemin correspond "
                    f"à un composant système ou logiciel légitime ({path_display})."
                )
                recommendation = "Probable faux positif ; confirmer via l'éditeur/la signature avant clôture définitive."
            else:
                status = "suspicious_review"
                confidence = 45
                explanation = (
                    f"{vt_malicious}/{vt_total} moteur(s) signalent une activité ; ratio faible mais non nul, "
                    "et le chemin ne présente pas de garantie de légitimité."
                )
                recommendation = "Analyse complémentaire (bac à sable) recommandée avant classification définitive."

        else:  # ratio == 0
            if is_suspicious_path:
                status = "potential_false_negative"
                confidence = 40
                explanation = (
                    f"Aucun moteur VirusTotal ne détecte ce hash (0/{vt_total}), mais son emplacement "
                    f"({path_display}) est un chemin fréquemment associé à des menaces. Possible évasion antivirus."
                )
                recommendation = "Analyse dynamique (sandbox) recommandée malgré l'absence de détection VirusTotal."
            else:
                status = "clean"
                confidence = 85
                explanation = (
                    f"Aucun moteur sur {vt_total} ne détecte ce hash, et son emplacement est cohérent "
                    "avec un usage légitime."
                )
                recommendation = "Aucune action requise ; conserver l'information pour référence."

    else:
        # Aucune donnée VirusTotal disponible pour ce hash/fichier
        if is_suspicious_path:
            status = "suspicious_review"
            confidence = 35
            explanation = (
                f"Aucune donnée VirusTotal disponible pour ce hash. Le chemin ({path_display}) est "
                "toutefois un emplacement suspect fréquemment utilisé par des logiciels malveillants."
            )
            recommendation = "Soumettre ce hash à VirusTotal ou effectuer une analyse manuelle du fichier."
        else:
            status = "clean"
            confidence = 30
            explanation = (
                "Aucune donnée VirusTotal disponible pour ce hash et le chemin ne présente pas "
                "d'indicateur de risque particulier."
            )
            recommendation = "Surveiller ; soumettre à VirusTotal si de nouvelles alertes apparaissent."

    if status not in VALID_STATUSES:
        # Garde-fou : ne devrait jamais arriver, mais évite tout statut orphelin
        status = "suspicious_review"

    return {
        "status": status,
        "confidence": round(confidence),
        "explanation": explanation,
        "recommendation": recommendation,
        "vt_malicious": vt_malicious,
        "vt_total": vt_total,
        "vt_verdict": vt_verdict,
    }