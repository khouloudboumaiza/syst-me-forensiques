"""
ai_explainer.py
---------------------
Génère des explications en langage humain via l'API Gemini (Google AI Studio).
Utilisé pour enrichir les alertes forensiques avec un contexte pédagogique.
"""
import os
import json
import requests

GEMINI_API_KEY = os.environ.get(
    "GEMINI_API_KEY",
    # Clé gratuite Google AI Studio - remplacer par votre propre clé si nécessaire
    # Obtenir une clé gratuite sur : https://aistudio.google.com/app/apikey
    ""
)
GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent"


def explain_alert(rule: str, target: str, source: str, details: str = "") -> str:
    """
    Appelle l'API Gemini pour générer une explication en langage humain.
    Retourne l'explication ou un message d'erreur fallback.
    """
    if not GEMINI_API_KEY or GEMINI_API_KEY == "AIzaSyDefault":
        return _fallback_explanation(rule, target, source)

    prompt = f"""Tu es un expert en cybersécurité et en forensique informatique.
Explique l'alerte suivante en langage humain clair et détaillé pour un analyste SOC débutant.
Sois concis (3-4 phrases max), factuel et pédagogique. Réponds en français.

Outil de détection: {source.upper()}
Règle déclenchée: {rule}
Cible/Hôte: {target or 'non spécifié'}
Détails techniques: {details[:300] if details else 'aucun détail supplémentaire'}

Explication:"""

    try:
        resp = requests.post(
            f"{GEMINI_URL}?key={GEMINI_API_KEY}",
            json={
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {"maxOutputTokens": 200, "temperature": 0.3}
            },
            timeout=8
        )
        if resp.status_code == 200:
            data = resp.json()
            text = data["candidates"][0]["content"]["parts"][0]["text"]
            return text.strip()
        else:
            return _fallback_explanation(rule, target, source)
    except Exception:
        return _fallback_explanation(rule, target, source)


def _fallback_explanation(rule: str, target: str, source: str) -> str:
    """Explication heuristique de secours si l'API n'est pas disponible."""
    r = rule.lower()
    t = target or "cible inconnue"
    if "logon" in r or "login" in r or "auth" in r:
        return f"Tentative d'authentification détectée par {source.upper()}. L'événement implique la machine ou l'IP '{t}'. Cela peut indiquer une attaque par force brute ou un accès non autorisé."
    if "process" in r or "cmd" in r or "shell" in r or "exec" in r:
        return f"Exécution d'un processus ou d'une commande système signalée par {source.upper()} sur '{t}'. Ce type d'activité est souvent associé à des outils d'attaque post-exploitation (ex: Mimikatz, PowerShell malveillant)."
    if "malware" in r or "virus" in r or "trojan" in r or "backdoor" in r or "yara" in r:
        return f"Signature de malware détectée par {source.upper()} sur '{t}'. Un logiciel malveillant potentiel (virus, cheval de Troie, backdoor) a été identifié via une règle YARA ou une signature comportementale."
    if "network" in r or "connection" in r or "traffic" in r or "port" in r or "scan" in r:
        return f"Trafic réseau anormal détecté par {source.upper()} impliquant '{t}'. Cela peut indiquer une reconnaissance réseau, une tentative de connexion non autorisée ou une communication vers un serveur C2 (Command & Control)."
    if "privilege" in r or "admin" in r or "credential" in r or "escalation" in r:
        return f"Activité suspecte liée à des privilèges élevés ou des credentials détectée par {source.upper()}. Cela suggère une tentative d'élévation de privilèges (ex: PassTheHash, Kerberoasting) ciblant '{t}'."
    if "file" in r or "registry" in r or "modification" in r:
        return f"Modification suspecte de fichier ou du registre système détectée par {source.upper()} sur '{t}'. Ce type d'activité est caractéristique d'un malware cherchant à maintenir sa persistance sur le système."
    if "inject" in r or "hook" in r or "hollowing" in r:
        return f"Technique d'injection de code détectée par {source.upper()}. L'attaquant cherche à exécuter du code malveillant dans un processus légitime ('{t}'), une technique souvent utilisée pour contourner les antivirus."
    return f"L'outil {source.upper()} a signalé la règle '{rule}' sur la cible '{t}' comme suspecte. Cette détection nécessite une investigation approfondie pour confirmer ou infirmer une compromission."


# ─────────────────────────────────────────────────────────────────────────────
# CLASSIFICATION D'IOC (Hash) via IA
# ─────────────────────────────────────────────────────────────────────────────

from hash_verdict import HashVerdict, VERDICT_LABELS_FR, Verdict, VTResult, FileContext, classify_hash

_FALLBACK_RECOMMENDATIONS = {
    Verdict.TRUE_POSITIVE: (
        "Isoler la machine concernée du réseau, mettre le fichier en quarantaine, "
        "et lancer une recherche de persistance associée (tâches planifiées, clés Run, services)."
    ),
    Verdict.LIKELY_FALSE_POSITIVE: (
        "Aucune action immédiate requise. Documenter l'exception si l'outil de sécurité "
        "doit être configuré pour ne plus alerter sur ce fichier légitime."
    ),
    Verdict.POTENTIAL_FALSE_NEGATIVE: (
        "Analyse manuelle recommandée : soumettre le fichier à une sandbox comportementale "
        "et vérifier les connexions réseau associées, malgré un score VirusTotal bas."
    ),
    Verdict.SUSPICIOUS_REVIEW: (
        "Revue manuelle par un analyste recommandée avant conclusion définitive."
    ),
    Verdict.CLEAN: "Aucune action requise.",
}

def _fallback_verdict_explanation(v: HashVerdict) -> str:
    label = VERDICT_LABELS_FR[v.verdict]
    rules_txt = " ; ".join(v.triggered_rules)
    return f"{label} (confiance : {v.confidence_score:.0f}/100). Éléments retenus : {rules_txt}."

def enrich_verdict_with_explanation(v: HashVerdict) -> HashVerdict:
    """Remplit v.explanation et v.recommendation.
    Essaie d'abord le LLM (reformulation uniquement), puis retombe sur un texte déterministe.
    """
    label = VERDICT_LABELS_FR[v.verdict]
    rules_txt = "\n".join(f"- {r}" for r in v.triggered_rules)

    prompt = f"""Tu rédiges une section de rapport d'investigation forensique.
Le verdict ci-dessous a DÉJÀ été déterminé par des règles automatiques déterministes.
Ta seule tâche : reformuler ces faits en 2-3 phrases claires pour un analyste,
puis proposer une recommandation concrète en 1 phrase.
Ne remets jamais en cause le verdict fourni, ne change aucun chiffre.

Hash: {v.file_hash}
Chemin: {v.file_path}
Verdict retenu: {label}
Score de confiance (déterministe): {v.confidence_score:.0f}/100
Règles ayant produit ce verdict:
{rules_txt}

Réponds au format:
EXPLICATION: <2-3 phrases>
RECOMMANDATION: <1 phrase concrète>
"""

    if GEMINI_API_KEY:
        try:
            resp = requests.post(
                f"{GEMINI_URL}?key={GEMINI_API_KEY}",
                json={"contents": [{"parts": [{"text": prompt}]}],
                      "generationConfig": {"maxOutputTokens": 300, "temperature": 0.2}},
                timeout=10
            )
            if resp.status_code == 200:
                raw = resp.json()["candidates"][0]["content"]["parts"][0]["text"].strip()
                if "EXPLICATION:" in raw and "RECOMMANDATION:" in raw:
                    expl_part = raw.split("EXPLICATION:")[1].split("RECOMMANDATION:")[0].strip()
                    reco_part = raw.split("RECOMMANDATION:")[1].strip()
                    v.explanation = expl_part
                    v.recommendation = reco_part
                    return v
        except Exception:
            pass  # Fallback

    v.explanation = _fallback_verdict_explanation(v)
    v.recommendation = _FALLBACK_RECOMMENDATIONS[v.verdict]
    return v

def classify_ioc_with_ai(
    hash_value: str,
    file_path: str = "",
    vt_malicious: int = 0,
    vt_total: int = 0,
    vt_verdict: str = "unknown",
    tool: str = ""
) -> dict:
    """
    Interface compatible avec le frontend et le rapport PDF actuels,
    utilisant la nouvelle logique HashVerdict.
    """
    # 1. Préparation du contexte
    path_lower = (file_path or "").lower()
    suspicious_paths = ["temp", "tmp", "appdata", "roaming", "downloads", "public", "startup", "run", "winlogon"]
    system_paths = ["system32", "windows", "program files", "microsoft"]
    
    ctx = FileContext(
        file_path=file_path,
        suspicious_path=any(p in path_lower for p in suspicious_paths),
        known_legitimate_software=any(p in path_lower for p in system_paths)
    )
    
    vt = VTResult(
        malicious=vt_malicious,
        total_engines=vt_total,
    )
    
    # 2. Classification déterministe
    verdict = classify_hash(hash_value, vt, ctx)
    
    # 3. Explication IA / Fallback
    enriched_verdict = enrich_verdict_with_explanation(verdict)
    
    # 4. Conversion au format attendu par le reste du code
    return {
        "status": enriched_verdict.verdict.value,
        "confidence": enriched_verdict.confidence_score,
        "explanation": enriched_verdict.explanation,
        "recommendation": enriched_verdict.recommendation
    }
