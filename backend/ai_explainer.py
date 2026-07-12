"""
ai_explainer.py
---------------------
Génère des explications en langage humain via l'API Gemini (Google AI Studio).
Utilisé pour enrichir les alertes forensiques avec un contexte pédagogique.
"""
import os
import json
import requests
from typing import Optional

NVIDIA_API_KEY = os.environ.get(
    "NVIDIA_API_KEY",
    "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"
)
NVIDIA_URL = "https://integrate.api.nvidia.com/v1/chat/completions"

GEMINI_API_KEY = os.environ.get(
    "GEMINI_API_KEY",
    ""
)
GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent"

_NVIDIA_RESPONSE_CACHE: dict[tuple[str, float, int], str] = {}


def _call_nvidia_chat(prompt: str, temperature: float = 0.35, max_tokens: int = 450) -> Optional[str]:
    """Appelle le modèle NVIDIA via l'API chat completions."""
    if not NVIDIA_API_KEY:
        return None

    cache_key = (prompt.strip(), round(temperature, 2), int(max_tokens))
    if cache_key in _NVIDIA_RESPONSE_CACHE:
        return _NVIDIA_RESPONSE_CACHE[cache_key]

    payload = {
        "model": "qwen/qwen3.5-397b-a17b",
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": max_tokens,
        "temperature": temperature,
        "top_p": 0.95,
        "top_k": 20,
        "presence_penalty": 0,
        "repetition_penalty": 1,
        "stream": False,
    }
    headers = {
        "Authorization": f"Bearer {NVIDIA_API_KEY}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    try:
        response = requests.post(NVIDIA_URL, headers=headers, json=payload, timeout=(2.5, 5.0))
        if response.status_code != 200:
            return None
        data = response.json()
        text = data.get("choices", [{}])[0].get("message", {}).get("content", "").strip()
        if text:
            _NVIDIA_RESPONSE_CACHE[cache_key] = text
        return text
    except Exception:
        return None


def explain_alert(rule: str, target: str, source: str, details: str = "") -> str:
    """
    Génère une explication professionnelle et concise pour une alerte via NVIDIA.
    Retourne un texte de secours si l'API n'est pas disponible.
    """
    prompt = f"""Tu es un expert en cybersécurité forensique et en réponse à incident.
Rédige une explication professionnelle en français, concise et utile pour un analyste SOC.
Ne mets pas de liste, limite-toi à 2 à 4 phrases factuelles et opérationnelles.

Outil de détection: {source.upper() or 'outil inconnu'}
Règle déclenchée: {rule or 'règle non renseignée'}
Cible/Hôte: {target or 'non spécifié'}
Détails techniques: {details[:600] if details else 'aucun détail supplémentaire'}

Explication:"""

    ai_text = _call_nvidia_chat(prompt, temperature=0.35, max_tokens=280)
    if ai_text:
        return ai_text
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
    """Remplit v.explanation et v.recommendation avec une formulation IA professionnelle."""
    label = VERDICT_LABELS_FR[v.verdict]
    rules_txt = "\n".join(f"- {r}" for r in v.triggered_rules)

    prompt = f"""Tu rédiges une section de rapport d'investigation forensique.
Le verdict ci-dessous a déjà été déterminé par des règles automatiques déterministes.
Ta seule tâche est de reformuler ces faits en 2 à 3 phrases techniques et professionnelles,
puis d'ajouter une recommandation concrète en 1 phrase.
Ne remets jamais en cause le verdict fourni, ne change aucun chiffre.

Hash: {v.file_hash}
Chemin: {v.file_path}
Verdict retenu: {label}
Score de confiance déterministe: {v.confidence_score:.0f}/100
Règles ayant produit ce verdict:
{rules_txt}

Réponds au format exact suivant:
EXPLICATION: <2-3 phrases>
RECOMMANDATION: <1 phrase concrète>
"""

    ai_text = _call_nvidia_chat(prompt, temperature=0.2, max_tokens=360)
    if ai_text and "EXPLICATION:" in ai_text and "RECOMMANDATION:" in ai_text:
        expl_part = ai_text.split("EXPLICATION:")[1].split("RECOMMANDATION:")[0].strip()
        reco_part = ai_text.split("RECOMMANDATION:")[1].strip()
        v.explanation = expl_part
        v.recommendation = reco_part
        return v

    v.explanation = _fallback_verdict_explanation(v)
    v.recommendation = _FALLBACK_RECOMMENDATIONS[v.verdict]
    return v


def explain_incident_summary(incident_name: str, threat_label: str, alerts: list[dict],
                             classified: list[dict], correlated_events: list[dict]) -> str:
    """Produit une synthèse professionnelle d'incident en français via NVIDIA."""
    n_crit = sum(1 for a in alerts if a.get("severity") == "critical")
    n_high = sum(1 for a in alerts if a.get("severity") == "high")
    n_vp = sum(1 for c in classified if c.get("classification", {}).get("status") == "true_positive")
    n_susp = sum(1 for c in classified if c.get("classification", {}).get("status") == "suspicious_review")
    n_correl = len(correlated_events)

    prompt = f"""Tu rédiges une synthèse professionnelle de rapport d'investigation forensique.
Incident: {incident_name}
Niveau de menace: {threat_label}
Alertes détectées: {len(alerts)} dont {n_crit} critiques et {n_high} élevées.
Éléments classifiés vrais positifs: {n_vp}
Éléments suspects: {n_susp}
Corrélations host/réseau: {n_correl}

Rédige 3 à 4 phrases techniques et concises en français pour un analyste SOC. Mets l'accent sur la compromission probable, les risques et les prochaines actions prioritaires.
"""
    ai_text = _call_nvidia_chat(prompt, temperature=0.3, max_tokens=320)
    if ai_text:
        return ai_text.strip()

    return (
        f"L'analyse de l'incident {incident_name} révèle un niveau de menace {threat_label} avec {len(alerts)} événement(s) observé(s). "
        f"{n_vp} élément(s) ont été classifié(s) comme vrai positif et {n_susp} élément(s) restent suspects, ce qui justifie une investigation approfondie."
    )

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
