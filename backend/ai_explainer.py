"""
ai_explainer.py
---------------------
Génère des explications en langage humain via l'API NVIDIA compatible OpenAI.
Utilise le modèle openai/gpt-oss-20b pour des explications précises.
"""
import os
import json
from typing import Optional
from openai import OpenAI

# ── Configuration NVIDIA API ─────────────────────────────────────────────────
NVIDIA_API_KEY = os.environ.get("NVIDIA_API_KEY", "").strip()
NVIDIA_API_KEY = NVIDIA_API_KEY or "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"
NVIDIA_BASE_URL = "https://integrate.api.nvidia.com/v1"
NVIDIA_MODEL = "meta/llama-3.1-8b-instruct"

_NVIDIA_RESPONSE_CACHE: dict[tuple[str, float, int], str] = {}
_CACHE_LIMIT = 200

# Initialisation du client OpenAI
client = OpenAI(
    base_url=NVIDIA_BASE_URL,
    api_key=NVIDIA_API_KEY
)

def _call_nvidia_chat(prompt: str, temperature: float = 0.60, max_tokens: int = 400) -> Optional[str]:
    """Appelle l'API chat completions NVIDIA."""
    if not NVIDIA_API_KEY:
        return "NVIDIA_KEY_MISSING"

    cache_key = (prompt.strip(), round(temperature, 2), int(max_tokens))
    if cache_key in _NVIDIA_RESPONSE_CACHE:
        return _NVIDIA_RESPONSE_CACHE[cache_key]
    if len(_NVIDIA_RESPONSE_CACHE) >= _CACHE_LIMIT:
        _NVIDIA_RESPONSE_CACHE.clear()

    try:
        completion = client.chat.completions.create(
            model=NVIDIA_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=temperature,
            top_p=1,
            max_tokens=max_tokens,
            stream=False,
            timeout=120
        )
        
        content = completion.choices[0].message.content
        if not content:
            reasoning = getattr(completion.choices[0].message, "reasoning_content", None)
            if reasoning:
                content = reasoning
                
        text = str(content or "").strip()
        
        # Nettoyer les balises <think>...</think>
        import re
        text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()

        if text:
            _NVIDIA_RESPONSE_CACHE[cache_key] = text
        return text or None

    except Exception as e:
        import openai
        if isinstance(e, openai.AuthenticationError):
            return "NVIDIA_ERROR_AuthenticationError"
        if isinstance(e, openai.APITimeoutError):
            return "NVIDIA_TIMEOUT"
        return f"NVIDIA_ERROR_{type(e).__name__}"


def explain_alert(rule: str, target: str, source: str, details: str = "", severity: str = "medium") -> str:
    """
    Génère une explication professionnelle et concise pour une alerte via l'API NVIDIA.
    L'objectif est d'expliquer précisément la colonne Cible / Description.
    """
    prompt = f"""Tu es un analyste SOC senior spécialisé en investigation forensique.
Explique en français, de manière professionnelle et précise, ce que signifie cette alerte pour l'investigation.

Sévérité: {severity or 'moyenne'}
Source/Outil: {source or 'outil inconnu'}
Règle déclenchée: {rule or 'règle non renseignée'}
Cible/Description: {target or 'non spécifié'}
Détails complémentaires: {details[:800] if details else 'aucun'}

Instructions:
- Explique en 2-3 phrases ce que cette alerte indique concrètement (quelle menace, quel risque).
- Mentionne la technique d'attaque si pertinent (ex: lateral movement, credential dumping, C2 beaconing).
- Propose une action de remédiation en 1 phrase.
- Ne commence pas par "Bien sûr" ou une formule de politesse.
- Ne répète pas simplement les données fournies, analyse-les."""

    ai_text = _call_nvidia_chat(prompt, temperature=0.6, max_tokens=1000)

    if ai_text and not ai_text.startswith("NVIDIA_"):
        return ai_text.strip()
    if ai_text == "NVIDIA_KEY_MISSING":
        return "La variable d'environnement NVIDIA_API_KEY n'est pas définie. Définissez-la avant de relancer l'API."
    if ai_text == "NVIDIA_ERROR_AuthenticationError":
        return "L'API NVIDIA a refusé la clé fournie. Vérifiez la valeur de la clé et son activation."
    if ai_text == "NVIDIA_TIMEOUT":
        return (
            "Le modèle IA a mis trop de temps à répondre. "
            "Cela peut arriver lors du premier appel (démarrage à froid). Réessayez dans quelques secondes."
        )
    return (
        f"L'explication IA n'a pas pu être générée (code: {ai_text}). "
        "Vérifiez la clé API NVIDIA et la connectivité réseau, puis réessayez."
    )


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

    ai_text = _call_nvidia_chat(prompt, temperature=0.6, max_tokens=1000)
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

    # Résumer les premières alertes pour donner du contexte au modèle
    alert_summaries = []
    for a in alerts[:10]:
        alert_summaries.append(
            f"- [{a.get('severity','?').upper()}] {a.get('title','')} → {a.get('target','')}"
        )
    alert_context = "\n".join(alert_summaries)

    prompt = f"""Tu rédiges une synthèse professionnelle de rapport d'investigation forensique.
Incident: {incident_name}
Niveau de menace: {threat_label}
Alertes détectées: {len(alerts)} dont {n_crit} critiques et {n_high} élevées.
Éléments classifiés vrais positifs: {n_vp}
Éléments suspects: {n_susp}
Corrélations host/réseau: {n_correl}

Exemples d'alertes:
{alert_context}

Rédige 3 à 4 phrases techniques et concises en français pour un analyste SOC.
Mets l'accent sur la compromission probable, les risques et les prochaines actions prioritaires.
Ne commence pas par une formule de politesse."""

    ai_text = _call_nvidia_chat(prompt, temperature=0.6, max_tokens=1000)
    if ai_text and not ai_text.startswith("NVIDIA_"):
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
    Interface compatible avec le frontend et le rapport PDF actuels.
    """
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
    
    verdict = classify_hash(hash_value, vt, ctx)
    enriched_verdict = enrich_verdict_with_explanation(verdict)
    
    return {
        "status": enriched_verdict.verdict.value,
        "confidence": enriched_verdict.confidence_score,
        "explanation": enriched_verdict.explanation,
        "recommendation": enriched_verdict.recommendation
    }

def explain_global_verdict(verdict: str, stats: dict) -> str:
    """
    Génère l'explication détaillée du verdict global (Clean, Suspicious, Compromised...)
    basée sur les statistiques du fichier.
    """
    prompt = f"""Tu rédiges la justification du verdict global d'un rapport d'investigation numérique (DFIR).
Le système a déterminé le verdict suivant pour ce fichier : {verdict}

Statistiques de l'analyse :
- Alertes Critiques : {stats.get('critical', 0)}
- Alertes Malveillantes (VP) : {stats.get('malicious', 0)}
- Alertes Suspectes : {stats.get('suspicious', 0)}
- Alertes Bénignes/Informatif : {stats.get('benign', 0) + stats.get('info', 0)}
- Corrélations identifiées : {stats.get('correlations', 0)}

Instructions:
Rédige un paragraphe de 3-4 phrases expliquant concrètement POURQUOI ce verdict a été choisi.
Si le verdict est "Clean" ou "Mostly Clean", rassure mais conseille la vigilance.
Si "Suspicious", justifie le besoin d'investigation manuelle.
Si "Compromised" ou "Critical Incident", insiste sur l'urgence et les preuves (alertes critiques/malicieuses).
Ton ton doit être neutre, très technique et factuel. Ne dis pas "Bonjour" ni "Voici l'explication".
"""
    ai_text = _call_nvidia_chat(prompt, temperature=0.6, max_tokens=1000)
    if ai_text and not ai_text.startswith("NVIDIA_"):
        return ai_text.strip()
    
    # Fallback
    if verdict in ("Clean", "Mostly Clean"):
        return "L'analyse automatique n'a révélé aucun indicateur de compromission majeur. La majorité des événements sont considérés comme bénins ou informatifs."
    elif verdict == "Suspicious":
        return "Plusieurs indicateurs suspects ont été relevés. Bien qu'aucune menace critique ne soit formellement confirmée, une investigation manuelle approfondie est requise."
    elif verdict in ("Compromised", "Critical Incident"):
        return "Des indicateurs de compromission clairs (alertes critiques ou malveillantes) ont été identifiés et confirmés. L'environnement est compromis, des actions de remédiation immédiates sont nécessaires."
    else:
        return "Les données fournies sont insuffisantes ou non classifiables pour émettre un verdict définitif."

def explain_correlation(correl_type: str, indicator: str, risk: str, tools: list[str], files: list[str], alert_count: int, events: list[str]) -> str:
    """
    Génère une explication détaillée d'une corrélation d'incidents via l'API NVIDIA.
    """
    events_text = "\n".join([f"- {e}" for e in events[:5]])
    tools_text = ", ".join(tools) if tools else "non spécifié"
    files_text = ", ".join(files) if files else "non spécifié"
    
    prompt = f"""Tu es un analyste SOC senior spécialisé en investigation forensique.
On te demande d'analyser une corrélation détectée entre plusieurs événements de sécurité.

Type de corrélation : {correl_type}
Indicateur partagé (Clé) : {indicator}
Niveau de risque global estimé : {risk}
Outils ayant levé les alertes : {tools_text}
Fichiers concernés : {files_text}
Nombre total d'alertes liées : {alert_count}

Exemples d'événements liés :
{events_text}

Instructions strictes - Tu dois structurer ta réponse EXACTEMENT avec les 4 parties suivantes (en utilisant des sauts de ligne pour les séparer, sans utiliser de Markdown excessif qui casserait l'affichage, utilise juste du texte clair ou des puces basiques) :

1. Explication : Explique clairement ce que représente cette corrélation et pourquoi ces événements ont été regroupés autour de cet indicateur ({indicator}).
2. Analyse : Analyse les éléments importants de cette corrélation (quels sont les outils impliqués, que font les événements).
3. Niveau d'impact : Quel est le risque ou l'impact potentiel de cette activité ?
4. Recommandations : Propose des actions concrètes (ex: isolation, blocage d'IP/Hash, investigation).

Ne commence pas par une formule de politesse. Rédige de manière professionnelle et concise en français.
"""

    ai_text = _call_nvidia_chat(prompt, temperature=0.6, max_tokens=1500)

    if ai_text and not ai_text.startswith("NVIDIA_"):
        return ai_text.strip()
    if ai_text == "NVIDIA_KEY_MISSING":
        return "La variable d'environnement NVIDIA_API_KEY n'est pas définie."
    if ai_text == "NVIDIA_ERROR_AuthenticationError":
        return "L'API NVIDIA a refusé la clé fournie."
    if ai_text == "NVIDIA_TIMEOUT":
        return "Le modèle IA a mis trop de temps à répondre. Réessayez."
    
    return "L'explication IA n'a pas pu être générée. Vérifiez l'API NVIDIA et réessayez."
