"""Defensive, evidence-first SOC analysis helpers for Congo Sec Vision."""
from collections import Counter
from datetime import datetime, timezone
import re

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

RULES = [
    (("eventid=1102", "audit log cleared"), "critical", "AUDIT-001", "Journal d’audit effacé",
     "Préserver les journaux centralisés, vérifier les comptes administrateurs et corréler l’heure avec les connexions."),
    (("mimikatz", "sekurlsa", "credential dumping", "lsass memory"), "critical", "CRED-001", "Indice de vol d’identifiants",
     "Isoler le poste selon la procédure SOC, préserver les preuves et réinitialiser les secrets concernés après investigation."),
    (("eventid=4740", "account locked out"), "high", "AUTH-002", "Verrouillage de compte",
     "Identifier le compte et les hôtes sources, corréler les échecs de connexion et vérifier les tâches ou services utilisant ce compte."),
    (("eventid=4720", "eventid=4728", "eventid=4732", "eventid=4756"), "high", "AD-001", "Changement Active Directory sensible",
     "Vérifier l’auteur, l’approbation et le groupe ciblé ; annuler le changement uniquement après validation du responsable AD."),
    (("powershell -enc", "encodedcommand", "downloadstring("), "high", "EXEC-001", "Commande PowerShell potentiellement suspecte",
     "Examiner la ligne de commande complète, le processus parent, l’utilisateur et les connexions réseau associées."),
    (("eventid=4625", "failed password", "authentication failure", "invalid user"), "medium", "AUTH-001", "Échec d’authentification",
     "Regrouper les tentatives par compte et IP source, vérifier les horaires et appliquer les contrôles de verrouillage adaptés."),
    (("sudo:", "user not in sudoers", "privilege escalation"), "low", "PRIV-001", "Événement de privilège Linux",
     "Vérifier l’utilisateur, la commande demandée et les modifications récentes des règles sudo."),
]

def analyze_logs(logs):
    findings = []
    for item in logs:
        message = str(item.get("message") or "")
        lower = message.lower()
        for needles, severity, rule_id, title, recommendation in RULES:
            if any(n in lower for n in needles):
                findings.append({
                    "severity": severity, "rule_id": rule_id, "title": title,
                    "message": message[:1800], "source": str(item.get("source") or "endpoint")[:120],
                    "timestamp": item.get("created_at") or item.get("timestamp"),
                    "recommendation": recommendation,
                    "confidence": "signal à investiguer — pas une preuve de compromission",
                })
                break
    counts = Counter(x["severity"] for x in findings)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "events_reviewed": len(logs), "findings_total": len(findings),
        "severity_counts": {k: counts.get(k, 0) for k in ("critical", "high", "medium", "low")},
        "findings": sorted(findings, key=lambda x: SEVERITY_ORDER.get(x["severity"], 0), reverse=True),
        "limitations": [
            "Les règles détectent des motifs dans les journaux fournis ; elles ne prouvent pas une compromission.",
            "La couverture dépend des journaux activés, des droits de collecte et de la période remontée par l’agent.",
        ],
    }

def cve_remediation_advice(cve_id, severity, software_name, version, title):
    """Safe guidance; never invent a fixed version or run remediation automatically."""
    return {
        "priority": severity or "unknown",
        "software": software_name or "logiciel non identifié",
        "detected_version": version or "version inconnue",
        "recommendations": [
            "Vérifier la plage de versions affectées dans la fiche CVE officielle et l’avis de sécurité de l’éditeur.",
            "Mettre à niveau vers une version corrigée explicitement indiquée par l’éditeur, après validation en préproduction.",
            "Si le correctif n’est pas disponible, appliquer uniquement les mesures compensatoires documentées par l’éditeur.",
            "Planifier une fenêtre de maintenance, sauvegarder la configuration et contrôler le service après correction.",
        ],
        "references": [f"https://nvd.nist.gov/vuln/detail/{cve_id}"] if re.fullmatch(r"CVE-\\d{4}-\\d{4,}", str(cve_id or "")) else [],
        "validation_required": True,
        "automatic_remediation": False,
        "evidence_note": "Une correspondance par nom de logiciel n’établit pas à elle seule que la version est vulnérable.",
        "source_title": (title or "")[:500],
    }
