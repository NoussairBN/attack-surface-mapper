# ai/explainer.py

from typing import List, Dict
from ai.feature_extractor import AppFeatures


def explain(features: AppFeatures, score_breakdown: Dict[str, float]) -> List[Dict]:
    explanations = []

    if features.debuggable:
        explanations.append({
            "issue": "Application en mode debuggable",
            "why": "Permet d'attacher un debugger ADB, d'inspecter la mémoire et d'extraire des données en clair.",
            "cwe": "CWE-489", "severity": "CRITICAL",
        })
    if features.allow_backup:
        explanations.append({
            "issue": "Sauvegarde ADB activée (allowBackup=true)",
            "why": "Un attaquant avec accès USB peut extraire toutes les données privées via 'adb backup' sans root.",
            "cwe": "CWE-530", "severity": "HIGH",
        })
    if features.uses_cleartext_traffic:
        explanations.append({
            "issue": "Trafic HTTP en clair autorisé",
            "why": "Les communications transitent sans chiffrement, exposées aux attaques Man-in-the-Middle.",
            "cwe": "CWE-319", "severity": "HIGH",
        })
    if features.missing_permissions_on_exported > 0:
        explanations.append({
            "issue": f"{features.missing_permissions_on_exported} composant(s) exporté(s) sans permission",
            "why": "N'importe quelle application tierce peut invoquer ces composants sans authentification.",
            "cwe": "CWE-926",
            "severity": "CRITICAL" if features.missing_permissions_on_exported > 3 else "HIGH",
        })
    if features.deep_links_exposed > 0:
        explanations.append({
            "issue": f"{features.deep_links_exposed} deep link(s) BROWSABLE exposé(s)",
            "why": "Des apps malveillantes peuvent rediriger l'utilisateur vers votre app avec des données contrôlées (hijacking).",
            "cwe": "CWE-939", "severity": "MEDIUM",
        })
    if features.file_providers_exposed > 0:
        explanations.append({
            "issue": f"{features.file_providers_exposed} FileProvider(s) exposé(s)",
            "why": "Un FileProvider exporté sans contrôle d'accès permet à des apps tierces d'accéder aux fichiers internes.",
            "cwe": "CWE-200", "severity": "HIGH",
        })
    if features.grant_uri_permissions_count > 0:
        explanations.append({
            "issue": f"grantUriPermissions activé sur {features.grant_uri_permissions_count} provider(s)",
            "why": "Peut accorder temporairement un accès aux URIs de contenu à des apps non autorisées.",
            "cwe": "CWE-732", "severity": "MEDIUM",
        })
    if features.direct_boot_aware_receivers > 0:
        explanations.append({
            "issue": f"{features.direct_boot_aware_receivers} receiver(s) directBootAware",
            "why": "Ces receivers s'exécutent avant le déverrouillage de l'appareil, avant toute authentification utilisateur.",
            "cwe": "CWE-306", "severity": "MEDIUM",
        })
    if features.task_affinity_set > 0:
        explanations.append({
            "issue": f"{features.task_affinity_set} activité(s) avec taskAffinity personnalisé",
            "why": "Une taskAffinity non standard peut permettre du task hijacking par une app malveillante.",
            "cwe": "CWE-1021", "severity": "MEDIUM",
        })
    if features.critical_findings > 0:
        explanations.append({
            "issue": f"{features.critical_findings} finding(s) CRITICAL détectés par l'analyse P2",
            "why": "Vulnérabilités critiques confirmées nécessitant une correction immédiate.",
            "cwe": "N/A", "severity": "CRITICAL",
        })

    return explanations