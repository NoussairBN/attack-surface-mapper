"""
Registre centralisé des patterns de risques (Vulnérabilités Android).
"""
from dataclasses import dataclass
from typing import Optional, Dict

# On importe l'Enum de P3 pour que nos sévérités matchent avec les couleurs de son graphe !
from graph.graph_model import RiskLevel

@dataclass
class RiskPattern:
    id: str               # ex: "EXPORTED_NO_PERM"
    name: str
    description: str
    severity: RiskLevel
    cwe: str              # ex: "CWE-926"
    owasp: Optional[str]  # ex: "M1"

# ─── Le Dictionnaire de toutes les failles ──────────────────────────────────────────
PATTERNS: Dict[str, RiskPattern] = {
    "EXPORTED_NO_PERM": RiskPattern(
        id          = "EXPORTED_NO_PERM",
        name        = "Composant exporté sans permission",
        description = "android:exported=true sans android:permission déclarée → accessible par n'importe quelle app.",
        severity    = RiskLevel.CRITICAL,
        cwe         = "CWE-926",
        owasp       = "M1"
    ),
    "ALLOW_BACKUP_TRUE": RiskPattern(
        id          = "ALLOW_BACKUP_TRUE",
        name        = "Sauvegarde ADB autorisée",
        description = "android:allowBackup=true → extraction des données privées via 'adb backup'.",
        severity    = RiskLevel.MEDIUM,
        cwe         = "CWE-530",
        owasp       = "M2"
    ),
    "DEBUGGABLE_TRUE": RiskPattern(
        id          = "DEBUGGABLE_TRUE",
        name        = "Application debuggable en production",
        description = "android:debuggable=true → un attaquant peut attacher un debugger ou dumper la mémoire.",
        severity    = RiskLevel.HIGH,
        cwe         = "CWE-215",
        owasp       = "M7"
    ),
    "DEEP_LINK_EXPOSED": RiskPattern(
        id          = "DEEP_LINK_EXPOSED",
        name        = "Deep Link potentiellement vulnérable",
        description = "Le composant accepte des URLs depuis l'extérieur (catégorie BROWSABLE). Risque de hijacking si non vérifié.",
        severity    = RiskLevel.HIGH,
        cwe         = "CWE-939",
        owasp       = "M1"
    ),
}

def get_pattern(pattern_id: str) -> RiskPattern:
    if pattern_id not in PATTERNS:
        raise KeyError(f"Pattern inconnu : {pattern_id}")
    return PATTERNS[pattern_id]
