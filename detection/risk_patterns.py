"""
Logique de détection des vulnérabilités à partir de l'AppManifest de P1.
"""
from dataclasses import dataclass
from typing import List, Dict, Any
from core.component_model import AppManifest, AndroidComponent
from detection.pattern_registry import PATTERNS, RiskLevel

@dataclass
class Finding:
    pattern_id: str
    component_name: str
    component_type: str
    severity: RiskLevel
    cwe: str
    detail: str
    evidence: Dict[str, Any]

def check_manifest_flags(manifest: AppManifest) -> List[Finding]:
    """Vérifie les failles globales de l'application (allowBackup, debuggable)."""
    findings = []
    
    # Check Debuggable
    if manifest.debuggable:
        pattern = PATTERNS["DEBUGGABLE_TRUE"]
        findings.append(Finding(
            pattern_id=pattern.id, component_name="<application>", component_type="manifest",
            severity=pattern.severity, cwe=pattern.cwe,
            detail="L'application est compilée en mode debug (debuggable=true).",
            evidence={"debuggable": True}
        ))
        
    # Check AllowBackup
    if manifest.allow_backup:
        pattern = PATTERNS["ALLOW_BACKUP_TRUE"]
        findings.append(Finding(
            pattern_id=pattern.id, component_name="<application>", component_type="manifest",
            severity=pattern.severity, cwe=pattern.cwe,
            detail="L'application autorise les sauvegardes ADB (allowBackup=true ou absent).",
            evidence={"allow_backup": True}
        ))
        
    return findings

def check_exported_no_permission(component: AndroidComponent) -> List[Finding]:
    """Vérifie si un composant est exporté sans être protégé par une permission."""
    findings = []
    
    if component.exported and not component.permission:
        pattern = PATTERNS["EXPORTED_NO_PERM"]
        findings.append(Finding(
            pattern_id=pattern.id, 
            component_name=component.name, 
            component_type=component.component_type,
            severity=pattern.severity, 
            cwe=pattern.cwe,
            detail=f"Le composant '{component.name}' est exporté sans protection. N'importe quelle app peut l'invoquer.",
            evidence={"exported": True, "permission": None}
        ))
        
    return findings
def check_implicit_intent_sensitive(component: AndroidComponent) -> List[Finding]:
    """Détecte si le composant écoute des actions système critiques."""
    findings = []
    
    # Liste des actions Android considérées comme sensibles
    SENSITIVE_ACTIONS = {
        "android.intent.action.SEND",
        "android.intent.action.SEND_MULTIPLE",
        "android.intent.action.CALL",
        "android.intent.action.BOOT_COMPLETED",
        "android.intent.action.PACKAGE_REPLACED",
        "android.provider.Telephony.SMS_RECEIVED"
    }
    
    for intent_filter in component.intent_filters:
        for action in intent_filter.actions:
            if action in SENSITIVE_ACTIONS:
                pattern = PATTERNS["IMPLICIT_INTENT_SENSITIVE"]
                findings.append(Finding(
                    pattern_id=pattern.id, 
                    component_name=component.name, 
                    component_type=component.component_type,
                    severity=pattern.severity, 
                    cwe=pattern.cwe,
                    detail=f"Action critique '{action}' détectée dans un intent-filter. Si le composant n'a pas de permission stricte, une app malveillante peut forcer cette action.",
                    evidence={"action": action}
                ))
                
    return findings

def analyze_all_components(manifest: AppManifest) -> List[Finding]:
    """Point d'entrée principal de l'analyse P2."""
    # L'import est décalé ici pour casser la boucle circulaire !
    from detection.fileprovider_checker import check_fileprovider_exported
    all_findings = []
    
    # 1. Analyse globale
    all_findings.extend(check_manifest_flags(manifest))
    
    # 2. Itération sur tous les composants pour les failles spécifiques
    all_components = manifest.activities + manifest.services + manifest.receivers + manifest.providers
    for comp in all_components:
        all_findings.extend(check_exported_no_permission(comp))
        all_findings.extend(check_implicit_intent_sensitive(comp))
        
        # Détection des Deep Links (BROWSABLE)
        for intent_filter in comp.intent_filters:
            if "android.intent.category.BROWSABLE" in intent_filter.categories:
                pattern = PATTERNS["DEEP_LINK_EXPOSED"]
                all_findings.append(Finding(
                    pattern_id=pattern.id, component_name=comp.name, component_type=comp.component_type,
                    severity=pattern.severity, cwe=pattern.cwe,
                    detail=f"Ce composant accepte des Deep Links...",
                    evidence={"categories": intent_filter.categories, "schemes": intent_filter.data_schemes}
                ))

    # 3. Analyse spécifique des Providers (NOUVEAU)
    for provider in manifest.providers:
        all_findings.extend(check_fileprovider_exported(provider))
                
    return all_findings
