"""
Analyse croisée des permissions globales de l'application et des composants exportés.
"""
from typing import List
from core.component_model import AppManifest
from detection.pattern_registry import PATTERNS, RiskLevel
from detection.risk_patterns import Finding

# Liste standardisée des permissions critiques Android
DANGEROUS_PERMISSIONS = {
    "android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS",
    "android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.READ_CALL_LOG", "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO", "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE", "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS"
}

def analyze_permissions(manifest: AppManifest) -> List[Finding]:
    findings = []
    
    # On récupère la liste des permissions extraites par P1 (par défaut une liste vide si non trouvée)
    app_uses_perms = getattr(manifest, 'uses_permissions', [])
    
    # Quelles permissions dangereuses cette app possède-t-elle ?
    dangerous_used = [p for p in app_uses_perms if p in DANGEROUS_PERMISSIONS]
    
    # S'il n'y a pas de permission dangereuse, le risque de "Confused Deputy" est faible
    if not dangerous_used:
        return findings
        
    # On analyse tous les composants pouvant agir comme "pont" (hors Providers)
    all_components = manifest.activities + manifest.services + manifest.receivers
    
    for comp in all_components:
        # Un composant est exporté s'il a 'exported=True' OU s'il a des intent-filters
        is_exported = comp.exported or bool(comp.intent_filters)
        
        if is_exported and not comp.permission:
            pattern = PATTERNS["DANGEROUS_PERM_MISSING"]
            findings.append(Finding(
                pattern_id=pattern.id,
                component_name=comp.name,
                component_type=comp.component_type,
                severity=pattern.severity,
                cwe=pattern.cwe,
                detail=f"Ce composant est accessible publiquement, et l'application possède les permissions : {', '.join(dangerous_used)}. Une application tierce pourrait forcer ce composant à utiliser ces privilèges à son insu.",
                evidence={"app_permissions": dangerous_used, "component_exported": True}
            ))
            
    return findings
