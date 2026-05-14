"""
Vérification spécifique des ContentProviders et FileProviders.
"""
from typing import List
from core.component_model import Provider
from detection.pattern_registry import PATTERNS, RiskLevel
from detection.risk_patterns import Finding

def check_fileprovider_exported(provider: Provider) -> List[Finding]:
    """Un FileProvider ne doit jamais être exporté (exported=True)."""
    findings = []
    
    if provider.is_file_provider and provider.exported:
        pattern = PATTERNS["FILEPROVIDER_EXPORTED"]
        findings.append(Finding(
            pattern_id=pattern.id,
            component_name=provider.name,
            component_type="provider",
            severity=pattern.severity,
            cwe=pattern.cwe,
            detail=f"Le FileProvider '{provider.name}' est exporté (exported=true). Cela permet à n'importe quelle application de lire/écrire les fichiers partagés sans restriction d'URI.",
            evidence={"is_file_provider": True, "exported": True}
        ))
        
    return findings
def check_fileprovider_config(provider: Provider) -> List[Finding]:
    """Vérifie la configuration interne obligatoire d'un FileProvider."""
    findings = []
    
    if not provider.is_file_provider:
        return findings

    # 1. Vérification du grantUriPermissions
    if not provider.grant_uri_permissions:
        pattern = PATTERNS["FILEPROVIDER_URI_PERM_MISSING"]
        findings.append(Finding(
            pattern_id=pattern.id, component_name=provider.name, component_type="provider",
            severity=pattern.severity, cwe=pattern.cwe,
            detail=f"Le FileProvider '{provider.name}' ne définit pas grantUriPermissions='true'. L'accès sécurisé par URI ne fonctionnera pas.",
            evidence={"grant_uri_permissions": False}
        ))

    # 2. Vérification de la présence de la balise meta-data
    has_paths_meta = False
    for meta in provider.meta_data:
        if meta.name in ["android.support.FILE_PROVIDER_PATHS", "androidx.core.content.FILE_PROVIDER_PATHS"]:
            has_paths_meta = True
            break

    if not has_paths_meta:
        pattern = PATTERNS["FILEPROVIDER_MISSING_METADATA"]
        findings.append(Finding(
            pattern_id=pattern.id, component_name=provider.name, component_type="provider",
            severity=pattern.severity, cwe=pattern.cwe,
            detail=f"Le FileProvider '{provider.name}' ne déclare pas la balise <meta-data> pointant vers le XML des chemins. Configuration invalide.",
            evidence={"meta_data_count": len(provider.meta_data)}
        ))

    return findings
