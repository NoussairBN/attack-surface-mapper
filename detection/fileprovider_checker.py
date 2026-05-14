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
