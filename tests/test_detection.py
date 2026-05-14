import pytest
from core.component_model import AppManifest, Activity, IntentFilter
from detection.risk_patterns import (
    check_manifest_flags, 
    check_exported_no_permission, 
    check_implicit_intent_sensitive
)

def test_debuggable_and_backup_flags():
    """Vérifie que les failles globales du Manifest sont bien détectées."""
    manifest = AppManifest(package="com.test", debuggable=True, allow_backup=True)
    findings = check_manifest_flags(manifest)
    
    assert len(findings) == 2
    assert findings[0].pattern_id == "DEBUGGABLE_TRUE"
    assert findings[1].pattern_id == "ALLOW_BACKUP_TRUE"

def test_exported_no_permission_detected():
    """Vérifie qu'un composant exporté sans permission lève une alerte critique."""
    comp = Activity(name="VulnActivity", component_type="activity", exported=True, permission=None)
    findings = check_exported_no_permission(comp)
    
    assert len(findings) == 1
    assert findings[0].pattern_id == "EXPORTED_NO_PERM"
    assert findings[0].severity.value == "critical"

def test_exported_with_permission_is_safe():
    """Vérifie qu'un composant protégé par permission NE lève PAS d'alerte."""
    comp = Activity(name="SafeActivity", component_type="activity", exported=True, permission="android.permission.CAMERA")
    findings = check_exported_no_permission(comp)
    
    assert len(findings) == 0

def test_implicit_intent_sensitive_detected():
    """Vérifie qu'une action système écoutée lève une alerte de Hijacking."""
    # On simule un intent qui écoute les SMS
    intent = IntentFilter(actions=["android.provider.Telephony.SMS_RECEIVED"])
    comp = Activity(name="SmsReceiver", component_type="receiver", exported=True, intent_filters=[intent])
    
    findings = check_implicit_intent_sensitive(comp)
    
    assert len(findings) == 1
    assert findings[0].pattern_id == "IMPLICIT_INTENT_SENSITIVE"

from core.component_model import Provider
from detection.fileprovider_checker import check_fileprovider_exported

def test_fileprovider_exported_detected():
    """Vérifie qu'un FileProvider exporté lève bien une alerte critique."""
    # On crée nous-mêmes un faux composant pour tester notre règle, 
    # sans avoir besoin d'un vrai fichier XML parsé par P1 !
    provider = Provider(name="MyVulnFileProvider", component_type="provider", exported=True, is_file_provider=True)
    findings = check_fileprovider_exported(provider)
    
    assert len(findings) == 1
    assert findings[0].pattern_id == "FILEPROVIDER_EXPORTED"
    assert findings[0].severity.value == "critical"

from detection.permission_analyzer import analyze_permissions

def test_dangerous_perm_missing_detected():
    """Vérifie le scénario d'attaque Confused Deputy (CWE-862)."""
    # 1. On crée une Activity vulnérable (exportée, sans permission)
    vuln_activity = Activity(name="BridgeActivity", component_type="activity", exported=True, permission=None)
    
    # 2. On simule un Manifest qui possède cette Activity ET une permission dangereuse (ex: lire les SMS)
    manifest = AppManifest(
        package="com.vuln.app",
        uses_permissions=["android.permission.RECEIVE_SMS"], # Permission critique globale
        activities=[vuln_activity]
    )
    
    # 3. On lance l'analyse
    findings = analyze_permissions(manifest)
    
    # 4. On vérifie que notre moteur lève bien l'alerte
    assert len(findings) == 1
    assert findings[0].pattern_id == "DANGEROUS_PERM_MISSING"
    assert findings[0].severity.value == "high"
