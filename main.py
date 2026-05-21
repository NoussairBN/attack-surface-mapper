#!/usr/bin/env python3
"""Attack Surface Mapper - Script de Test P2."""

import sys
from pathlib import Path

# Ajoute le dossier courant au PYTHONPATH
sys.path.insert(0, str(Path(__file__).parent))

from core.manifest_parser import parse_manifest
from detection.risk_patterns import analyze_all_components

def run_detection_test():
    print("🚀 Démarrage de l'analyse de sécurité statique...")
    
    # 1. On cible le fichier XML vulnérable préparé par P1
    test_manifest_path = "tests/fixatures/manifest_export_no_perm.xml"
    
    try:
        # 2. P1 fait son travail : Parser le Manifest
        manifest = parse_manifest(test_manifest_path)
        print(f"📦 Package analysé : {manifest.package}\n")
        
        # 3. TU fais ton travail : Détecter les risques
        findings = analyze_all_components(manifest)
        
        # 4. Affichage du rapport brut
        print(f"🚨 {len(findings)} Vulnérabilité(s) trouvée(s) :\n")
        print("-" * 60)
        for finding in findings:
            print(f"[{finding.severity.name}] {finding.pattern_id} | {finding.cwe}")
            print(f"   📍 Composant : {finding.component_name} ({finding.component_type})")
            print(f"   💡 Détail    : {finding.detail}")
            print("-" * 60)
            
    except Exception as e:
        print(f"❌ Erreur lors de l'exécution : {e}")

if __name__ == "__main__":
    run_detection_test()
