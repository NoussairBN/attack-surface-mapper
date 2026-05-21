import sys
import os
import json
from datetime import datetime

# ── Imports P1 ──────────────────────────────────────────────────────
from core.manifest_parser import parse_manifest
from core.apk_extractor import analyze_apk
from core.component_model import AppManifest

# ── Imports P2 ──────────────────────────────────────────────────────
from detection.risk_patterns import analyze_all_components

# ── Imports P4 (notre partie) ────────────────────────────────────────
from ai.feature_extractor import extract_features
from ai.finding_adapter import enrich_features_with_findings
from ai.surface_scorer import compute_score
from ai.explainer import explain
from ai.recommendation_engine import generate_recommendations
from reports.report_generator import generate_html_report


def run_pipeline(manifest_path: str, output_html: str = "report.html"):
    """
    Pipeline complet :
    1. Parse le manifest XML (P1)
    2. Détecte les vulnérabilités (P2)
    3. Extrait les features AI (P4)
    4. Enrichit avec les findings P2 (P4)
    5. Score + explications + recommandations (P4)
    6. Génère le rapport HTML
    """

    print("\n" + "="*60)
    print("   ATTACK SURFACE MAPPER — Pipeline Complet")
    print("="*60)

    # ── ÉTAPE 1 : Parsing du manifest (P1) ──────────────────────────
    print(f"\n[1/5] Parsing du manifest → {manifest_path}")
    if manifest_path.endswith('.apk'):
        manifest: AppManifest = analyze_apk(manifest_path)
    else:
        manifest: AppManifest = parse_manifest(manifest_path)
    print(f"      Package  : {manifest.package}")
    print(f"      SDK min  : {manifest.min_sdk} / target : {manifest.target_sdk}")
    print(f"      Activities : {len(manifest.activities)} | Services : {len(manifest.services)}")
    print(f"      Receivers  : {len(manifest.receivers)} | Providers : {len(manifest.providers)}")

    # ── ÉTAPE 2 : Détection des vulnérabilités (P2) ─────────────────
    print("\n[2/5] Analyse des vulnérabilités (P2)...")
    findings = analyze_all_components(manifest)
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = str(f.severity).upper()
        for key in severity_counts:
            if key in sev:
                severity_counts[key] += 1
                break
    print(f"      Findings : {len(findings)} total")
    for sev, count in severity_counts.items():
        if count > 0:
            print(f"      └─ {sev:<10} : {count}")

    # ── ÉTAPE 3 : Extraction des features AI (P4) ───────────────────
    print("\n[3/5] Extraction des features AI...")
    features = extract_features(manifest)
    features = enrich_features_with_findings(features, findings)
    print(f"      Vector dimension : {len(features.to_vector())} features")
    print(f"      Critical findings enrichis : {features.critical_findings}")
    print(f"      High findings enrichis     : {features.high_findings}")

    # ── ÉTAPE 4 : Scoring ML ────────────────────────────────────────
    print("\n[4/5] Calcul du score de risque...")
    result = compute_score(features)
    print(f"      Score global : {result.total_score}/100")
    print(f"      Niveau       : {result.level}")
    if result.ml_confidence > 0:
        label = "RISQUÉ" if result.ml_prediction else "SÛR"
        print(f"      ML Prediction: {label} (confiance {result.ml_confidence}%)")

    # ── ÉTAPE 5 : Explications & Recommandations ─────────────────────
    explanations = explain(features, result.breakdown)
    recommendations = generate_recommendations(features)
    print(f"\n[5/5] Explications : {len(explanations)} | Recommandations : {len(recommendations)}")

    # ── RAPPORT HTML ─────────────────────────────────────────────────
    print(f"\n[→]  Génération du rapport HTML → {output_html}")
    generate_html_report(
        manifest=manifest,
        findings=findings,
        features=features,
        score_result=result,
        explanations=explanations,
        recommendations=recommendations,
        output_path=output_html,
    )
    print(f"     ✅ Rapport généré : {output_html}")
    print("\n" + "="*60)

    return {
        "manifest": manifest,
        "findings": findings,
        "features": features,
        "score": result,
        "explanations": explanations,
        "recommendations": recommendations,
    }


if __name__ == "__main__":
    # Usage : python demo.py path/to/AndroidManifest.xml [output.html]
    if len(sys.argv) < 2:
        print("Usage: python demo.py <AndroidManifest.xml> [output.html]")
        print("Exemple: python demo.py samples/AndroidManifest.xml report.html")
        sys.exit(1)

    manifest_path = sys.argv[1]
    output_html = sys.argv[2] if len(sys.argv) > 2 else "report.html"

    if not os.path.exists(manifest_path):
        print(f"Erreur : fichier introuvable → {manifest_path}")
        sys.exit(1)

    run_pipeline(manifest_path, output_html)
