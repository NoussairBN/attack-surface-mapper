import sys
from pathlib import Path

# ── Imports P1 ──────────────────────────────────────────────────────
from core.manifest_parser import parse_manifest
from core.apk_extractor import analyze_apk
from core.component_model import AppManifest

# ── Imports P2 ──────────────────────────────────────────────────────
from detection.risk_patterns import analyze_all_components

# ── Imports P4 / IA ─────────────────────────────────────────────────
from ai.feature_extractor import extract_features
from ai.finding_adapter import enrich_features_with_findings
from ai.surface_scorer import compute_score
from ai.explainer import explain
from ai.recommendation_engine import generate_recommendations
from ai.predict_large_model import predict_apk_with_large_model

# ── Rapport ─────────────────────────────────────────────────────────
from reports.report_generator import generate_html_report


def is_apk_file(path: Path) -> bool:
    """Vérifie si le fichier donné est une APK."""
    return path.suffix.lower() == ".apk"


def print_manifest_summary(manifest: AppManifest):
    """Affiche un résumé du manifest extrait."""
    print(f"      Package      : {manifest.package}")
    print(f"      SDK min      : {manifest.min_sdk}")
    print(f"      SDK target   : {manifest.target_sdk}")
    print(f"      Activities   : {len(manifest.activities)}")
    print(f"      Services     : {len(manifest.services)}")
    print(f"      Receivers    : {len(manifest.receivers)}")
    print(f"      Providers    : {len(manifest.providers)}")


def print_findings_summary(findings: list):
    """Affiche le nombre de findings par sévérité."""
    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }

    for finding in findings:
        severity = str(finding.severity).upper()

        for key in severity_counts:
            if key in severity:
                severity_counts[key] += 1
                break

    print(f"      Findings total : {len(findings)}")

    for severity, count in severity_counts.items():
        if count > 0:
            print(f"      └─ {severity:<10}: {count}")


def run_pipeline(input_path: str, output_html: str = "report.html"):
    """
    Pipeline complet Attack Surface Mapper :

    1. Décompile l'APK ou parse directement un AndroidManifest.xml
    2. Extrait les composants Android
    3. Détecte les vulnérabilités par règles
    4. Extrait les features internes du projet
    5. Calcule le score statique
    6. Si l'entrée est une APK, applique le modèle ML entraîné sur Drebin-215
    7. Génère le rapport HTML final
    """

    input_file = Path(input_path).resolve()
    output_file = Path(output_html).resolve()

    print("\n" + "=" * 60)
    print("   ATTACK SURFACE MAPPER — Pipeline Complet")
    print("=" * 60)

    # ── ÉTAPE 1 : Parsing du manifest ou APK ────────────────────────
    print(f"\n[1/5] Parsing du manifest / APK → {input_file}")

    if is_apk_file(input_file):
        manifest: AppManifest = analyze_apk(str(input_file))
    else:
        manifest: AppManifest = parse_manifest(str(input_file))

    print_manifest_summary(manifest)

    # ── ÉTAPE 2 : Détection des vulnérabilités P2 ───────────────────
    print("\n[2/5] Analyse des vulnérabilités par règles...")

    findings = analyze_all_components(manifest)
    print_findings_summary(findings)

    # ── ÉTAPE 3 : Extraction des features internes ──────────────────
    print("\n[3/5] Extraction des features internes...")

    features = extract_features(manifest)
    features = enrich_features_with_findings(features, findings)

    print(f"      Vector dimension            : {len(features.to_vector())}")
    print(f"      Critical findings enrichis  : {features.critical_findings}")
    print(f"      High findings enrichis      : {features.high_findings}")
    print(f"      Medium findings enrichis    : {features.medium_findings}")

    # ── ÉTAPE 4 : Score statique + prédiction ML ────────────────────
    print("\n[4/5] Calcul du score de risque...")

    result = compute_score(features)

    print(f"      Score statique : {result.total_score}/100")
    print(f"      Niveau         : {result.level}")

    # Le grand modèle ML Drebin ne s'applique qu'aux APKs,
    # car il doit scanner le fichier APK décompilé.
    if is_apk_file(input_file):
        print("\n      [ML] Prédiction avec le modèle entraîné sur Drebin-215...")

        ml_prediction, ml_confidence = predict_apk_with_large_model(str(input_file))

        result.ml_prediction = ml_prediction
        result.ml_confidence = ml_confidence

        if ml_prediction is not None and ml_confidence > 0:
            ml_label = "RISQUÉ" if ml_prediction == 1 else "SÛR"
            print(f"      [ML] Résultat    : {ml_label}")
            print(f"      [ML] Confiance   : {ml_confidence}%")
        else:
            print("      [ML] Aucun modèle disponible ou prédiction impossible.")
    else:
        print("      [ML] Ignoré : l'entrée n'est pas une APK.")

    # ── ÉTAPE 5 : Explications, recommandations, rapport ────────────
    print("\n[5/5] Génération des explications et recommandations...")

    explanations = explain(features, result.breakdown)
    recommendations = generate_recommendations(features)

    print(f"      Explications     : {len(explanations)}")
    print(f"      Recommandations  : {len(recommendations)}")

    print(f"\n[→] Génération du rapport HTML → {output_file}")

    generate_html_report(
        manifest=manifest,
        findings=findings,
        features=features,
        score_result=result,
        explanations=explanations,
        recommendations=recommendations,
        output_path=str(output_file),
    )

    print(f"     ✅ Rapport généré : {output_file}")
    print("\n" + "=" * 60)

    return {
        "manifest": manifest,
        "findings": findings,
        "features": features,
        "score": result,
        "explanations": explanations,
        "recommendations": recommendations,
    }


if __name__ == "__main__":
    # Usage :
    # python demo.py tests/InsecureBankv2.apk report.html
    # python demo.py tests/AndroidManifest.xml report.html

    if len(sys.argv) < 2:
        print("Usage: python demo.py <APK|AndroidManifest.xml> [output.html]")
        sys.exit(1)

    input_path = Path(sys.argv[1])
    output_html = sys.argv[2] if len(sys.argv) > 2 else "report.html"

    if not input_path.exists():
        print(f"Erreur : fichier introuvable → {input_path}")
        sys.exit(1)

    if not input_path.is_file():
        print(f"Erreur : le chemin existe mais ce n'est pas un fichier → {input_path}")
        sys.exit(1)

    run_pipeline(str(input_path), output_html)