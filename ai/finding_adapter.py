# ai/finding_adapter.py

from ai.feature_extractor import AppFeatures

def enrich_features_with_findings(features: AppFeatures, findings: list) -> AppFeatures:
    """
    Enrichit les features avec les findings détectés par P2.
    Appelé après extract_features(), avant compute_score().
    """
    for finding in findings:
        severity = str(finding.severity).upper()
        if "CRITICAL" in severity:
            features.critical_findings += 1
        elif "HIGH" in severity:
            features.high_findings += 1
        elif "MEDIUM" in severity:
            features.medium_findings += 1

    return features