# ai/surface_scorer.py

from dataclasses import dataclass, field
from typing import Dict, List, Tuple
from ai.feature_extractor import AppFeatures
import pickle
import os
import pandas as pd

MODEL_PATH = os.path.join(os.path.dirname(__file__), "risk_model.pkl")

@dataclass
class ScoreResult:
    total_score: float = 0.0
    level: str = "LOW"
    breakdown: Dict[str, float] = field(default_factory=dict)
    ml_prediction: int = 0
    ml_confidence: float = 0.0
    top_factors: List[Tuple[str, float]] = field(default_factory=list)


WEIGHTS = {
    "exported_components":   0.20,
    "missing_permissions":   0.20,
    "dangerous_permissions": 0.10,
    "app_flags":             0.15,
    "deep_links":            0.05,
    "p1_advanced":           0.10,
    "p2_findings":           0.20,
}

def _clamp(v: float) -> float:
    return max(0.0, min(100.0, v))

def _load_model():
    if not os.path.exists(MODEL_PATH):
        return None
    with open(MODEL_PATH, "rb") as f:
        return pickle.load(f)

def compute_score(features: AppFeatures) -> ScoreResult:
    result = ScoreResult()

    # --- Breakdown par catégorie ---
    total_exported = (
        features.exported_activities + features.exported_services +
        features.exported_receivers + features.exported_providers
    )

    breakdown = {
        "exported_components":   _clamp(total_exported / 10 * 100),
        "missing_permissions":   _clamp(features.missing_permissions_on_exported / 8 * 100),
        "dangerous_permissions": _clamp(features.dangerous_permissions / 5 * 100),
        "app_flags":             _clamp((int(features.debuggable) + int(features.allow_backup) + int(features.uses_cleartext_traffic)) / 3 * 100),
        "deep_links":            _clamp(features.deep_links_exposed / 5 * 100),
        "p1_advanced":           _clamp((features.file_providers_exposed + features.grant_uri_permissions_count + features.direct_boot_aware_receivers + features.task_affinity_set) / 8 * 100),
        "p2_findings":           _clamp((features.critical_findings * 3 + features.high_findings * 2 + features.medium_findings) / 15 * 100),
    }

    total = sum(breakdown[k] * WEIGHTS[k] for k in WEIGHTS)
    result.total_score = round(total, 1)
    result.breakdown = {k: round(v, 1) for k, v in breakdown.items()}

    # --- Niveau de risque (seuils ajustés) ---
    if result.total_score >= 70:
        result.level = "CRITICAL"
    elif result.total_score >= 40:
        result.level = "HIGH"
    elif result.total_score >= 20:
        result.level = "MEDIUM"
    else:
        result.level = "LOW"

    # --- ML prediction ---
    model = _load_model()
    if model:
        vector = pd.DataFrame(
            [features.to_vector()],
            columns=AppFeatures.feature_names()
        )
        result.ml_prediction = int(model.predict(vector)[0])
        result.ml_confidence = round(
            float(model.predict_proba(vector)[0][result.ml_prediction]) * 100, 1
        )

        # Top 5 facteurs les plus importants
        names = AppFeatures.feature_names()
        importances = model.feature_importances_
        result.top_factors = sorted(
            zip(names, importances),
            key=lambda x: x[1],
            reverse=True
        )[:5]
    return result