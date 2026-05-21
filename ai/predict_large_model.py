from pathlib import Path

import joblib

from ai.drebin_apk_adapter import apk_to_drebin_dataframe


ROOT = Path(__file__).resolve().parents[1]
MODEL_PATH = ROOT / "data" / "models" / "best_model.joblib"


def predict_apk_with_large_model(apk_path: str):
    if not MODEL_PATH.exists():
        print("[ML] No trained model found. Skipping ML prediction.")
        return None, 0.0

    try:
        model = joblib.load(MODEL_PATH)

        X = apk_to_drebin_dataframe(apk_path)

        prediction = int(model.predict(X)[0])

        confidence = 0.0
        if hasattr(model, "predict_proba"):
            probabilities = model.predict_proba(X)[0]
            confidence = round(float(max(probabilities)) * 100, 2)

        return prediction, confidence

    except Exception as e:
        print(f"[ML] Prediction failed: {e}")
        return None, 0.0