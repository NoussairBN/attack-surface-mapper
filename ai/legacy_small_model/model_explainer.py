# ai/model_explainer.py

import pickle
import os
from ai.feature_extractor import AppFeatures

MODEL_PATH = os.path.join(os.path.dirname(__file__), "risk_model.pkl")

def print_feature_importance():
    if not os.path.exists(MODEL_PATH):
        print("Modèle introuvable. Lance train_model.py d'abord.")
        return

    with open(MODEL_PATH, "rb") as f:
        model = pickle.load(f)

    names = AppFeatures.feature_names()
    importances = model.feature_importances_

    ranked = sorted(zip(names, importances), key=lambda x: x[1], reverse=True)

    print("\n=== TOP FACTEURS DE RISQUE (RandomForest) ===")
    for i, (name, score) in enumerate(ranked[:10], 1):
        bar = "█" * int(score * 100)
        print(f"  {i:>2}. {name:<40} {bar} {score:.3f}")

if __name__ == "__main__":
    print_feature_importance()