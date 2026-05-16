# ai/train_model.py
# Lance ce fichier UNE SEULE FOIS pour générer risk_model.pkl

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import pickle
import os

CSV_PATH = os.path.join(os.path.dirname(__file__), "dataset.csv")
MODEL_PATH = os.path.join(os.path.dirname(__file__), "risk_model.pkl")

def train():
    df = pd.read_csv(CSV_PATH)
    X = df.drop("risk_label", axis=1)
    y = df["risk_label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    print("=== Evaluation du modèle ===")
    print(classification_report(y_test, model.predict(X_test), zero_division=0))

    with open(MODEL_PATH, "wb") as f:
        pickle.dump(model, f)

    print(f"Modèle sauvegardé → {MODEL_PATH}")

if __name__ == "__main__":
    train()