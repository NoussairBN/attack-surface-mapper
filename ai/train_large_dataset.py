import json
from pathlib import Path

import joblib
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import SVC
from sklearn.neighbors import KNeighborsClassifier


ROOT = Path(__file__).resolve().parents[1]
DATASET_PATH = ROOT / "data" / "external" / "android_malware_dataset.csv"
MODEL_DIR = ROOT / "data" / "models"
MODEL_DIR.mkdir(parents=True, exist_ok=True)


def normalize_labels(y: pd.Series) -> pd.Series:
    y = y.astype(str).str.lower().str.strip()

    mapping = {
        "b": 0,
        "benign": 0,
        "normal": 0,
        "goodware": 0,
        "safe": 0,
        "0": 0,

        "s": 1,
        "malware": 1,
        "malicious": 1,
        "risky": 1,
        "attack": 1,
        "1": 1,
    }

    y = y.map(mapping)

    if y.isna().any():
        raise ValueError(
            "Some labels could not be converted. "
            "Check the values inside the class column."
        )

    return y.astype(int)


def load_dataset():
    if not DATASET_PATH.exists():
        raise FileNotFoundError(f"Dataset not found: {DATASET_PATH}")

    df = pd.read_csv(DATASET_PATH, low_memory=False)

    print("Dataset loaded:", DATASET_PATH)
    print("Shape:", df.shape)

    if "class" not in df.columns:
        raise ValueError("Column 'class' not found in dataset.")

    y = normalize_labels(df["class"])

    X = df.drop(columns=["class"])

    for col in X.columns:
        X[col] = pd.to_numeric(X[col], errors="coerce").fillna(0).astype(int)

    print("Features:", X.shape[1])
    print("Class distribution:")
    print(y.value_counts())

    return X, y, list(X.columns)


def get_models():
    return {
        "logistic_regression": LogisticRegression(max_iter=1000),
        "random_forest": RandomForestClassifier(
            n_estimators=200,
            random_state=42,
            n_jobs=-1,
        ),
        "gradient_boosting": GradientBoostingClassifier(random_state=42),
        "svm": SVC(probability=True, random_state=42),
        "knn": KNeighborsClassifier(n_neighbors=5),
    }


def train_models():
    X, y, feature_names = load_dataset()

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y,
    )

    results = {}
    best_model = None
    best_name = None
    best_f1 = -1

    for name, model in get_models().items():
        print("\n" + "=" * 60)
        print(f"Training model: {name}")
        print("=" * 60)

        pipeline = Pipeline(
            steps=[
                ("scaler", StandardScaler()),
                ("model", model),
            ]
        )

        pipeline.fit(X_train, y_train)
        y_pred = pipeline.predict(X_test)

        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred, average="weighted", zero_division=0)
        recall = recall_score(y_test, y_pred, average="weighted", zero_division=0)
        f1 = f1_score(y_test, y_pred, average="weighted", zero_division=0)

        results[name] = {
            "accuracy": round(accuracy, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
            "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
        }

        print("Accuracy :", round(accuracy, 4))
        print("Precision:", round(precision, 4))
        print("Recall   :", round(recall, 4))
        print("F1-score :", round(f1, 4))

        if f1 > best_f1:
            best_f1 = f1
            best_model = pipeline
            best_name = name

    results["best_model"] = best_name
    results["feature_count"] = len(feature_names)

    joblib.dump(best_model, MODEL_DIR / "best_model.joblib")

    with open(MODEL_DIR / "feature_schema.json", "w", encoding="utf-8") as f:
        json.dump(feature_names, f, indent=4)

    with open(MODEL_DIR / "metrics.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4)

    print("\n" + "=" * 60)
    print("Best model:", best_name)
    print("Best F1-score:", round(best_f1, 4))
    print("Saved model:", MODEL_DIR / "best_model.joblib")
    print("Saved schema:", MODEL_DIR / "feature_schema.json")
    print("Saved metrics:", MODEL_DIR / "metrics.json")
    print("=" * 60)


if __name__ == "__main__":
    train_models()