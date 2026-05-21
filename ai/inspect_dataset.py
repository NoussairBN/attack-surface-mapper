from pathlib import Path
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "data" / "external" / "android_malware_dataset.csv"

df = pd.read_csv(DATASET, low_memory=False)

print("Shape:", df.shape)
print("\nColumns:")
for col in df.columns:
    print(col)

print("\nFirst rows:")
print(df.head())

print("\nPossible label values:")
for col in ["class", "Class", "label", "Label", "malware", "Malware"]:
    if col in df.columns:
        print(col)
        print(df[col].value_counts())