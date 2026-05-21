import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pandas as pd

from core.apk_extractor import _resolve_apktool_command


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "data" / "models" / "feature_schema.json"

TEXT_EXTENSIONS = {
    ".xml",
    ".smali",
    ".txt",
    ".yml",
    ".yaml",
    ".json",
    ".properties",
    ".cfg",
    ".ini",
    ".java",
    ".kt",
}


def normalize_text(value: str) -> str:
    """
    Normalise les noms pour pouvoir comparer :
    - SEND_SMS
    - android.permission.SEND_SMS
    - Ljava/lang/Class;->getMethod
    - Ljava.lang.Class.getMethod
    """
    value = value.lower()
    value = value.replace("android.permission.", "")
    value = re.sub(r"[^a-z0-9]+", "", value)
    return value


def decompile_full_apk(apk_path: str) -> str:
    apk = Path(apk_path).resolve()

    if not apk.exists() or not apk.is_file():
        raise FileNotFoundError(f"APK not found or not a file: {apk}")

    apktool_cmd = _resolve_apktool_command()
    tmp_dir = tempfile.mkdtemp(prefix="asm_drebin_")

    cmd = apktool_cmd + [
        "d",
        "-f",
        "-o",
        tmp_dir,
        str(apk),
    ]

    print(f"[ML] Full APK decompilation: {' '.join(cmd)}")

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=180,
    )

    if result.returncode != 0:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise RuntimeError(
            "apktool failed during full APK decompilation:\n"
            + result.stdout
            + "\n"
            + result.stderr
        )

    return tmp_dir


def collect_text_from_decompiled_apk(folder: str) -> str:
    parts = []

    for path in Path(folder).rglob("*"):
        if not path.is_file():
            continue

        if path.suffix.lower() not in TEXT_EXTENSIONS:
            continue

        try:
            if path.stat().st_size > 2_000_000:
                continue

            content = path.read_text(encoding="utf-8", errors="ignore")
            parts.append(content)

        except Exception:
            continue

    return "\n".join(parts)


def apk_to_drebin_dataframe(apk_path: str) -> pd.DataFrame:
    if not SCHEMA_PATH.exists():
        raise FileNotFoundError(
            "feature_schema.json not found. Run ai/train_large_dataset.py first."
        )

    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        feature_names = json.load(f)

    tmp_dir = None

    try:
        tmp_dir = decompile_full_apk(apk_path)
        raw_text = collect_text_from_decompiled_apk(tmp_dir)
        normalized_apk_text = normalize_text(raw_text)

        row = {}

        for feature in feature_names:
            normalized_feature = normalize_text(feature)

            if normalized_feature and normalized_feature in normalized_apk_text:
                row[feature] = 1
            else:
                row[feature] = 0

        return pd.DataFrame([row], columns=feature_names)

    finally:
        if tmp_dir:
            shutil.rmtree(tmp_dir, ignore_errors=True)