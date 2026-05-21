import subprocess
import tempfile
import os
import shutil
from pathlib import Path
from core.manifest_parser import parse_manifest
from core.component_model import AppManifest


class ApkExtractionError(Exception):
    """Levée quand apktool échoue ou que le manifest est absent."""


def _resolve_apktool_command() -> list:
    """
    Trouve la bonne commande apktool selon le système.
    Teste dans l'ordre : apktool, apktool.bat, APKTOOL_PATH env, chemin fixe Windows.
    """
    candidates = []

    # Variable d'environnement en priorité
    env_path = os.environ.get("APKTOOL_PATH")
    if env_path and Path(env_path).exists():
        candidates.append([env_path])

    # Chemins fixes Windows courants
    candidates += [
        ["apktool"],
        ["apktool.bat"],
        [r"C:\Windows\apktool.bat"],
        [r"C:\apktool\apktool.bat"],
    ]

    for cmd in candidates:
        try:
            result = subprocess.run(
                cmd + ["--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                print(f"      apktool trouvé : {' '.join(cmd)} (v{result.stdout.strip().splitlines()[0]})")
                return cmd
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue

    raise ApkExtractionError(
        "apktool introuvable. Installe-le depuis https://apktool.org "
        "et assure-toi qu'il est dans le PATH."
    )


def extract_manifest_from_apk(apk_path: str) -> AppManifest:
    """
    Pipeline complet :
    1. Lance apktool pour décompiler l'APK dans un dossier temp
    2. Récupère AndroidManifest.xml (texte décodé)
    3. Parse via manifest_parser et retourne AppManifest
    4. Nettoie le dossier temporaire
    """
    apk = Path(apk_path).resolve()
    if not apk.exists():
        raise FileNotFoundError(f"APK non trouvé : {apk_path}")

    apktool_cmd = _resolve_apktool_command()

    tmp_dir = tempfile.mkdtemp(prefix="asm_apktool_")
    print(f"      Dossier temp : {tmp_dir}")

    try:
        cmd = apktool_cmd + [
            "d",           # decode
            str(apk),
            "--no-src",    # skip smali → plus rapide
            "-o", tmp_dir,
            "-f",          # force overwrite
        ]
        print(f"      Commande    : {' '.join(cmd)}")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )

        # Affiche la sortie apktool pour debug
        if result.stdout.strip():
            for line in result.stdout.strip().splitlines()[-5:]:
                print(f"      [apktool] {line}")
        if result.stderr.strip():
            for line in result.stderr.strip().splitlines()[-5:]:
                print(f"      [apktool ERR] {line}")

        if result.returncode != 0:
            raise ApkExtractionError(
                f"apktool a échoué (code {result.returncode}) :\n{result.stderr}"
            )

        # Liste le contenu extrait
        extracted = os.listdir(tmp_dir)
        print(f"      Fichiers extraits : {extracted}")

        manifest_path = os.path.join(tmp_dir, "AndroidManifest.xml")
        if not os.path.exists(manifest_path):
            raise ApkExtractionError(
                f"AndroidManifest.xml absent apres extraction.\n"
                f"Contenu du dossier : {extracted}"
            )

        print(f"      Manifest trouve, parsing...")
        return parse_manifest(manifest_path)

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def analyze_apk(apk_path: str) -> AppManifest:
    """Alias public utilisé par les autres modules (P2, P3, P4)."""
    return extract_manifest_from_apk(apk_path)