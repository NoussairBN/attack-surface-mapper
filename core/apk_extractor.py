import subprocess, tempfile, os, shutil
from pathlib import Path
from .manifest_parser import parse_manifest
from .component_model import AppManifest

class ApkExtractionError(Exception):
    """Levée quand apktool échoue ou que le manifest est absent."""


def _resolve_apktool_command() -> list[str]:
    """Retourne la commande apktool à utiliser sur la machine locale."""
    apktool_path = os.environ.get("APKTOOL_PATH")
    if apktool_path:
        return [apktool_path]

    workspace_root = Path(__file__).resolve().parents[1]
    candidate_bat = workspace_root.parent / "apktool.bat"
    if candidate_bat.exists():
        return [str(candidate_bat)]

    candidate_jar = workspace_root.parent / "apktool.jar"
    if candidate_jar.exists():
        return ["java", "-jar", str(candidate_jar)]

    return ["apktool"]

def extract_manifest_from_apk(apk_path: str) -> AppManifest:
    """
    Pipeline complet :
    1. Lance apktool pour décompiler l'APK dans un dossier temp
    2. Récupère AndroidManifest.xml (texte décodé)
    3. Parse via manifest_parser et retourne AppManifest
    4. Nettoie le dossier temporaire
    """
    apk = Path(apk_path)
    if not apk.exists():
        raise FileNotFoundError(f"APK non trouvé : {apk_path}")

    tmp_dir = tempfile.mkdtemp(prefix="asm_apktool_")
    try:
        # Décompile l'APK (--no-src : skip le smali pour aller vite)
        result = subprocess.run(
            _resolve_apktool_command() + ["d", str(apk), "--no-src", "-o", tmp_dir, "-f"],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode != 0:
            raise ApkExtractionError(
                f"apktool a échoué :\n{result.stderr}"
            )
        manifest_path = os.path.join(tmp_dir, "AndroidManifest.xml")
        if not os.path.exists(manifest_path):
            raise ApkExtractionError("AndroidManifest.xml absent après extraction.")

        return parse_manifest(manifest_path)

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)  # nettoyage garanti

def analyze_apk(apk_path: str) -> AppManifest:
    """Alias public utilisé par les autres modules (P2, P3, P4)."""
    return extract_manifest_from_apk(apk_path)