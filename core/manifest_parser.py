from lxml import etree
from typing import Optional
from .component_model import (
    AppManifest, Activity, Service, Receiver, Provider
)
from .intent_filter_parser import parse_intent_filters

NS = "http://schemas.android.com/apk/res/android"

def _attr(el, name: str, default: str = "") -> str:
    return el.get(f"{{{NS}}}{name}", default)

def _bool_attr(el, name: str, default: bool = False) -> bool:
    v = _attr(el, name, str(default)).lower()
    return v == "true"

def _exported(el, has_intent_filters: bool) -> Optional[bool]:
    """
    Android règle : si exported n'est pas déclaré ET qu'il y a
    des intent-filters → exported=True implicitement (risqué !).
    """
    raw = _attr(el, "exported")
    if raw == "true":  return True
    if raw == "false": return False
    return True if has_intent_filters else None

def _parse_activity(el) -> Activity:
    ifilters = parse_intent_filters(el)
    return Activity(
        name           = _attr(el, "name"),
        component_type = "activity",
        exported       = _exported(el, bool(ifilters)),
        permission     = _attr(el, "permission") or None,
        intent_filters = ifilters,
        enabled        = _bool_attr(el, "enabled", True),
        task_affinity  = _attr(el, "taskAffinity") or None,
        launch_mode    = _attr(el, "launchMode")  or None,
    )

def _parse_service(el) -> Service:
    ifilters = parse_intent_filters(el)
    return Service(
        name            = _attr(el, "name"),
        component_type  = "service",
        exported        = _exported(el, bool(ifilters)),
        permission      = _attr(el, "permission") or None,
        intent_filters  = ifilters,
        enabled         = _bool_attr(el, "enabled", True),
        foreground_service_type = _attr(el, "foregroundServiceType") or None,
    )

def _parse_receiver(el) -> Receiver:
    ifilters = parse_intent_filters(el)
    return Receiver(
        name               = _attr(el, "name"),
        component_type     = "receiver",
        exported           = _exported(el, bool(ifilters)),
        permission         = _attr(el, "permission") or None,
        intent_filters     = ifilters,
        enabled            = _bool_attr(el, "enabled", True),
        direct_boot_aware  = _bool_attr(el, "directBootAware"),
    )

def _parse_provider(el) -> Provider:
    ifilters = parse_intent_filters(el)
    name = _attr(el, "name")
    return Provider(
        name              = name,
        component_type    = "provider",
        exported          = _exported(el, bool(ifilters)),
        permission        = _attr(el, "permission") or None,
        intent_filters    = ifilters,
        enabled           = _bool_attr(el, "enabled", True),
        authorities       = _attr(el, "authorities") or None,
        read_permission   = _attr(el, "readPermission") or None,
        write_permission  = _attr(el, "writePermission") or None,
        grant_uri_permissions = _bool_attr(el, "grantUriPermissions"),
        is_file_provider  = "FileProvider" in name,
    )

def parse_manifest(manifest_path: str) -> AppManifest:
    """
    Point d'entrée principal.
    manifest_path : chemin vers un AndroidManifest.xml décodé (texte).
    Retourne un objet AppManifest complet.
    """
    tree = etree.parse(manifest_path)
    root = tree.getroot()
    app  = root.find("application")

    manifest = AppManifest(
        package    = root.get("package", ""),
        min_sdk    = _int_or_none(root.find("uses-sdk"), "minSdkVersion"),
        target_sdk = _int_or_none(root.find("uses-sdk"), "targetSdkVersion"),
        debuggable         = _bool_attr(app, "debuggable", False),
        allow_backup       = _bool_attr(app, "allowBackup", True),
        network_security_config = _attr(app, "networkSecurityConfig") or None,
    )
    if app is not None:
        manifest.activities = [_parse_activity(e) for e in app.findall("activity")]
        manifest.services   = [_parse_service(e)  for e in app.findall("service")]
        manifest.receivers  = [_parse_receiver(e) for e in app.findall("receiver")]
        manifest.providers  = [_parse_provider(e) for e in app.findall("provider")]
    return manifest

def _int_or_none(el, attr: str) -> Optional[int]:
    if el is None: return None
    v = _attr(el, attr)
    return int(v) if v.isdigit() else None