from typing import List
from .component_model import IntentFilter

# Namespace Android dans le Manifest
NS = "http://schemas.android.com/apk/res/android"

def _attr(element, name: str) -> str:
    """Lecture d'un attribut dans le namespace Android."""
    return element.get(f"{{{NS}}}{name}", "")

def parse_intent_filters(component_node) -> List[IntentFilter]:
    """
    Extrait tous les <intent-filter> d'un nœud de composant XML.
    Retourne une liste d'IntentFilter (vide si aucun).
    """
    filters = []
    for ifilter in component_node.findall("intent-filter"):
        f = IntentFilter()

        # Actions : ex. android.intent.action.MAIN
        f.actions = [
            _attr(a, "name")
            for a in ifilter.findall("action")
            if _attr(a, "name")
        ]

        # Catégories : ex. android.intent.category.DEFAULT
        f.categories = [
            _attr(c, "name")
            for c in ifilter.findall("category")
            if _attr(c, "name")
        ]

        # Deep links : balises <data>
        for data in ifilter.findall("data"):
            scheme = _attr(data, "scheme")
            host   = _attr(data, "host")
            path   = _attr(data, "path")
            if scheme: f.data_schemes.append(scheme)
            if host:   f.data_hosts.append(host)
            if path:   f.data_paths.append(path)

        filters.append(f)
    return filters