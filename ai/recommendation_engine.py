# ai/recommendation_engine.py

from typing import List, Dict
from ai.feature_extractor import AppFeatures


def generate_recommendations(features: AppFeatures) -> List[Dict]:
    recs = []

    if features.debuggable:
        recs.append({
            "title": "Désactiver le mode debug",
            "priority": "CRITICAL",
            "patch": 'android:debuggable="false"',
            "description": "Ne jamais shipper avec debuggable=true. Gradle active automatiquement le debug en build debug.",
        })
    if features.allow_backup:
        recs.append({
            "title": "Désactiver la sauvegarde ADB",
            "priority": "HIGH",
            "patch": 'android:allowBackup="false"',
            "description": "Utilisez l'API BackupAgent pour contrôler précisément les données sauvegardées.",
        })
    if features.uses_cleartext_traffic:
        recs.append({
            "title": "Forcer HTTPS uniquement",
            "priority": "HIGH",
            "patch": 'android:usesCleartextTraffic="false"',
            "description": "Créez un network_security_config.xml pour un contrôle granulaire du trafic réseau.",
        })
    if features.missing_permissions_on_exported > 0:
        recs.append({
            "title": "Protéger les composants exportés",
            "priority": "CRITICAL",
            "patch": 'android:permission="com.example.MY_PERMISSION"',
            "description": "Définissez une permission custom avec protectionLevel='signature' sur chaque composant exporté.",
        })
    if features.file_providers_exposed > 0:
        recs.append({
            "title": "Restreindre l'accès aux FileProviders",
            "priority": "HIGH",
            "patch": 'android:exported="false" sur le FileProvider',
            "description": "Un FileProvider ne doit jamais être exporté. Partagez les fichiers uniquement via Intent avec grantUriPermission.",
        })
    if features.grant_uri_permissions_count > 0:
        recs.append({
            "title": "Limiter les grantUriPermissions",
            "priority": "MEDIUM",
            "patch": "Définir <grant-uri-permission> avec des paths précis",
            "description": "Évitez path='/' (accès total). Limitez à des sous-répertoires précis dans le file_paths.xml.",
        })
    if features.task_affinity_set > 0:
        recs.append({
            "title": "Supprimer les taskAffinity non nécessaires",
            "priority": "MEDIUM",
            "patch": 'android:taskAffinity=""',
            "description": "Mettre taskAffinity vide empêche le task hijacking par des applications malveillantes.",
        })
    if features.deep_links_exposed > 0:
        recs.append({
            "title": "Vérifier les deep links avec App Links",
            "priority": "MEDIUM",
            "patch": 'android:autoVerify="true" + assetlinks.json',
            "description": "Utilisez Android App Links pour lier cryptographiquement votre app à votre domaine.",
        })

    return recs