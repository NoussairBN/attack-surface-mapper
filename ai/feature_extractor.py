# ai/feature_extractor.py

from dataclasses import dataclass, field
from typing import List
from core.component_model import AppManifest, Activity, Service, Receiver, Provider

DANGEROUS_PERMISSIONS = {
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.READ_CALL_LOG",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.GET_ACCOUNTS",
    "android.permission.USE_BIOMETRIC",
    "android.permission.RECEIVE_SMS",
}

@dataclass
class AppFeatures:
    # --- Composants exportés ---
    exported_activities: int = 0
    exported_services: int = 0
    exported_receivers: int = 0
    exported_providers: int = 0

    # --- Permissions ---
    dangerous_permissions: int = 0
    missing_permissions_on_exported: int = 0

    # --- Flags applicatifs ---
    debuggable: bool = False
    allow_backup: bool = False
    uses_cleartext_traffic: bool = False

    # --- Deep links ---
    deep_links_exposed: int = 0
    implicit_intents_sensitive: int = 0

    # --- Nouveaux champs P1 ---
    file_providers_exposed: int = 0
    grant_uri_permissions_count: int = 0
    direct_boot_aware_receivers: int = 0
    task_affinity_set: int = 0

    # --- Findings P2 (remplis par finding_adapter.py) ---
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0

    def to_vector(self) -> List[float]:
        return [
            self.exported_activities,
            self.exported_services,
            self.exported_receivers,
            self.exported_providers,
            self.dangerous_permissions,
            self.missing_permissions_on_exported,
            float(self.debuggable),
            float(self.allow_backup),
            float(self.uses_cleartext_traffic),
            self.deep_links_exposed,
            self.implicit_intents_sensitive,
            self.file_providers_exposed,
            self.grant_uri_permissions_count,
            self.direct_boot_aware_receivers,
            self.task_affinity_set,
            self.critical_findings,
            self.high_findings,
            self.medium_findings,
        ]

    @staticmethod
    def feature_names() -> List[str]:
        return [
            "exported_activities",
            "exported_services",
            "exported_receivers",
            "exported_providers",
            "dangerous_permissions",
            "missing_permissions_on_exported",
            "debuggable",
            "allow_backup",
            "uses_cleartext_traffic",
            "deep_links_exposed",
            "implicit_intents_sensitive",
            "file_providers_exposed",
            "grant_uri_permissions_count",
            "direct_boot_aware_receivers",
            "task_affinity_set",
            "critical_findings",
            "high_findings",
            "medium_findings",
        ]


SENSITIVE_ACTIONS = {
    "android.intent.action.SEND",
    "android.intent.action.SEND_MULTIPLE",
    "android.intent.action.CALL",
    "android.intent.action.BOOT_COMPLETED",
    "android.provider.Telephony.SMS_RECEIVED",
}


def extract_features(manifest: AppManifest) -> AppFeatures:
    f = AppFeatures()

    # Flags globaux
    f.debuggable = manifest.debuggable
    f.allow_backup = manifest.allow_backup

    # Permissions dangereuses
    used_perms = set(getattr(manifest, "uses_permissions", []))
    f.dangerous_permissions = len(used_perms & DANGEROUS_PERMISSIONS)

    # --- Activities ---
    for activity in manifest.activities:
        is_exported = activity.exported or bool(activity.intent_filters)
        if is_exported:
            f.exported_activities += 1
            if not activity.permission:
                f.missing_permissions_on_exported += 1
        if activity.task_affinity:
            f.task_affinity_set += 1
        for intent in activity.intent_filters:
            if "android.intent.category.BROWSABLE" in intent.categories:
                f.deep_links_exposed += 1
            for action in intent.actions:
                if action in SENSITIVE_ACTIONS and is_exported:
                    f.implicit_intents_sensitive += 1

    # --- Services ---
    for service in manifest.services:
        is_exported = service.exported or bool(service.intent_filters)
        if is_exported:
            f.exported_services += 1
            if not service.permission:
                f.missing_permissions_on_exported += 1

    # --- Receivers ---
    for receiver in manifest.receivers:
        is_exported = receiver.exported or bool(receiver.intent_filters)
        if is_exported:
            f.exported_receivers += 1
            if not receiver.permission:
                f.missing_permissions_on_exported += 1
        if receiver.direct_boot_aware:
            f.direct_boot_aware_receivers += 1

    # --- Providers ---
    for provider in manifest.providers:
        is_exported = provider.exported or False
        if is_exported:
            f.exported_providers += 1
            if not provider.permission:
                f.missing_permissions_on_exported += 1
        if provider.is_file_provider:
            f.file_providers_exposed += 1
        if provider.grant_uri_permissions:
            f.grant_uri_permissions_count += 1

    return f