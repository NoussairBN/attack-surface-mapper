from dataclasses import dataclass, field
from typing import List, Optional
from dataclasses_json import dataclass_json

# ── Intent Filter ──────────────────────────────────
@dataclass_json
@dataclass
class IntentFilter:
    actions:    List[str] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)
    # deep links : ex. ["myapp://home", "https://myapp.com"]
    data_schemes: List[str] = field(default_factory=list)
    data_hosts:   List[str] = field(default_factory=list)
    data_paths:   List[str] = field(default_factory=list)

# ── Composant de base ──────────────────────────────
@dataclass_json
@dataclass
class AndroidComponent:
    name:            str  = ""
    component_type:  str  = ""   # activity | service | receiver | provider
    exported:        Optional[bool] = None  # None = non déclaré
    permission:      Optional[str]  = None
    intent_filters:  List[IntentFilter] = field(default_factory=list)
    enabled:         bool = True

# ── Activity ───────────────────────────────────────
@dataclass_json
@dataclass
class Activity(AndroidComponent):
    task_affinity:   Optional[str] = None
    launch_mode:     Optional[str] = None

# ── Service ────────────────────────────────────────
@dataclass_json
@dataclass
class Service(AndroidComponent):
    foreground_service_type: Optional[str] = None

# ── BroadcastReceiver ──────────────────────────────
@dataclass_json
@dataclass
class Receiver(AndroidComponent):
    direct_boot_aware: bool = False

# ── ContentProvider ────────────────────────────────
@dataclass_json
@dataclass
class MetaData:
    name: str = ""
    resource: Optional[str] = None
    value: Optional[str] = None


@dataclass_json
@dataclass
class Provider(AndroidComponent):
    authorities:    Optional[str] = None
    read_permission:  Optional[str] = None
    write_permission: Optional[str] = None
    grant_uri_permissions: bool = False
    is_file_provider: bool = False
    meta_data: List[MetaData] = field(default_factory=list)

# ── Application (manifest global) ──────────────────
@dataclass_json
@dataclass
class AppManifest:
    package:      str  = ""
    min_sdk:      Optional[int]  = None
    target_sdk:   Optional[int]  = None
    debuggable:   bool = False
    allow_backup: bool = True    # défaut Android = True → risqué
    network_security_config: Optional[str] = None
    uses_permissions: List[str] = field(default_factory=list)
    activities:  List[Activity] = field(default_factory=list)
    services:    List[Service]  = field(default_factory=list)
    receivers:   List[Receiver] = field(default_factory=list)
    providers:   List[Provider] = field(default_factory=list)