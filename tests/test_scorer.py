# tests/test_scorer.py

import pytest
from core.component_model import AppManifest, Activity, Service, Receiver, Provider, IntentFilter
from ai.feature_extractor import extract_features
from ai.finding_adapter import enrich_features_with_findings
from ai.surface_scorer import compute_score
from ai.explainer import explain
from ai.recommendation_engine import generate_recommendations


# --- Fixtures ---

class MockFinding:
    def __init__(self, severity): self.severity = severity

VULNERABLE = AppManifest(
    package="com.test.vulnerable",
    debuggable=True, allow_backup=True,
    uses_permissions=["android.permission.READ_SMS", "android.permission.CAMERA",
                      "android.permission.ACCESS_FINE_LOCATION"],
    activities=[Activity(name="com.test.MainActivity", exported=True, permission=None,
                         intent_filters=[IntentFilter(categories=["android.intent.category.BROWSABLE"])],
                         task_affinity="com.evil")],
    services=[Service(name="com.test.SyncService", exported=True, permission=None)],
    receivers=[Receiver(name="com.test.BootReceiver", exported=True, permission=None,
                        direct_boot_aware=True)],
    providers=[Provider(name="com.test.FP", exported=True, is_file_provider=True,
                        grant_uri_permissions=True)],
)

SECURE = AppManifest(
    package="com.test.secure",
    debuggable=False, allow_backup=False,
    uses_permissions=["android.permission.INTERNET"],
    activities=[Activity(name="com.test.Main", exported=True,
                         permission="com.test.PERM")],
)

FAKE_FINDINGS = [MockFinding("CRITICAL"), MockFinding("HIGH"), MockFinding("MEDIUM")]


# --- Tests feature extractor ---

def test_vulnerable_features():
    f = extract_features(VULNERABLE)
    assert f.debuggable is True
    assert f.allow_backup is True
    assert f.file_providers_exposed == 1
    assert f.direct_boot_aware_receivers == 1
    assert f.task_affinity_set == 1

def test_secure_no_critical_features():
    f = extract_features(SECURE)
    assert f.debuggable is False
    assert f.missing_permissions_on_exported == 0


# --- Tests finding adapter ---

def test_finding_adapter_counts():
    f = extract_features(VULNERABLE)
    f = enrich_features_with_findings(f, FAKE_FINDINGS)
    assert f.critical_findings == 1
    assert f.high_findings == 1
    assert f.medium_findings == 1


# --- Tests scorer ---

def test_vulnerable_score_high():
    f = extract_features(VULNERABLE)
    f = enrich_features_with_findings(f, FAKE_FINDINGS)
    r = compute_score(f)
    assert r.total_score > 40
    assert r.level in ("HIGH", "CRITICAL")

def test_secure_score_low():
    f = extract_features(SECURE)
    r = compute_score(f)
    assert r.total_score < 40

def test_score_in_range():
    f = extract_features(VULNERABLE)
    r = compute_score(f)
    assert 0 <= r.total_score <= 100


# --- Tests explainer ---

def test_explain_debuggable():
    f = extract_features(VULNERABLE)
    exps = explain(f, {})
    assert any("debuggable" in e["issue"].lower() for e in exps)

def test_explain_file_provider():
    f = extract_features(VULNERABLE)
    exps = explain(f, {})
    assert any("FileProvider" in e["issue"] for e in exps)


# --- Tests recommandations ---

def test_recs_vulnerable():
    f = extract_features(VULNERABLE)
    recs = generate_recommendations(f)
    assert len(recs) >= 3
    assert any(r["priority"] == "CRITICAL" for r in recs)

def test_recs_secure():
    f = extract_features(SECURE)
    recs = generate_recommendations(f)
    assert not any(r["priority"] == "CRITICAL" for r in recs)