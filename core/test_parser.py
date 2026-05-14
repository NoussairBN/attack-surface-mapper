import pytest
from pathlib import Path
from core.manifest_parser import parse_manifest

FIXTURE = Path(__file__).parent / "fixtures/manifest_export_no_perm.xml"

def test_package_parsed():
    m = parse_manifest(str(FIXTURE))
    assert m.package == "com.example.vuln"

def test_debuggable_detected():
    m = parse_manifest(str(FIXTURE))
    assert m.debuggable == True

def test_allow_backup():
    m = parse_manifest(str(FIXTURE))
    assert m.allow_backup == True

def test_activities_count():
    m = parse_manifest(str(FIXTURE))
    assert len(m.activities) == 2

def test_exported_explicit():
    m = parse_manifest(str(FIXTURE))
    main = m.activities[0]
    assert main.exported == True

def test_exported_implicit_via_intent_filter():
    # DeepLinkActivity n'a pas android:exported déclaré
    # mais a un intent-filter → doit être traité comme exporté
    m = parse_manifest(str(FIXTURE))
    deep = m.activities[1]
    assert deep.exported == True

def test_deep_link_parsed():
    m = parse_manifest(str(FIXTURE))
    deep = m.activities[1]
    ifilter = deep.intent_filters[0]
    assert "myapp" in ifilter.data_schemes
    assert "open"  in ifilter.data_hosts

def test_service_not_exported():
    m = parse_manifest(str(FIXTURE))
    assert m.services[0].exported == False

def test_sdk_versions():
    m = parse_manifest(str(FIXTURE))
    assert m.min_sdk == 21
    assert m.target_sdk == 33