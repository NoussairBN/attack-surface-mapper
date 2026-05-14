from pathlib import Path

import pytest

from core import apk_extractor
from core.component_model import AppManifest


def test_resolve_apktool_command_prefers_parent_bat():
    command = apk_extractor._resolve_apktool_command()

    assert command[0].endswith("apktool.bat")


def test_extract_manifest_from_apk_uses_apktool_and_cleans_up(tmp_path, monkeypatch):
    apk_path = tmp_path / "sample.apk"
    apk_path.write_bytes(b"dummy")

    temp_dir = tmp_path / "decoded"
    manifest_path = temp_dir / "AndroidManifest.xml"

    calls = {}

    class DummyResult:
        returncode = 0
        stderr = ""

    def fake_mkdtemp(prefix):
        temp_dir.mkdir()
        return str(temp_dir)

    def fake_run(command, capture_output, text, timeout):
        calls["command"] = command
        calls["capture_output"] = capture_output
        calls["text"] = text
        calls["timeout"] = timeout
        manifest_path.write_text("<manifest />", encoding="utf-8")
        return DummyResult()

    def fake_parse_manifest(path):
        calls["manifest_path"] = path
        return AppManifest(package="com.example.test")

    removed_paths = []

    monkeypatch.setattr(apk_extractor.tempfile, "mkdtemp", fake_mkdtemp)
    monkeypatch.setattr(apk_extractor.subprocess, "run", fake_run)
    monkeypatch.setattr(apk_extractor, "parse_manifest", fake_parse_manifest)
    monkeypatch.setattr(apk_extractor.shutil, "rmtree", lambda path, ignore_errors: removed_paths.append((path, ignore_errors)))

    manifest = apk_extractor.extract_manifest_from_apk(str(apk_path))

    assert manifest.package == "com.example.test"
    assert calls["command"][0].endswith("apktool.bat")
    assert calls["command"][1:] == ["d", str(apk_path), "--no-src", "-o", str(temp_dir), "-f"]
    assert calls["capture_output"] is True
    assert calls["text"] is True
    assert calls["timeout"] == 60
    assert Path(calls["manifest_path"]) == manifest_path
    assert removed_paths == [(str(temp_dir), True)]