from pathlib import Path

from core.manifest_parser import parse_manifest


def test_parse_uses_permissions_and_fileprovider_metadata(tmp_path):
		manifest_xml = tmp_path / "AndroidManifest.xml"
		manifest_xml.write_text(
				"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
		package="com.example.app">
	<uses-permission android:name="android.permission.INTERNET" />
	<application>
		<provider
				android:name="androidx.core.content.FileProvider"
				android:authorities="com.example.app.provider">
			<meta-data
					android:name="android.support.FILE_PROVIDER_PATHS"
					android:resource="@xml/file_paths" />
		</provider>
	</application>
</manifest>
""",
				encoding="utf-8",
		)

		manifest = parse_manifest(str(manifest_xml))

		assert manifest.uses_permissions == ["android.permission.INTERNET"]
		assert len(manifest.providers) == 1
		provider = manifest.providers[0]
		assert provider.is_file_provider is True
		assert len(provider.meta_data) == 1
		assert provider.meta_data[0].name == "android.support.FILE_PROVIDER_PATHS"
		assert provider.meta_data[0].resource == "@xml/file_paths"
