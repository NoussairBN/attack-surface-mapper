# Attack Surface Mapper

## Prerequisites

- Python 3.14
- The local virtual environment at `.venv`
- `apktool.bat` available at `C:\xampp\htdocs\projet\apktool.bat`

## Install

```powershell
& ".venv\Scripts\python.exe" -m pip install -r requirements.txt
```

## Run the parser test on UnCrackable Level 2

```powershell
& ".venv\Scripts\python.exe" -m pytest tests\test_apk_extractor.py
```

## Run the parser manually on the APK

```powershell
& ".venv\Scripts\python.exe" -c "from core.apk_extractor import analyze_apk; m = analyze_apk(r'C:\xampp\htdocs\projet\UnCrackable-Level2.apk'); print(m.package); print(len(m.activities)); print(len(m.services)); print(len(m.receivers)); print(len(m.providers))"
```

## Expected result

- package: `owasp.mstg.uncrackable2`
- activities: `1`
- services: `0`
- receivers: `0`
- providers: `0`

## Suggested task split for a team

- Parser: validate manifest extraction and component parsing
- Detection: improve risk rules and exported component checks
- Graph: verify node/edge generation and export formats
- UI: update CLI/report output and make results easier to read

## Notes

- The workspace uses `.venv`, not the global Python installation.
- `lxml`, `dataclasses-json`, and `pytest` must be installed in `.venv`.
