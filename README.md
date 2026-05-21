# 🔐 Attack Surface Mapper

A comprehensive Android APK security analysis tool that extracts manifests, detects vulnerabilities, and generates detailed security reports with ML-powered risk scoring.

## 📋 Features

- ✅ **APK Manifest Extraction** - Parse Android manifests and extract components
- ✅ **Vulnerability Detection** - Identify exposed components, risky permissions, debuggable apps
- ✅ **ML-Based Risk Scoring** - Predict attack surface severity with scikit-learn
- ✅ **Interactive Web Interface** - Upload APKs and view reports in real-time
- ✅ **Export Options** - Download reports as HTML or PDF
- ✅ **Docker Support** - Fully containerized for easy deployment
- ✅ **Graph Visualization** - Mermaid-based component relationship graphs

---

## 🚀 Quick Start (Docker - Recommended)

### Prerequisites
- Docker & Docker Desktop installed

### Run the Web Interface

```bash
docker build -t attack-surface-mapper .
docker run -p 5000:5000 attack-surface-mapper
```

Then open: **http://localhost:5000**

Upload an APK file and get a detailed security report instantly!

---

## 💻 Local Development Setup

### Prerequisites

- **Python 3.12+** (or 3.13+)
- **Virtual environment** at `.venv`
- **Java** (for apktool)
- **apktool.bat** available at `C:\xampp\htdocs\projet\apktool.bat`

### Installation

```powershell
# Activate virtual environment
& ".venv\Scripts\Activate.ps1"

# Install dependencies
pip install -r requirements.txt
```

### Run Tests

```powershell
& ".venv\Scripts\python.exe" -m pytest tests\test_apk_extractor.py
```

### Run CLI Parser (Example)

```powershell
& ".venv\Scripts\python.exe" -c "from core.apk_extractor import analyze_apk; m = analyze_apk(r'C:\xampp\htdocs\projet\UnCrackable-Level2.apk'); print(m.package); print(len(m.activities)); print(len(m.services)); print(len(m.receivers)); print(len(m.providers))"
```

**Expected result for UnCrackable Level 2:**
```
Package: owasp.mstg.uncrackable2
Activities: 1
Services: 0
Receivers: 0
Providers: 0
```

### Run Web Interface Locally

```powershell
python ui_app.py
```

Then navigate to: **http://localhost:5000**

---

## 📁 Project Structure

```
attack-surface-mapper/
├── core/                    # APK parsing & manifest extraction
│   ├── apk_extractor.py    # Main APK analysis
│   ├── manifest_parser.py  # Manifest XML parsing
│   ├── component_model.py  # Data models
│   └── test_parser.py
├── detection/              # Security vulnerability detection
│   ├── risk_patterns.py    # Risk rule definitions
│   ├── pattern_registry.py # Pattern matching engine
│   └── fileprovider_checker.py
├── ai/                     # ML-based threat scoring
│   ├── feature_extractor.py      # Feature engineering
│   ├── surface_scorer.py         # Risk scoring model
│   ├── predict_large_model.py    # Large model predictions
│   ├── explainer.py              # Model explainability
│   └── recommendation_engine.py  # Security recommendations
├── graph/                  # Component visualization
│   ├── graph_model.py      # Graph structure
│   ├── mermaid_builder.py  # Mermaid diagram generation
│   └── graph_exporter.py   # Export formats
├── reports/                # Report generation
│   └── report_generator.py # HTML report creation
├── ui/                     # Web interface
│   ├── cli.py             # CLI commands
│   └── report_generator.py
├── tests/                  # Unit & integration tests
├── Dockerfile             # Docker configuration
├── requirements.txt       # Python dependencies
├── demo.py               # CLI demo script
├── ui_app.py             # Flask web application
├── main.py               # Entry point
└── config.yaml           # Configuration file
```

---

## 🔍 Team Task Breakdown

| Component | Responsibility |
|-----------|-----------------|
| **Parser** | Validate manifest extraction and component parsing (P1) |
| **Detection** | Improve risk rules and exported component checks (P2) |
| **Graph** | Verify node/edge generation and export formats (P3) |
| **AI** | ML model training, feature engineering, and explainability (P4) |
| **UI** | Web interface improvements and report visualization |

---

## 📝 Usage Examples

### Docker (Recommended)
```bash
# Build image
docker build -t attack-surface-mapper .

# Run with web interface
docker run -p 5000:5000 attack-surface-mapper

# Use different port if 5000 is busy
docker run -p 5001:5000 attack-surface-mapper
# Then access at http://localhost:5001
```

### Local Python
```bash
# Run CLI demo
python demo.py

# Run specific APK analysis
python -c "from demo import run_pipeline; run_pipeline('path/to/app.apk', 'output_report.html')"

# Run tests
pytest tests/ -v
```

---

## ⚙️ Configuration

Edit `config.yaml` to customize:
- Risk scoring thresholds
- Graph visualization settings
- Report templates
- Security patterns and CWE mappings

---

## 📊 Sample Report Output

The generated security report includes:
- 📋 APK metadata (package name, SDK version, etc.)
- 🔴 Critical/High/Medium/Low vulnerabilities
- 📈 Attack surface scoring breakdown
- 🔗 Component relationship graph
- 💡 Security recommendations

---

## 🛠️ Development Notes

- The workspace uses `.venv`, not the global Python installation
- Required packages: `lxml`, `dataclasses-json`, `pytest`, `flask`, `androguard`, `scikit-learn`
- Docker image is based on `python:3.12-slim` with Java & apktool pre-installed
- Flask development server runs on `0.0.0.0:5000` by default

---

## 📦 Dependencies

See `requirements.txt` for the full list. Key dependencies:
- **androguard** - APK analysis framework
- **lxml** - XML parsing
- **scikit-learn** - ML models
- **flask** - Web framework
- **jinja2** - Template engine
- **pyyaml** - Configuration
- **pytest** - Testing framework
- **mermaid-cli** - Graph visualization

---

## 🐛 Troubleshooting

**Port 5000 already in use?**
```bash
docker run -p 5001:5000 attack-surface-mapper
# Access at http://localhost:5001
```

**Docker build fails?**
```bash
docker build -t attack-surface-mapper . --no-cache
```

**Test failures?**
```bash
pytest tests/ -v --tb=short
```

---

## 📄 License

See LICENSE file for details.

---

## 👥 Contributing

1. Create a feature branch
2. Make your changes
3. Write/update tests
4. Ensure tests pass
5. Submit a pull request

Refer to the team task breakdown above for contribution areas.
