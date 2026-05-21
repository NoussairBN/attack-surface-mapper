import uuid
from pathlib import Path

from flask import Flask, request, send_file, render_template_string, redirect, url_for
from werkzeug.utils import secure_filename

from demo import run_pipeline

app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
REPORT_DIR = BASE_DIR / "generated_reports"

UPLOAD_DIR.mkdir(exist_ok=True)
REPORT_DIR.mkdir(exist_ok=True)


HOME_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Attack Surface Mapper</title>
<style>
body{margin:0;font-family:Arial;background:linear-gradient(135deg,#0f172a,#0f766e);min-height:100vh;display:flex;align-items:center;justify-content:center;color:white}
.card{width:540px;background:rgba(255,255,255,.12);border:1px solid rgba(255,255,255,.22);border-radius:24px;padding:36px;box-shadow:0 30px 80px rgba(0,0,0,.35);backdrop-filter:blur(18px)}
.badge{display:inline-block;background:#14b8a6;color:#042f2e;padding:6px 12px;border-radius:999px;font-size:12px;font-weight:800;margin-bottom:16px}
h1{margin:0 0 12px;font-size:34px}
p{color:#cbd5e1;line-height:1.6}
input{width:100%;box-sizing:border-box;padding:16px;background:white;color:#0f172a;border-radius:14px;border:none;margin:18px 0}
button{width:100%;padding:15px;border:0;border-radius:14px;background:linear-gradient(135deg,#14b8a6,#6366f1);color:white;font-weight:800;cursor:pointer}
</style>
</head>
<body>
<div class="card">
  <div class="badge">Dockerized APK Security Pipeline</div>
  <h1>Attack Surface Mapper</h1>
  <p>Upload an Android APK. The pipeline will extract the manifest, detect risky components, apply ML prediction, and generate a security report.</p>

  <form method="POST" action="/analyze" enctype="multipart/form-data">
    <input type="file" name="apk" accept=".apk" required>
    <button type="submit">Analyze APK</button>
  </form>
</div>
</body>
</html>
"""


REPORT_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>ASM Report Viewer</title>
<style>
body{margin:0;background:#0f172a;font-family:Arial}
.topbar{height:64px;background:#111827;color:white;display:flex;align-items:center;justify-content:space-between;padding:0 22px;box-shadow:0 4px 18px rgba(0,0,0,.35)}
.actions a{margin-left:10px;border:0;border-radius:10px;padding:10px 14px;font-weight:700;cursor:pointer;text-decoration:none;display:inline-block}
.print{background:#14b8a6;color:white}
.html{background:#6366f1;color:white}
.back{background:#334155;color:white}
iframe{width:100%;height:calc(100vh - 64px);border:0;background:white}
</style>
</head>
<body>
<div class="topbar">
  <strong>Attack Surface Mapper — Report</strong>
  <div class="actions">
    <a class="back" href="/">New analysis</a>
    <a class="html" href="/download-html/{{ report_id }}">Download HTML</a>
    <a class="print" href="/print-report/{{ report_id }}" target="_blank">Download as PDF</a>
  </div>
</div>
<iframe src="/view-report/{{ report_id }}"></iframe>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(HOME_HTML)


@app.route("/analyze", methods=["POST"])
def analyze():
    file = request.files.get("apk")

    if not file or not file.filename.lower().endswith(".apk"):
        return "Invalid file. Please upload an APK.", 400

    run_id = str(uuid.uuid4())[:8]
    safe_name = secure_filename(file.filename)

    apk_path = UPLOAD_DIR / f"{run_id}_{safe_name}"
    report_path = REPORT_DIR / f"report_{run_id}.html"

    file.save(apk_path)

    run_pipeline(str(apk_path), str(report_path))

    return redirect(url_for("report_page", report_id=run_id))


@app.route("/report/<report_id>")
def report_page(report_id):
    report_path = REPORT_DIR / f"report_{report_id}.html"

    if not report_path.exists():
        return "Report not found.", 404

    return render_template_string(REPORT_PAGE, report_id=report_id)


@app.route("/view-report/<report_id>")
def view_report(report_id):
    report_path = REPORT_DIR / f"report_{report_id}.html"

    if not report_path.exists():
        return "Report not found.", 404

    return send_file(report_path)


@app.route("/download-html/<report_id>")
def download_html(report_id):
    report_path = REPORT_DIR / f"report_{report_id}.html"

    if not report_path.exists():
        return "Report not found.", 404

    return send_file(report_path, as_attachment=True, download_name="report.html")


@app.route("/print-report/<report_id>")
def print_report(report_id):
    report_path = REPORT_DIR / f"report_{report_id}.html"

    if not report_path.exists():
        return "Report not found.", 404

    html = report_path.read_text(encoding="utf-8")

    print_css = """
<style>
@media print {
    @page {
        size: A4;
        margin: 10mm;
    }

    html, body {
        background: white !important;
        margin: 0 !important;
        padding: 0 !important;
        width: 100% !important;
        overflow: visible !important;
    }

    .w {
        max-width: 100% !important;
        width: 100% !important;
        margin: 0 !important;
        padding: 0 !important;
    }

    .card, section {
        break-inside: avoid;
        page-break-inside: avoid;
    }

    table {
        width: 100% !important;
        page-break-inside: auto;
    }

    tr {
        page-break-inside: avoid;
        page-break-after: auto;
    }

    .mermaid {
        max-width: 100% !important;
        overflow: visible !important;
    }

    a {
        text-decoration: none !important;
        color: inherit !important;
    }
}
</style>

<script>
window.onload = function() {
    setTimeout(function() {
        window.print();
    }, 1400);
};
</script>
"""

    html = html.replace("</head>", print_css + "</head>")

    return html


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)