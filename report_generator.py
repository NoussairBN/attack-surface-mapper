"""
reports/report_generator.py
Génère un rapport HTML professionnel à partir des résultats du pipeline P4.
"""

from datetime import datetime
from typing import List, Dict


def _severity_color(severity: str) -> str:
    s = severity.upper()
    if "CRITICAL" in s: return "#ef4444"
    if "HIGH" in s:     return "#f97316"
    if "MEDIUM" in s:   return "#eab308"
    return "#22c55e"


def _severity_badge(severity: str) -> str:
    color = _severity_color(severity)
    return f'<span style="background:{color};color:#fff;padding:2px 10px;border-radius:999px;font-size:11px;font-weight:700;letter-spacing:1px;">{severity.upper()}</span>'


def _level_color(level: str) -> str:
    return {
        "CRITICAL": "#ef4444",
        "HIGH":     "#f97316",
        "MEDIUM":   "#eab308",
        "LOW":      "#22c55e",
    }.get(level.upper(), "#6b7280")


def generate_html_report(
    manifest,
    findings,
    features,
    score_result,
    explanations: List[Dict],
    recommendations: List[Dict],
    output_path: str = "report.html",
):
    level_color = _level_color(score_result.level)
    score = score_result.total_score
    now = datetime.now().strftime("%d/%m/%Y à %H:%M")

    # Sévérité counts
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        s = str(f.severity).upper()
        for k in sev_counts:
            if k in s:
                sev_counts[k] += 1
                break

    # Breakdown bars
    breakdown_rows = ""
    for cat, val in score_result.breakdown.items():
        label = cat.replace("_", " ").title()
        color = "#ef4444" if val > 70 else "#f97316" if val > 40 else "#22c55e"
        breakdown_rows += f"""
        <div style="margin-bottom:14px;">
          <div style="display:flex;justify-content:space-between;margin-bottom:4px;">
            <span style="font-size:13px;color:#d1d5db;">{label}</span>
            <span style="font-size:13px;font-weight:700;color:{color};">{val}/100</span>
          </div>
          <div style="background:#1f2937;border-radius:6px;height:8px;overflow:hidden;">
            <div style="width:{val}%;background:{color};height:100%;border-radius:6px;transition:width 1s;"></div>
          </div>
        </div>"""

    # Findings table rows
    finding_rows = ""
    for f in findings:
        sev = str(f.severity).upper()
        color = _severity_color(sev)
        finding_rows += f"""
        <tr style="border-bottom:1px solid #1f2937;">
          <td style="padding:10px 12px;font-size:12px;color:#9ca3af;">{f.component_type.upper()}</td>
          <td style="padding:10px 12px;font-size:12px;color:#e5e7eb;font-family:monospace;">{f.component_name}</td>
          <td style="padding:10px 12px;">{_severity_badge(sev)}</td>
          <td style="padding:10px 12px;font-size:11px;color:#6b7280;">{f.cwe}</td>
          <td style="padding:10px 12px;font-size:12px;color:#d1d5db;">{f.detail[:90]}{'...' if len(f.detail) > 90 else ''}</td>
        </tr>"""

    # Explanations cards
    explanation_cards = ""
    for e in explanations:
        sev = e.get("severity", "MEDIUM")
        color = _severity_color(sev)
        cwe = e.get("cwe", "N/A")
        explanation_cards += f"""
        <div style="background:#111827;border-left:4px solid {color};border-radius:8px;padding:16px 20px;margin-bottom:12px;">
          <div style="display:flex;align-items:center;gap:12px;margin-bottom:8px;">
            {_severity_badge(sev)}
            <span style="font-weight:600;color:#f9fafb;">{e['issue']}</span>
            <span style="margin-left:auto;font-size:11px;color:#6b7280;font-family:monospace;">{cwe}</span>
          </div>
          <p style="margin:0;font-size:13px;color:#9ca3af;line-height:1.6;">{e['why']}</p>
        </div>"""

    # Recommendations cards
    rec_cards = ""
    for r in recommendations:
        color = _severity_color(r["priority"])
        rec_cards += f"""
        <div style="background:#111827;border-radius:8px;padding:16px 20px;margin-bottom:12px;border:1px solid #1f2937;">
          <div style="display:flex;align-items:center;gap:12px;margin-bottom:10px;">
            {_severity_badge(r['priority'])}
            <span style="font-weight:600;color:#f9fafb;">{r['title']}</span>
          </div>
          <p style="margin:0 0 10px;font-size:13px;color:#9ca3af;">{r['description']}</p>
          <div style="background:#0f172a;border-radius:6px;padding:10px 14px;">
            <code style="font-size:12px;color:#34d399;font-family:monospace;">{r['patch']}</code>
          </div>
        </div>"""

    # Top ML factors
    top_factors_html = ""
    if score_result.top_factors:
        top_factors_html = "<div style='margin-top:20px;'><p style='color:#6b7280;font-size:12px;text-transform:uppercase;letter-spacing:1px;margin-bottom:12px;'>Top Facteurs IA (RandomForest)</p>"
        for name, imp in score_result.top_factors:
            pct = round(imp * 100, 1)
            top_factors_html += f"""
            <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;">
              <span style="font-size:12px;color:#d1d5db;width:240px;font-family:monospace;">{name}</span>
              <div style="flex:1;background:#1f2937;border-radius:4px;height:6px;">
                <div style="width:{min(pct*5,100)}%;background:#6366f1;height:100%;border-radius:4px;"></div>
              </div>
              <span style="font-size:11px;color:#6b7280;width:40px;text-align:right;">{pct}%</span>
            </div>"""
        top_factors_html += "</div>"

    ml_section = ""
    if score_result.ml_confidence > 0:
        ml_label = "RISQUÉ" if score_result.ml_prediction else "SÛR"
        ml_color = "#ef4444" if score_result.ml_prediction else "#22c55e"
        ml_section = f"""
        <div style="background:#111827;border-radius:12px;padding:20px;margin-top:20px;">
          <p style="color:#6b7280;font-size:12px;text-transform:uppercase;letter-spacing:1px;margin:0 0 12px;">Prédiction ML</p>
          <div style="display:flex;align-items:center;gap:16px;">
            <span style="font-size:28px;font-weight:800;color:{ml_color};">{ml_label}</span>
            <span style="font-size:14px;color:#6b7280;">Confiance : <strong style="color:#f9fafb;">{score_result.ml_confidence}%</strong></span>
          </div>
          {top_factors_html}
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Attack Surface Report — {manifest.package}</title>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Syne:wght@400;600;700;800&display=swap" rel="stylesheet"/>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      background: #030712;
      color: #f9fafb;
      font-family: 'Syne', sans-serif;
      min-height: 100vh;
      padding: 40px 20px;
    }}
    .container {{ max-width: 1100px; margin: 0 auto; }}
    .header {{
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      margin-bottom: 40px;
      padding-bottom: 30px;
      border-bottom: 1px solid #1f2937;
    }}
    .logo {{ font-size: 11px; color: #4b5563; letter-spacing: 3px; text-transform: uppercase; margin-bottom: 8px; }}
    h1 {{ font-size: 32px; font-weight: 800; color: #f9fafb; line-height: 1.2; }}
    .package {{ font-family: 'JetBrains Mono', monospace; font-size: 13px; color: #6366f1; margin-top: 6px; }}
    .date {{ font-size: 12px; color: #4b5563; text-align: right; }}
    .score-ring {{
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      width: 120px;
      height: 120px;
      border-radius: 50%;
      border: 6px solid {level_color};
      background: rgba(0,0,0,0.3);
      box-shadow: 0 0 30px {level_color}44;
    }}
    .score-num {{ font-size: 36px; font-weight: 800; color: {level_color}; line-height: 1; }}
    .score-label {{ font-size: 10px; color: #6b7280; letter-spacing: 2px; margin-top: 4px; }}
    .level-badge {{
      display: inline-block;
      background: {level_color}22;
      color: {level_color};
      border: 1px solid {level_color}66;
      padding: 4px 14px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 2px;
      margin-top: 8px;
    }}
    .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 30px; }}
    .card {{
      background: #0f172a;
      border: 1px solid #1f2937;
      border-radius: 12px;
      padding: 24px;
    }}
    .card-title {{
      font-size: 11px;
      color: #4b5563;
      text-transform: uppercase;
      letter-spacing: 2px;
      margin-bottom: 16px;
    }}
    .stat-row {{ display: flex; justify-content: space-between; margin-bottom: 10px; align-items: center; }}
    .stat-label {{ font-size: 13px; color: #9ca3af; }}
    .stat-value {{ font-size: 13px; font-weight: 700; color: #f9fafb; font-family: 'JetBrains Mono', monospace; }}
    .sev-grid {{ display: grid; grid-template-columns: repeat(4,1fr); gap: 10px; }}
    .sev-box {{ background: #111827; border-radius: 8px; padding: 12px; text-align: center; }}
    .sev-num {{ font-size: 28px; font-weight: 800; }}
    .sev-name {{ font-size: 10px; letter-spacing: 1px; margin-top: 4px; }}
    section {{ margin-bottom: 30px; }}
    section h2 {{
      font-size: 14px;
      text-transform: uppercase;
      letter-spacing: 2px;
      color: #4b5563;
      margin-bottom: 16px;
      padding-bottom: 10px;
      border-bottom: 1px solid #1f2937;
    }}
    table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
    thead tr {{ background: #111827; }}
    thead th {{
      padding: 10px 12px;
      text-align: left;
      font-size: 11px;
      color: #4b5563;
      text-transform: uppercase;
      letter-spacing: 1px;
    }}
    tbody tr:hover {{ background: #0f172a; }}
    @media print {{
      body {{ background: white; color: black; }}
      .card, section {{ break-inside: avoid; }}
    }}
  </style>
</head>
<body>
<div class="container">

  <!-- Header -->
  <div class="header">
    <div>
      <div class="logo">Attack Surface Mapper · Rapport de Sécurité</div>
      <h1>Android Security<br/>Analysis Report</h1>
      <div class="package">{manifest.package}</div>
      <div class="level-badge">{score_result.level}</div>
    </div>
    <div style="text-align:center;">
      <div class="score-ring">
        <span class="score-num">{score}</span>
        <span class="score-label">/ 100</span>
      </div>
      <div class="date" style="margin-top:12px;">Généré le<br/>{now}</div>
    </div>
  </div>

  <!-- Stats Grid -->
  <div class="grid">
    <div class="card">
      <div class="card-title">Informations Application</div>
      <div class="stat-row"><span class="stat-label">Package</span><span class="stat-value" style="font-size:11px;">{manifest.package}</span></div>
      <div class="stat-row"><span class="stat-label">SDK Minimum</span><span class="stat-value">{manifest.min_sdk or 'N/A'}</span></div>
      <div class="stat-row"><span class="stat-label">SDK Cible</span><span class="stat-value">{manifest.target_sdk or 'N/A'}</span></div>
      <div class="stat-row"><span class="stat-label">Debuggable</span><span class="stat-value" style="color:{'#ef4444' if manifest.debuggable else '#22c55e'}">{'OUI ⚠' if manifest.debuggable else 'NON ✓'}</span></div>
      <div class="stat-row"><span class="stat-label">Allow Backup</span><span class="stat-value" style="color:{'#f97316' if manifest.allow_backup else '#22c55e'}">{'OUI ⚠' if manifest.allow_backup else 'NON ✓'}</span></div>
      <div class="stat-row"><span class="stat-label">Activities</span><span class="stat-value">{len(manifest.activities)}</span></div>
      <div class="stat-row"><span class="stat-label">Services</span><span class="stat-value">{len(manifest.services)}</span></div>
      <div class="stat-row"><span class="stat-label">Receivers</span><span class="stat-value">{len(manifest.receivers)}</span></div>
      <div class="stat-row"><span class="stat-label">Providers</span><span class="stat-value">{len(manifest.providers)}</span></div>
    </div>
    <div class="card">
      <div class="card-title">Findings par Sévérité</div>
      <div class="sev-grid" style="margin-bottom:20px;">
        <div class="sev-box">
          <div class="sev-num" style="color:#ef4444;">{sev_counts['CRITICAL']}</div>
          <div class="sev-name" style="color:#ef4444;">CRITICAL</div>
        </div>
        <div class="sev-box">
          <div class="sev-num" style="color:#f97316;">{sev_counts['HIGH']}</div>
          <div class="sev-name" style="color:#f97316;">HIGH</div>
        </div>
        <div class="sev-box">
          <div class="sev-num" style="color:#eab308;">{sev_counts['MEDIUM']}</div>
          <div class="sev-name" style="color:#eab308;">MEDIUM</div>
        </div>
        <div class="sev-box">
          <div class="sev-num" style="color:#22c55e;">{sev_counts['LOW']}</div>
          <div class="sev-name" style="color:#22c55e;">LOW</div>
        </div>
      </div>
      <div class="card-title">Score par Catégorie</div>
      {breakdown_rows}
    </div>
  </div>

  <!-- ML Section -->
  {ml_section}

  <!-- Findings Table -->
  <section style="margin-top:30px;">
    <h2>Vulnérabilités Détectées ({len(findings)})</h2>
    <div style="background:#0f172a;border:1px solid #1f2937;border-radius:12px;overflow:hidden;">
      <table>
        <thead>
          <tr>
            <th>Type</th>
            <th>Composant</th>
            <th>Sévérité</th>
            <th>CWE</th>
            <th>Détail</th>
          </tr>
        </thead>
        <tbody>{finding_rows}</tbody>
      </table>
    </div>
  </section>

  <!-- Explanations -->
  <section>
    <h2>Explications des Risques ({len(explanations)})</h2>
    {explanation_cards}
  </section>

  <!-- Recommendations -->
  <section>
    <h2>Recommandations de Correctifs ({len(recommendations)})</h2>
    {rec_cards}
  </section>

  <!-- Footer -->
  <div style="text-align:center;padding:30px 0;color:#1f2937;font-size:11px;letter-spacing:2px;">
    ATTACK SURFACE MAPPER · RAPPORT GÉNÉRÉ LE {now} · P4 AI ENGINE
  </div>

</div>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)