"""
reports/report_generator.py
Rapport HTML — theme clair, UI soignee.
"""

from datetime import datetime
from typing import List, Dict


def _severity_color(severity: str) -> tuple:
    s = severity.upper()
    if "CRITICAL" in s: return ("#fef2f2", "#ef4444", "#b91c1c")
    if "HIGH" in s:     return ("#fff7ed", "#f97316", "#c2410c")
    if "MEDIUM" in s:   return ("#fefce8", "#eab308", "#a16207")
    return ("#f0fdf4", "#22c55e", "#15803d")


def _badge(severity: str) -> str:
    bg, border, text = _severity_color(severity)
    return (f'<span style="background:{bg};color:{text};border:1px solid {border}55;'
            f'padding:2px 9px;border-radius:5px;font-size:11px;font-weight:600;">'
            f'{severity.upper()}</span>')


def _level_accent(level: str) -> tuple:
    return {
        "CRITICAL": ("#fef2f2", "#ef4444", "#b91c1c"),
        "HIGH":     ("#fff7ed", "#f97316", "#c2410c"),
        "MEDIUM":   ("#fefce8", "#eab308", "#a16207"),
        "LOW":      ("#f0fdf4", "#22c55e", "#15803d"),
    }.get(level.upper(), ("#f9fafb", "#6b7280", "#374151"))


def _mermaid_pipeline() -> str:
    return """<div class="mermaid">
flowchart LR
    A([AndroidManifest.xml]) --> B
    subgraph P1 [P1 - Parser]
        B[parse_manifest]
    end
    B --> C
    subgraph P2 [P2 - Detection]
        C[analyze_all_components] --> D[Findings]
    end
    D --> E
    subgraph P4 [P4 - AI Engine]
        E[extract_features] --> F[enrich_with_findings]
        F --> G[RandomForest]
        G --> H[compute_score]
        H --> I[explain]
        H --> J[recommendations]
    end
    I --> K([Rapport HTML])
    J --> K
    style P1 fill:#eff6ff,stroke:#3b82f6,color:#1e40af
    style P2 fill:#fef2f2,stroke:#ef4444,color:#991b1b
    style P4 fill:#f0fdf4,stroke:#22c55e,color:#166534
</div>"""


def _mermaid_pie(sev_counts: dict) -> str:
    lines = []
    labels = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low"}
    for key, label in labels.items():
        count = sev_counts.get(key, 0)
        if count > 0:
            lines.append(f'    "{label} ({count})" : {count}')
    if not lines:
        return "<p style='color:#9ca3af;font-size:13px;text-align:center;padding:20px;'>Aucun finding.</p>"
    inner = "\n".join(lines)
    return f"""<div class="mermaid">
pie title Findings par severite
{inner}
</div>"""


def _mermaid_components(manifest, findings) -> str:
    lines = ["flowchart TD"]
    pkg_short = manifest.package.split(".")[-1] if manifest.package else "app"
    lines.append(f'    APP(["{pkg_short}"])')
    added = set()
    finding_map = {}
    for f in findings:
        sev = str(f.severity).upper()
        existing = finding_map.get(f.component_name)
        if not existing or "CRITICAL" in sev:
            finding_map[f.component_name] = (f.component_name.split(".")[-1], sev)
    for comp_name, (short_name, sev) in finding_map.items():
        node_id = "".join(c if c.isalnum() else "_" for c in short_name)
        if node_id in added:
            node_id = node_id + str(len(added))
        added.add(node_id)
        if "CRITICAL" in sev:
            style = "fill:#fef2f2,stroke:#ef4444,color:#991b1b"
        elif "HIGH" in sev:
            style = "fill:#fff7ed,stroke:#f97316,color:#c2410c"
        else:
            style = "fill:#fefce8,stroke:#eab308,color:#a16207"
        lines.append(f'    APP --> {node_id}["{short_name}"]')
        lines.append(f'    style {node_id} {style}')
    return '<div class="mermaid">\n' + "\n".join(lines) + "\n</div>"


def generate_html_report(
    manifest,
    findings,
    features,
    score_result,
    explanations: List[Dict],
    recommendations: List[Dict],
    output_path: str = "report.html",
):
    bg, border_c, text_c = _level_accent(score_result.level)
    score = score_result.total_score
    now = datetime.now().strftime("%d %b %Y, %H:%M")

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
        bar_c = "#ef4444" if val > 70 else "#f97316" if val > 40 else "#22c55e"
        breakdown_rows += f"""
        <div style="margin-bottom:11px;">
          <div style="display:flex;justify-content:space-between;margin-bottom:4px;">
            <span style="font-size:12px;color:#6b7280;">{label}</span>
            <span style="font-size:12px;font-weight:600;color:{bar_c};">{val}/100</span>
          </div>
          <div style="background:#f3f4f6;border-radius:99px;height:5px;overflow:hidden;">
            <div style="width:{val}%;background:{bar_c};height:100%;border-radius:99px;"></div>
          </div>
        </div>"""

    # Findings rows
    finding_rows = ""
    for f in findings:
        sev = str(f.severity).upper()
        detail = f.detail[:80] + ("..." if len(f.detail) > 80 else "")
        finding_rows += f"""
        <tr>
          <td style="padding:10px 12px;">{_badge(sev)}</td>
          <td style="padding:10px 12px;font-family:monospace;font-size:12px;color:#374151;">{f.component_name.split('.')[-1]}</td>
          <td style="padding:10px 12px;font-size:12px;color:#6b7280;">{f.component_type}</td>
          <td style="padding:10px 12px;font-size:11px;color:#9ca3af;font-family:monospace;">{f.cwe}</td>
          <td style="padding:10px 12px;font-size:12px;color:#6b7280;">{detail}</td>
        </tr>"""

    # Explanation cards
    explanation_cards = ""
    for e in explanations:
        sev = e.get("severity", "MEDIUM")
        _, bdr, _ = _severity_color(sev)
        explanation_cards += f"""
        <div style="border:1px solid #e5e7eb;border-left:3px solid {bdr};border-radius:8px;padding:14px 18px;margin-bottom:10px;background:#fff;">
          <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px;flex-wrap:wrap;">
            {_badge(sev)}
            <span style="font-size:13px;font-weight:600;color:#111827;">{e['issue']}</span>
            <span style="margin-left:auto;font-size:11px;color:#9ca3af;font-family:monospace;">{e.get('cwe','')}</span>
          </div>
          <p style="margin:0;font-size:13px;color:#6b7280;line-height:1.6;">{e['why']}</p>
        </div>"""

    # Recommendation cards
    rec_cards = ""
    for r in recommendations:
        _, bdr, _ = _severity_color(r["priority"])
        rec_cards += f"""
        <div style="border:1px solid #e5e7eb;border-radius:8px;padding:14px 18px;margin-bottom:10px;background:#fff;">
          <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;flex-wrap:wrap;">
            {_badge(r['priority'])}
            <span style="font-size:13px;font-weight:600;color:#111827;">{r['title']}</span>
          </div>
          <p style="margin:0 0 10px;font-size:13px;color:#6b7280;">{r['description']}</p>
          <div style="background:#f9fafb;border:1px solid #e5e7eb;border-radius:6px;padding:10px 14px;">
            <code style="font-size:12px;color:#059669;font-family:monospace;">{r['patch']}</code>
          </div>
        </div>"""

    # ML section
    top_factors_html = ""
    if score_result.top_factors:
        top_factors_html = "<div style='margin-top:14px;border-top:1px solid #f3f4f6;padding-top:14px;'>"
        top_factors_html += "<p style='font-size:11px;color:#9ca3af;text-transform:uppercase;letter-spacing:1px;margin-bottom:10px;'>Top facteurs IA</p>"
        for name, imp in score_result.top_factors:
            pct = round(imp * 100, 1)
            top_factors_html += f"""
            <div style="display:flex;align-items:center;gap:10px;margin-bottom:7px;">
              <span style="font-size:12px;color:#374151;font-family:monospace;min-width:200px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">{name}</span>
              <div style="flex:1;background:#f3f4f6;border-radius:99px;height:4px;">
                <div style="width:{min(pct*5,100)}%;background:#6366f1;height:100%;border-radius:99px;"></div>
              </div>
              <span style="font-size:11px;color:#9ca3af;min-width:35px;text-align:right;">{pct}%</span>
            </div>"""
        top_factors_html += "</div>"

    ml_section = ""
    if score_result.ml_confidence > 0:
        ml_label = "Risque" if score_result.ml_prediction else "Sur"
        ml_color = "#ef4444" if score_result.ml_prediction else "#16a34a"
        ml_section = f"""
        <div style="background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:20px;margin-bottom:24px;">
          <p style="font-size:11px;color:#9ca3af;text-transform:uppercase;letter-spacing:1px;margin:0 0 12px;">Prediction ML — RandomForest</p>
          <div style="display:flex;align-items:center;gap:16px;">
            <span style="font-size:24px;font-weight:700;color:{ml_color};">{ml_label}</span>
            <div style="width:1px;height:28px;background:#e5e7eb;"></div>
            <span style="font-size:13px;color:#6b7280;">Confiance <strong style="color:#111827;font-weight:600;">{score_result.ml_confidence}%</strong></span>
          </div>
          {top_factors_html}
        </div>"""

    sev_boxes = ""
    for key, color in [("CRITICAL","#ef4444"),("HIGH","#f97316"),("MEDIUM","#eab308"),("LOW","#22c55e")]:
        sev_boxes += f"""
        <div style="background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:12px;text-align:center;">
          <div style="font-size:24px;font-weight:700;color:{color};">{sev_counts[key]}</div>
          <div style="font-size:10px;color:{color};letter-spacing:0.5px;margin-top:2px;font-weight:500;">{key}</div>
        </div>"""

    mermaid_pipeline = _mermaid_pipeline()
    mermaid_pie      = _mermaid_pie(sev_counts)
    mermaid_comps    = _mermaid_components(manifest, findings)

    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1.0"/>
  <title>ASM Report — {manifest.package}</title>
  <script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet"/>
  <style>
    *,*::before,*::after{{box-sizing:border-box;margin:0;padding:0;}}
    body{{background:#f3f4f6;color:#111827;font-family:'Inter',sans-serif;padding:28px 16px;font-size:14px;line-height:1.5;}}
    .w{{max-width:1040px;margin:0 auto;}}
    .card{{background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:20px;}}
    .lbl{{font-size:11px;color:#9ca3af;text-transform:uppercase;letter-spacing:1px;margin-bottom:12px;font-weight:500;}}
    h2{{font-size:12px;color:#9ca3af;text-transform:uppercase;letter-spacing:1px;padding-bottom:10px;border-bottom:1px solid #f3f4f6;margin-bottom:16px;font-weight:500;}}
    section{{margin-bottom:24px;}}
    table{{width:100%;border-collapse:collapse;}}
    thead th{{padding:9px 12px;text-align:left;font-size:11px;color:#9ca3af;text-transform:uppercase;letter-spacing:1px;background:#f9fafb;border-bottom:1px solid #e5e7eb;font-weight:500;}}
    tbody tr:hover{{background:#fafafa;}}
    tbody tr{{border-bottom:1px solid #f3f4f6;}}
    tbody tr:last-child{{border-bottom:none;}}
    .mermaid{{background:#f9fafb;border-radius:8px;padding:12px;text-align:center;overflow-x:auto;}}
  </style>
</head>
<body>
<div class="w">

  <!-- Header -->
  <div style="display:flex;align-items:flex-start;justify-content:space-between;background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:24px;margin-bottom:20px;">
    <div>
      <div style="font-size:11px;color:#9ca3af;letter-spacing:2px;text-transform:uppercase;margin-bottom:8px;">Attack Surface Mapper · Security Report</div>
      <div style="font-size:22px;font-weight:700;color:#111827;margin-bottom:4px;">Android Security Analysis</div>
      <div style="font-family:'JetBrains Mono',monospace;font-size:12px;color:#6366f1;margin-bottom:12px;">{manifest.package}</div>
      <span style="background:{bg};color:{text_c};border:1px solid {border_c}44;padding:4px 12px;border-radius:6px;font-size:12px;font-weight:600;letter-spacing:1px;">{score_result.level}</span>
    </div>
    <div style="text-align:center;margin-left:24px;">
      <div style="width:96px;height:96px;border-radius:50%;border:5px solid {border_c};display:flex;flex-direction:column;align-items:center;justify-content:center;background:#fff;box-shadow:0 0 0 4px {bg};">
        <span style="font-size:26px;font-weight:700;color:{text_c};line-height:1;">{score}</span>
        <span style="font-size:10px;color:#9ca3af;letter-spacing:1px;">/100</span>
      </div>
      <div style="font-size:11px;color:#9ca3af;margin-top:8px;">{now}</div>
    </div>
  </div>

  <!-- Summary grid -->
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:20px;">
    <div class="card">
      <div class="lbl">Application</div>
      <table style="font-size:13px;">
        <tr><td style="color:#6b7280;padding:5px 0;width:130px;">Package</td><td style="text-align:right;font-family:monospace;font-size:11px;color:#374151;">{manifest.package}</td></tr>
        <tr><td style="color:#6b7280;padding:5px 0;">SDK min / cible</td><td style="text-align:right;font-weight:600;color:#111827;">{manifest.min_sdk or '?'} / {manifest.target_sdk or '?'}</td></tr>
        <tr><td style="color:#6b7280;padding:5px 0;">Debuggable</td><td style="text-align:right;font-weight:600;color:{'#ef4444' if manifest.debuggable else '#16a34a'};">{'Oui' if manifest.debuggable else 'Non'}</td></tr>
        <tr><td style="color:#6b7280;padding:5px 0;">Allow Backup</td><td style="text-align:right;font-weight:600;color:{'#f97316' if manifest.allow_backup else '#16a34a'};">{'Oui' if manifest.allow_backup else 'Non'}</td></tr>
        <tr><td style="color:#6b7280;padding:5px 0;">Composants</td><td style="text-align:right;font-weight:600;color:#111827;">{len(manifest.activities)}A / {len(manifest.services)}S / {len(manifest.receivers)}R / {len(manifest.providers)}P</td></tr>
      </table>
    </div>
    <div class="card">
      <div class="lbl">Findings</div>
      <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-bottom:16px;">{sev_boxes}</div>
      <div class="lbl">Score par categorie</div>
      {breakdown_rows}
    </div>
  </div>

  <!-- ML -->
  {ml_section}

  <!-- Diagrams -->
  <section>
    <h2>Diagrammes</h2>
    <div class="card" style="margin-bottom:14px;">
      <div class="lbl">Pipeline complet</div>
      {mermaid_pipeline}
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;">
      <div class="card">
        <div class="lbl">Findings par severite</div>
        {mermaid_pie}
      </div>
      <div class="card">
        <div class="lbl">Composants vulnerables</div>
        {mermaid_comps}
      </div>
    </div>
  </section>

  <!-- Findings table -->
  <section>
    <h2>Vulnerabilites detectees ({len(findings)})</h2>
    <div class="card" style="padding:0;overflow:hidden;">
      <table>
        <thead><tr><th>Severite</th><th>Composant</th><th>Type</th><th>CWE</th><th>Detail</th></tr></thead>
        <tbody>{finding_rows}</tbody>
      </table>
    </div>
  </section>

  <!-- Explanations -->
  <section>
    <h2>Explications ({len(explanations)})</h2>
    {explanation_cards}
  </section>

  <!-- Recommendations -->
  <section>
    <h2>Recommandations ({len(recommendations)})</h2>
    {rec_cards}
  </section>

  <div style="text-align:center;padding:20px 0;font-size:11px;color:#d1d5db;letter-spacing:2px;text-transform:uppercase;">
    Attack Surface Mapper · {now} · P4 AI Engine
  </div>

</div>
<script>
  mermaid.initialize({{
    startOnLoad: true,
    theme: 'default',
    themeVariables: {{
      primaryColor: '#eff6ff',
      primaryTextColor: '#1e40af',
      primaryBorderColor: '#3b82f6',
      lineColor: '#9ca3af',
      background: '#f9fafb',
      fontSize: '13px'
    }}
  }});
</script>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)