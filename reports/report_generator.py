"""
reports/report_generator.py
Rapport HTML moderne pour Attack Surface Mapper.

Objectifs de cette version :
- palette Navy / Teal / Indigo plus propre ;
- suppression de P1 Advanced et P2 Findings dans le score par catégorie ;
- diagrammes Mermaid plus lisibles ;
- section ML cohérente avec le modèle entraîné sur Drebin-215 ;
- échappement HTML pour éviter les problèmes avec <application> ou les noms de composants.
"""

from __future__ import annotations

from datetime import datetime
from html import escape
from pathlib import Path
from typing import Dict, List, Tuple
import json


# ─────────────────────────────────────────────────────────────────────────────
# Palette & helpers
# ─────────────────────────────────────────────────────────────────────────────

PALETTE = {
    "navy": "#0f172a",
    "slate": "#334155",
    "muted": "#64748b",
    "soft_bg": "#edf2f7",
    "card": "#ffffff",
    "line": "#dbe4ee",
    "teal": "#0f766e",
    "teal_soft": "#ccfbf1",
    "indigo": "#4f46e5",
    "cyan": "#0891b2",
    "rose": "#e11d48",
    "amber": "#f59e0b",
    "green": "#16a34a",
}


HIDDEN_BREAKDOWN_CATEGORIES = {
    "p1_advanced",
    "p2_findings",
}


def _clean_severity(severity: str) -> str:
    """Normalise RiskLevel.HIGH, HIGH, etc. vers HIGH/CRITICAL/MEDIUM/LOW."""
    s = str(severity).upper()
    if "CRITICAL" in s:
        return "CRITICAL"
    if "HIGH" in s:
        return "HIGH"
    if "MEDIUM" in s:
        return "MEDIUM"
    if "LOW" in s:
        return "LOW"
    return s.replace("RISKLEVEL.", "") or "INFO"


def _severity_color(severity: str) -> Tuple[str, str, str]:
    sev = _clean_severity(severity)
    if sev == "CRITICAL":
        return ("#fff1f2", "#e11d48", "#9f1239")
    if sev == "HIGH":
        return ("#fffbeb", "#f59e0b", "#92400e")
    if sev == "MEDIUM":
        return ("#ecfeff", "#0891b2", "#155e75")
    if sev == "LOW":
        return ("#f0fdf4", "#16a34a", "#166534")
    return ("#f8fafc", "#64748b", "#334155")


def _level_accent(level: str) -> Tuple[str, str, str]:
    level = str(level).upper()
    if level == "CRITICAL":
        return ("#fff1f2", "#e11d48", "#9f1239")
    if level == "HIGH":
        return ("#fffbeb", "#f59e0b", "#92400e")
    if level == "MEDIUM":
        return ("#ecfeff", "#0891b2", "#155e75")
    if level == "LOW":
        return ("#f0fdf4", "#16a34a", "#166534")
    return ("#f8fafc", "#64748b", "#334155")


def _badge(severity: str) -> str:
    sev = _clean_severity(severity)
    bg, border, text = _severity_color(sev)
    return (
        f'<span class="badge" style="background:{bg};color:{text};'
        f'border:1px solid {border}55;">{escape(sev)}</span>'
    )


def _value_color(value: float) -> str:
    if value >= 70:
        return PALETTE["rose"]
    if value >= 40:
        return PALETTE["amber"]
    return PALETTE["teal"]


def _safe_attr(value) -> str:
    return escape(str(value) if value is not None else "")


def _short_component_name(component_name: str) -> str:
    name = str(component_name or "")
    if not name:
        return "unknown"
    if name == "<application>":
        return "application"
    return name.split(".")[-1]


def _load_best_model_name() -> str:
    """Lit data/models/metrics.json si disponible pour afficher le meilleur modèle."""
    metrics_path = Path(__file__).resolve().parents[1] / "data" / "models" / "metrics.json"
    if not metrics_path.exists():
        return "modèle entraîné"

    try:
        with open(metrics_path, "r", encoding="utf-8") as f:
            metrics = json.load(f)
        name = metrics.get("best_model") or "modèle entraîné"
        return str(name).replace("_", " ").title()
    except Exception:
        return "modèle entraîné"


# ─────────────────────────────────────────────────────────────────────────────
# Mermaid diagrams
# ─────────────────────────────────────────────────────────────────────────────


def _mermaid_pipeline() -> str:
    return """<div class="mermaid diagram-box pipeline-diagram">
%%{init: {
  "theme": "base",
  "themeVariables": {
    "primaryColor": "#ecfeff",
    "primaryTextColor": "#0f172a",
    "primaryBorderColor": "#0f766e",
    "lineColor": "#64748b",
    "fontFamily": "Inter",
    "fontSize": "14px"
  }
}}%%
flowchart LR
    A([APK Android]) --> B[Décompilation apktool]
    B --> C[Extraction Manifest]
    C --> D[Détection statique]
    D --> E[Score de risque]
    B --> F[Extraction features Drebin-215]
    F --> G[Prédiction ML]
    E --> H([Rapport HTML])
    G --> H
    style A fill:#e0f2fe,stroke:#0284c7,color:#0c4a6e,stroke-width:2px
    style B fill:#ede9fe,stroke:#7c3aed,color:#4c1d95,stroke-width:2px
    style C fill:#ecfeff,stroke:#0891b2,color:#164e63,stroke-width:2px
    style D fill:#fff7ed,stroke:#f59e0b,color:#78350f,stroke-width:2px
    style E fill:#fff1f2,stroke:#e11d48,color:#881337,stroke-width:2px
    style F fill:#f0fdfa,stroke:#0f766e,color:#134e4a,stroke-width:2px
    style G fill:#eef2ff,stroke:#4f46e5,color:#312e81,stroke-width:2px
    style H fill:#f8fafc,stroke:#334155,color:#0f172a,stroke-width:2px
</div>"""


def _mermaid_pie(sev_counts: Dict[str, int]) -> str:
    lines = []
    labels = {
        "CRITICAL": "Critical",
        "HIGH": "High",
        "MEDIUM": "Medium",
        "LOW": "Low",
    }

    for key, label in labels.items():
        count = int(sev_counts.get(key, 0))
        if count > 0:
            lines.append(f'    "{label} ({count})" : {count}')

    if not lines:
        return "<p class='empty-state'>Aucun finding détecté.</p>"

    inner = "\n".join(lines)
    return f"""<div class="mermaid diagram-box pie-diagram">
%%{{init: {{
  "theme": "base",
  "themeVariables": {{
    "pie1": "#e11d48",
    "pie2": "#f59e0b",
    "pie3": "#0891b2",
    "pie4": "#16a34a",
    "pieTextColor": "#0f172a",
    "pieTitleTextColor": "#0f172a",
    "pieStrokeColor": "#ffffff",
    "fontFamily": "Inter",
    "fontSize": "15px"
  }}
}}}}%%
pie title Distribution des findings
{inner}
</div>"""


def _mermaid_components(manifest, findings) -> str:
    lines = ["flowchart TB"]
    pkg_short = _safe_attr(str(getattr(manifest, "package", "app") or "app").split(".")[-1])
    lines.append(f'    APP(["{pkg_short}"])')

    finding_map = {}
    for f in findings:
        component_name = getattr(f, "component_name", "unknown")
        sev = _clean_severity(getattr(f, "severity", "LOW"))
        existing = finding_map.get(component_name)

        if not existing:
            finding_map[component_name] = (_short_component_name(component_name), sev)
        else:
            _, old_sev = existing
            priority = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
            if priority.get(sev, 0) > priority.get(old_sev, 0):
                finding_map[component_name] = (_short_component_name(component_name), sev)

    if not finding_map:
        return "<p class='empty-state'>Aucun composant vulnérable à afficher.</p>"

    max_nodes = 22
    items = list(finding_map.items())[:max_nodes]

    for idx, (_, (short_name, sev)) in enumerate(items, start=1):
        node_id = f"N{idx}"
        safe_name = _safe_attr(short_name).replace('"', "'")

        if sev == "CRITICAL":
            style = "fill:#fff1f2,stroke:#e11d48,color:#9f1239,stroke-width:2px"
        elif sev == "HIGH":
            style = "fill:#fffbeb,stroke:#f59e0b,color:#92400e,stroke-width:2px"
        elif sev == "MEDIUM":
            style = "fill:#ecfeff,stroke:#0891b2,color:#155e75,stroke-width:2px"
        else:
            style = "fill:#f0fdf4,stroke:#16a34a,color:#166534,stroke-width:2px"

        lines.append(f'    APP --> {node_id}["{safe_name}"]')
        lines.append(f'    style {node_id} {style}')

    if len(finding_map) > max_nodes:
        lines.append(f'    APP --> MORE["+ {len(finding_map) - max_nodes} autres composants"]')
        lines.append("    style MORE fill:#f8fafc,stroke:#64748b,color:#334155,stroke-dasharray: 5 5")

    return '<div class="mermaid diagram-box components-diagram">\n' + "\n".join(lines) + "\n</div>"


# ─────────────────────────────────────────────────────────────────────────────
# Main generator
# ─────────────────────────────────────────────────────────────────────────────


def generate_html_report(
    manifest,
    findings,
    features,
    score_result,
    explanations: List[Dict],
    recommendations: List[Dict],
    output_path: str = "report.html",
):
    level_bg, level_border, level_text = _level_accent(score_result.level)
    score = float(score_result.total_score)
    now = datetime.now().strftime("%d %b %Y, %H:%M")
    best_model_name = _load_best_model_name()

    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = _clean_severity(getattr(f, "severity", "LOW"))
        if sev in sev_counts:
            sev_counts[sev] += 1

    # ── Breakdown bars, sans P1 Advanced et P2 Findings ─────────────
    breakdown_rows = ""
    for cat, raw_val in score_result.breakdown.items():
        if cat in HIDDEN_BREAKDOWN_CATEGORIES:
            continue

        val = round(float(raw_val), 1)
        label = cat.replace("_", " ").title()
        bar_c = _value_color(val)

        breakdown_rows += f"""
        <div class="score-row">
          <div class="score-line">
            <span>{escape(label)}</span>
            <strong style="color:{bar_c};">{val}/100</strong>
          </div>
          <div class="bar-track">
            <div class="bar-fill" style="width:{min(max(val, 0), 100)}%;background:{bar_c};"></div>
          </div>
        </div>"""

    # ── Findings table ──────────────────────────────────────────────
    finding_rows = ""
    for f in findings:
        sev = _clean_severity(getattr(f, "severity", "LOW"))
        component_name = _short_component_name(getattr(f, "component_name", "unknown"))
        component_type = getattr(f, "component_type", "")
        cwe = getattr(f, "cwe", "")
        detail = str(getattr(f, "detail", ""))
        if len(detail) > 115:
            detail = detail[:115] + "..."

        finding_rows += f"""
        <tr>
          <td>{_badge(sev)}</td>
          <td class="mono">{_safe_attr(component_name)}</td>
          <td>{_safe_attr(component_type)}</td>
          <td class="mono soft">{_safe_attr(cwe)}</td>
          <td>{_safe_attr(detail)}</td>
        </tr>"""

    if not finding_rows:
        finding_rows = """
        <tr>
          <td colspan="5" class="empty-cell">Aucune vulnérabilité détectée.</td>
        </tr>"""

    # ── Explanations ────────────────────────────────────────────────
    explanation_cards = ""
    for e in explanations:
        sev = _clean_severity(e.get("severity", "MEDIUM"))
        _, border, _ = _severity_color(sev)
        explanation_cards += f"""
        <article class="issue-card" style="border-left-color:{border};">
          <div class="issue-head">
            {_badge(sev)}
            <strong>{_safe_attr(e.get('issue', 'Issue'))}</strong>
            <span class="mono soft">{_safe_attr(e.get('cwe', ''))}</span>
          </div>
          <p>{_safe_attr(e.get('why', ''))}</p>
        </article>"""

    if not explanation_cards:
        explanation_cards = "<p class='empty-state'>Aucune explication générée.</p>"

    # ── Recommendations ─────────────────────────────────────────────
    rec_cards = ""
    for r in recommendations:
        sev = _clean_severity(r.get("priority", "MEDIUM"))
        _, border, _ = _severity_color(sev)
        rec_cards += f"""
        <article class="rec-card" style="border-top-color:{border};">
          <div class="issue-head">
            {_badge(sev)}
            <strong>{_safe_attr(r.get('title', 'Recommandation'))}</strong>
          </div>
          <p>{_safe_attr(r.get('description', ''))}</p>
          <div class="patch-box"><code>{_safe_attr(r.get('patch', ''))}</code></div>
        </article>"""

    if not rec_cards:
        rec_cards = "<p class='empty-state'>Aucune recommandation générée.</p>"

    # ── ML section ──────────────────────────────────────────────────
    ml_section = ""
    if getattr(score_result, "ml_prediction", None) is not None and float(getattr(score_result, "ml_confidence", 0) or 0) > 0:
        ml_prediction = int(score_result.ml_prediction)
        ml_confidence = round(float(score_result.ml_confidence), 1)
        ml_label = "RISQUÉ" if ml_prediction == 1 else "SÛR"
        ml_color = PALETTE["rose"] if ml_prediction == 1 else PALETTE["teal"]
        ml_bg = "#fff1f2" if ml_prediction == 1 else "#f0fdfa"

        ml_section = f"""
        <section>
          <h2>Prédiction ML</h2>
          <div class="ml-card" style="background:{ml_bg};border-color:{ml_color}33;">
            <div>
              <div class="eyebrow">Modèle entraîné sur Drebin-215 · {escape(best_model_name)}</div>
              <div class="ml-result" style="color:{ml_color};">{ml_label}</div>
              <p>
                Cette prédiction est calculée à partir des features statiques Drebin-215 extraites depuis l’APK
                décompilée. Elle complète le score statique sans le remplacer.
              </p>
            </div>
            <div class="confidence-pill" style="border-color:{ml_color};color:{ml_color};">
              <span>{ml_confidence}%</span>
              <small>confiance</small>
            </div>
          </div>
        </section>"""
    else:
        ml_section = """
        <section>
          <h2>Prédiction ML</h2>
          <div class="ml-card muted-card">
            <div>
              <div class="eyebrow">Modèle entraîné sur Drebin-215</div>
              <div class="ml-result">Non disponible</div>
              <p>Le modèle ML n’a pas encore été entraîné ou la prédiction n’a pas pu être calculée.</p>
            </div>
          </div>
        </section>"""

    # ── Severity summary boxes ──────────────────────────────────────
    sev_boxes = ""
    for key in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        _, border, text = _severity_color(key)
        sev_boxes += f"""
        <div class="sev-box" style="border-color:{border}44;">
          <strong style="color:{text};">{sev_counts[key]}</strong>
          <span>{key}</span>
        </div>"""

    mermaid_pipeline = _mermaid_pipeline()
    mermaid_pie = _mermaid_pie(sev_counts)
    mermaid_comps = _mermaid_components(manifest, findings)

    package_name = _safe_attr(getattr(manifest, "package", "unknown"))
    min_sdk = _safe_attr(getattr(manifest, "min_sdk", None) or "?")
    target_sdk = _safe_attr(getattr(manifest, "target_sdk", None) or "?")

    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1.0"/>
  <title>ASM Report — {package_name}</title>
  <script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet"/>
  <style>
    *,*::before,*::after{{box-sizing:border-box;margin:0;padding:0;}}
    body{{
      background:
        radial-gradient(circle at top left, #dbeafe 0, transparent 34%),
        radial-gradient(circle at top right, #ccfbf1 0, transparent 30%),
        #edf2f7;
      color:#0f172a;
      font-family:'Inter',sans-serif;
      padding:30px 16px;
      font-size:14px;
      line-height:1.55;
    }}
    .w{{max-width:1180px;margin:0 auto;}}
    .card{{
      background:rgba(255,255,255,0.94);
      border:1px solid #dbe4ee;
      border-radius:18px;
      padding:22px;
      box-shadow:0 12px 32px rgba(15,23,42,0.06);
    }}
    section{{margin-bottom:24px;}}
    h2,.lbl,.eyebrow{{
      font-size:12px;
      color:#334155;
      text-transform:uppercase;
      letter-spacing:1.45px;
      font-weight:800;
    }}
    h2{{padding-bottom:12px;border-bottom:1px solid #dbe4ee;margin-bottom:16px;}}
    .lbl{{margin-bottom:14px;}}
    .eyebrow{{margin-bottom:8px;color:#0f766e;}}
    .hero{{
      position:relative;
      overflow:hidden;
      display:flex;
      align-items:flex-start;
      justify-content:space-between;
      gap:24px;
      background:linear-gradient(135deg,#0f172a 0%,#164e63 48%,#0f766e 100%);
      border-radius:24px;
      padding:30px;
      color:white;
      margin-bottom:22px;
      box-shadow:0 20px 45px rgba(15,23,42,0.20);
    }}
    .hero::after{{
      content:"";
      position:absolute;
      width:260px;
      height:260px;
      right:-80px;
      top:-100px;
      border-radius:50%;
      background:rgba(255,255,255,0.10);
    }}
    .hero-title{{font-size:28px;font-weight:800;margin:5px 0 7px;letter-spacing:-0.5px;}}
    .hero-package{{font-family:'JetBrains Mono',monospace;font-size:13px;color:#bae6fd;word-break:break-all;}}
    .level-pill{{
      display:inline-flex;
      margin-top:16px;
      background:{level_bg};
      color:{level_text};
      border:1px solid {level_border};
      padding:7px 14px;
      border-radius:999px;
      font-size:12px;
      font-weight:800;
      letter-spacing:1px;
    }}
    .score-ring{{
      width:120px;
      height:120px;
      flex:0 0 auto;
      border-radius:50%;
      background:conic-gradient({level_border} {min(max(score, 0), 100)}%, rgba(255,255,255,0.18) 0);
      display:flex;
      align-items:center;
      justify-content:center;
      position:relative;
      z-index:1;
    }}
    .score-ring::before{{
      content:"";
      position:absolute;
      width:88px;
      height:88px;
      border-radius:50%;
      background:#0f172a;
    }}
    .score-ring div{{position:relative;text-align:center;}}
    .score-ring strong{{display:block;font-size:30px;line-height:1;font-weight:800;color:white;}}
    .score-ring span{{font-size:11px;color:#cbd5e1;text-transform:uppercase;letter-spacing:1px;}}
    .grid-2{{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-bottom:22px;}}
    .mini-table{{width:100%;border-collapse:collapse;font-size:13px;}}
    .mini-table td{{padding:7px 0;border-bottom:1px solid #eef2f7;}}
    .mini-table tr:last-child td{{border-bottom:none;}}
    .mini-table td:first-child{{color:#64748b;}}
    .mini-table td:last-child{{text-align:right;font-weight:700;color:#0f172a;}}
    .mono{{font-family:'JetBrains Mono',monospace;}}
    .soft{{color:#64748b;}}
    .sev-grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:18px;}}
    .sev-box{{
      background:#f8fbff;
      border:1px solid #dbe4ee;
      border-radius:14px;
      padding:13px 10px;
      text-align:center;
    }}
    .sev-box strong{{display:block;font-size:25px;line-height:1;font-weight:800;}}
    .sev-box span{{font-size:10px;color:#64748b;letter-spacing:0.8px;font-weight:800;margin-top:5px;display:block;}}
    .score-row{{margin-bottom:15px;}}
    .score-line{{display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;color:#475569;font-size:13px;}}
    .score-line strong{{font-size:13px;}}
    .bar-track{{height:8px;border-radius:999px;background:#dbe4ee;overflow:hidden;}}
    .bar-fill{{height:100%;border-radius:999px;}}
    .ml-card{{
      display:flex;
      justify-content:space-between;
      gap:24px;
      align-items:center;
      border:1px solid;
      border-radius:20px;
      padding:24px;
      box-shadow:0 12px 30px rgba(15,23,42,0.05);
    }}
    .ml-card p{{color:#475569;max-width:820px;margin-top:4px;}}
    .ml-result{{font-size:30px;font-weight:800;letter-spacing:-0.5px;}}
    .confidence-pill{{
      min-width:130px;
      height:92px;
      border:2px solid;
      border-radius:18px;
      display:flex;
      flex-direction:column;
      align-items:center;
      justify-content:center;
      background:white;
    }}
    .confidence-pill span{{font-size:26px;font-weight:800;line-height:1;}}
    .confidence-pill small{{font-size:11px;text-transform:uppercase;letter-spacing:1px;margin-top:5px;color:#64748b;font-weight:800;}}
    .muted-card{{background:#f8fafc;border-color:#cbd5e1;color:#64748b;}}
    .diagram-box{{
      background:#f8fbff;
      border:1px solid #dbe4ee;
      border-radius:16px;
      padding:18px;
      overflow:auto;
      text-align:center;
    }}
    .pipeline-diagram{{min-height:260px;}}
    .pie-diagram{{min-height:390px;display:flex;align-items:center;justify-content:center;}}
    .components-diagram{{min-height:500px;}}
    table{{width:100%;border-collapse:collapse;}}
    .table-wrap{{overflow-x:auto;}}
    thead th{{
      padding:12px 14px;
      text-align:left;
      font-size:11px;
      color:#334155;
      text-transform:uppercase;
      letter-spacing:1px;
      background:#f8fbff;
      border-bottom:1px solid #dbe4ee;
      font-weight:800;
      white-space:nowrap;
    }}
    tbody td{{padding:13px 14px;border-bottom:1px solid #edf2f7;color:#475569;font-size:13px;vertical-align:top;}}
    tbody tr:hover{{background:#f8fbff;}}
    tbody tr:last-child td{{border-bottom:none;}}
    .badge{{padding:4px 10px;border-radius:999px;font-size:11px;font-weight:800;letter-spacing:0.35px;white-space:nowrap;}}
    .issue-card,.rec-card{{
      background:#fff;
      border:1px solid #dbe4ee;
      border-radius:16px;
      padding:16px 18px;
      margin-bottom:12px;
      box-shadow:0 8px 24px rgba(15,23,42,0.04);
    }}
    .issue-card{{border-left:5px solid;}}
    .rec-card{{border-top:5px solid;}}
    .issue-head{{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:8px;}}
    .issue-head strong{{font-size:14px;color:#0f172a;}}
    .issue-head .soft{{margin-left:auto;font-size:12px;}}
    .issue-card p,.rec-card p{{margin:0;color:#64748b;font-size:13px;}}
    .patch-box{{
      margin-top:12px;
      background:#f8fbff;
      border:1px solid #dbe4ee;
      border-radius:12px;
      padding:11px 13px;
      overflow:auto;
    }}
    .patch-box code{{font-size:12px;color:#0f766e;font-family:'JetBrains Mono',monospace;}}
    .empty-state,.empty-cell{{color:#94a3b8;text-align:center;padding:24px;font-size:13px;}}
    .footer{{text-align:center;padding:24px 0 8px;font-size:11px;color:#94a3b8;letter-spacing:2px;text-transform:uppercase;font-weight:800;}}
    @media (max-width:850px){{
      .hero,.ml-card{{flex-direction:column;align-items:flex-start;}}
      .grid-2{{grid-template-columns:1fr;}}
      .sev-grid{{grid-template-columns:repeat(2,1fr);}}
      .score-ring{{width:110px;height:110px;}}
    }}
  </style>
</head>
<body>
<div class="w">

  <header class="hero">
    <div>
      <div class="eyebrow" style="color:#bae6fd;">Attack Surface Mapper · Security Report</div>
      <div class="hero-title">Android Security Analysis</div>
      <div class="hero-package">{package_name}</div>
      <span class="level-pill">{_safe_attr(score_result.level)}</span>
    </div>
    <div>
      <div class="score-ring">
        <div>
          <strong>{score}</strong>
          <span>/100</span>
        </div>
      </div>
      <div style="font-size:11px;color:#cbd5e1;margin-top:10px;text-align:center;">{now}</div>
    </div>
  </header>

  <div class="grid-2">
    <div class="card">
      <div class="lbl">Application</div>
      <table class="mini-table">
        <tr><td>Package</td><td class="mono">{package_name}</td></tr>
        <tr><td>SDK min / cible</td><td>{min_sdk} / {target_sdk}</td></tr>
        <tr><td>Debuggable</td><td style="color:{PALETTE['rose'] if getattr(manifest, 'debuggable', False) else PALETTE['teal']};">{'Oui' if getattr(manifest, 'debuggable', False) else 'Non'}</td></tr>
        <tr><td>Allow Backup</td><td style="color:{PALETTE['amber'] if getattr(manifest, 'allow_backup', False) else PALETTE['teal']};">{'Oui' if getattr(manifest, 'allow_backup', False) else 'Non'}</td></tr>
        <tr><td>Composants</td><td>{len(manifest.activities)}A / {len(manifest.services)}S / {len(manifest.receivers)}R / {len(manifest.providers)}P</td></tr>
      </table>
    </div>

    <div class="card">
      <div class="lbl">Synthèse des findings</div>
      <div class="sev-grid">{sev_boxes}</div>
      <div class="lbl">Score par catégorie</div>
      {breakdown_rows}
    </div>
  </div>

  {ml_section}

  <section>
    <h2>Pipeline d’analyse</h2>
    <div class="card">
      {mermaid_pipeline}
    </div>
  </section>

  <section>
    <h2>Distribution des findings</h2>
    <div class="card">
      {mermaid_pie}
    </div>
  </section>

  <section>
    <h2>Composants vulnérables</h2>
    <div class="card">
      {mermaid_comps}
    </div>
  </section>

  <section>
    <h2>Vulnérabilités détectées ({len(findings)})</h2>
    <div class="card" style="padding:0;overflow:hidden;">
      <div class="table-wrap">
        <table>
          <thead>
            <tr><th>Sévérité</th><th>Composant</th><th>Type</th><th>CWE</th><th>Détail</th></tr>
          </thead>
          <tbody>{finding_rows}</tbody>
        </table>
      </div>
    </div>
  </section>

  <section>
    <h2>Explications ({len(explanations)})</h2>
    {explanation_cards}
  </section>

  <section>
    <h2>Recommandations ({len(recommendations)})</h2>
    {rec_cards}
  </section>

  <div class="footer">Attack Surface Mapper · {now} · Static Analysis + Drebin ML</div>

</div>
<script>
  mermaid.initialize({{
    startOnLoad: true,
    securityLevel: 'loose',
    theme: 'base',
    flowchart: {{
      useMaxWidth: true,
      htmlLabels: true,
      curve: 'basis',
      nodeSpacing: 45,
      rankSpacing: 55
    }}
  }});
</script>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)
