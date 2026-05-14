"""Report generator for HTML output."""

from pathlib import Path
from typing import Optional, Dict, Any, List
from datetime import datetime
import json

from graph.graph_model import GraphModel, ComponentNode, RiskLevel
from graph.mermaid_builder import MermaidBuilder


class ReportGenerator:
    """Generates HTML security reports."""
    
    def __init__(self, graph: GraphModel, manifest_data: Optional[Dict] = None):
        self.graph = graph
        self.manifest_data = manifest_data or {}
        self.mermaid_builder = MermaidBuilder(graph)
    
    def generate_report(self, output_path: Path, include_graph: bool = True) -> None:
        """Generate complete HTML report."""
        
        # Get graph statistics
        stats = self.graph.stats
        
        # Get exported components count
        exported_count = len([n for n in self.graph.nodes.values() if n.exported])
        
        # Prepare component list for template
        components = []
        for node in self.graph.nodes.values():
            components.append({
                'name': node.name,
                'type': node.type.value,
                'exported': node.exported,
                'permission': node.permission if node.permission else None,
                'risk': node.risk_level.value
            })
        
        # Generate recommendations
        recommendations = self._generate_recommendations()
        
        # Get Mermaid code
        mermaid_code = ""
        if include_graph:
            try:
                mermaid_code = self.mermaid_builder.build()
            except Exception as e:
                mermaid_code = f"flowchart TB\n    A[Graph generation note]"
        
        # Read template or use fallback
        template_path = Path(__file__).parent / "templates" / "report.html.jinja"
        
        try:
            from jinja2 import Template
            if template_path.exists():
                template_content = template_path.read_text(encoding='utf-8')
                template = Template(template_content)
                html_content = template.render(
                    manifest=self.manifest_data,
                    timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    stats=stats,
                    exported_count=exported_count,
                    components=components,
                    recommendations=recommendations,
                    mermaid_code=mermaid_code
                )
            else:
                html_content = self._generate_inline_html(stats, components, recommendations, exported_count, mermaid_code)
        except Exception as e:
            html_content = self._generate_inline_html(stats, components, recommendations, exported_count, mermaid_code)
        
        # Write output
        output_path.write_text(html_content, encoding='utf-8')
    
    def _generate_recommendations(self) -> List[str]:
        """Generate security recommendations."""
        recommendations = []
        
        critical_nodes = [n for n in self.graph.nodes.values() if n.risk_level == RiskLevel.CRITICAL]
        if critical_nodes:
            recommendations.append(f"Found {len(critical_nodes)} critical risk components that require immediate attention.")
        
        exported_nodes = [n for n in self.graph.nodes.values() if n.exported]
        if exported_nodes:
            recommendations.append(f"{len(exported_nodes)} components are exported. Review if each truly needs to be accessible externally.")
        
        exported_no_perm = [n for n in exported_nodes if not n.permission]
        if exported_no_perm:
            recommendations.append(f"{len(exported_no_perm)} exported components have no permission protection. Consider adding android:permission attributes.")
        
        high_nodes = [n for n in self.graph.nodes.values() if n.risk_level == RiskLevel.HIGH]
        if high_nodes:
            recommendations.append(f"{len(high_nodes)} high risk components need security review.")
        
        recommendations.extend([
            "Run complete penetration testing on all exported components",
            "Implement certificate pinning for network communications",
            "Enable ProGuard/R8 obfuscation for production builds",
            "Regularly update dependencies and fix security patches",
            "Consider using androidx.security:security-crypto for data encryption"
        ])
        
        return recommendations
    
    def _generate_inline_html(self, stats: Dict, components: List, recommendations: List, exported_count: int, mermaid_code: str) -> str:
        """Generate inline HTML without external template."""
        
        rows = ""
        for comp in components:
            risk_class = comp['risk']
            exported_text = "🔓 Exported" if comp['exported'] else "🔒 Internal"
            exported_class = "badge-exported" if comp['exported'] else "badge-internal"
            rows += f"""
            <tr>
                <td><code>{comp['name']}</code></td>
                <td>{comp['type']}</td>
                <td><span class="badge {exported_class}">{exported_text}</span></td>
                <td>{comp['permission'] if comp['permission'] else '<span style="color:#a0aec0;">None</span>'}</td>
                <td><span class="badge badge-{risk_class}">{comp['risk'].upper()}</span></td>
            </tr>"""
        
        recs = ""
        for rec in recommendations:
            recs += f'<li><span class="recommendation-icon recommendation-info">✅</span>{rec}</li>'
        
        return f'''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Attack Surface Report</title>
    <script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Inter', sans-serif; background: #f5f7fa; color: #1a1a2e; padding: 24px; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); border-radius: 16px; padding: 32px; margin-bottom: 24px; color: white; }}
        .header h1 {{ font-size: 28px; margin-bottom: 8px; }}
        .subtitle {{ color: #a0aec0; font-size: 14px; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 24px; }}
        .stat-card {{ background: white; border-radius: 12px; padding: 20px; text-align: center; border: 1px solid #e2e8f0; }}
        .stat-number {{ font-size: 42px; font-weight: 700; background: linear-gradient(135deg, #667eea, #764ba2); -webkit-background-clip: text; background-clip: text; color: transparent; }}
        .stat-label {{ color: #4a5568; margin-top: 8px; font-size: 14px; }}
        .section {{ background: white; border-radius: 12px; margin-bottom: 24px; border: 1px solid #e2e8f0; overflow: hidden; }}
        .section-header {{ padding: 20px 24px; border-bottom: 1px solid #e2e8f0; background: #fafbfc; }}
        .section-header h2 {{ font-size: 18px; font-weight: 600; }}
        .section-content {{ padding: 24px; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th {{ text-align: left; padding: 12px 16px; background: #f7fafc; font-weight: 600; font-size: 13px; border-bottom: 2px solid #e2e8f0; }}
        td {{ padding: 12px 16px; border-bottom: 1px solid #edf2f7; font-size: 14px; }}
        .badge {{ display: inline-flex; padding: 4px 10px; border-radius: 20px; font-size: 12px; font-weight: 600; }}
        .badge-critical {{ background: #fed7d7; color: #c53030; }}
        .badge-high {{ background: #feebc8; color: #c05621; }}
        .badge-medium {{ background: #fefcbf; color: #975a16; }}
        .badge-low {{ background: #c6f6d5; color: #276749; }}
        .badge-exported {{ background: #fef5e7; color: #d35400; }}
        .badge-internal {{ background: #e2e8f0; color: #4a5568; }}
        .graph-container {{ background: #fafbfc; border-radius: 8px; padding: 20px; }}
        .mermaid {{ display: flex; justify-content: center; background: white; border-radius: 8px; padding: 20px; }}
        .recommendations-list {{ list-style: none; }}
        .recommendations-list li {{ padding: 12px 0; border-bottom: 1px solid #edf2f7; display: flex; align-items: center; gap: 12px; }}
        .recommendation-icon {{ width: 24px; height: 24px; display: inline-flex; align-items: center; justify-content: center; border-radius: 50%; background: #bee3f8; color: #2c5282; }}
        code {{ background: #edf2f7; padding: 2px 6px; border-radius: 4px; font-family: monospace; font-size: 13px; }}
        @media (max-width: 768px) {{ .stats-grid {{ grid-template-columns: repeat(2, 1fr); }} }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Attack Surface Report</h1>
            <div class="subtitle">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
        </div>
        <div class="stats-grid">
            <div class="stat-card"><div class="stat-number">{stats['total_nodes']}</div><div class="stat-label">Components</div></div>
            <div class="stat-card"><div class="stat-number">{stats['total_edges']}</div><div class="stat-label">Connections</div></div>
            <div class="stat-card"><div class="stat-number">{stats['nodes_by_risk'].get('critical', 0)}</div><div class="stat-label">Critical Risks</div></div>
            <div class="stat-card"><div class="stat-number">{exported_count}</div><div class="stat-label">Exported</div></div>
        </div>
        <div class="section">
            <div class="section-header"><h2>📋 Component Analysis</h2></div>
            <div class="section-content">
                <table><thead><tr><th>Name</th><th>Type</th><th>Exported</th><th>Permission</th><th>Risk</th></tr></thead><tbody>{rows}</tbody></table>
            </div>
        </div>
        <div class="section">
            <div class="section-header"><h2>🔄 Attack Surface Graph</h2></div>
            <div class="section-content">
                <div class="graph-container"><pre class="mermaid">{mermaid_code}</pre></div>
            </div>
        </div>
        <div class="section">
            <div class="section-header"><h2>💡 Security Recommendations</h2></div>
            <div class="section-content"><ul class="recommendations-list">{recs}</ul></div>
        </div>
    </div>
    <script>
        mermaid.initialize({{ startOnLoad: true, theme: 'base', themeVariables: {{ 'primaryColor': '#667eea', 'primaryBorderColor': '#764ba2' }} }});
    </script>
</body>
</html>'''