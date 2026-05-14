"""Report generator for HTML output."""

from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime
import json

from graph.graph_model import GraphModel
from graph.mermaid_builder import MermaidBuilder


class ReportGenerator:
    """Generates HTML security reports."""
    
    def __init__(self, graph: GraphModel, manifest_data: Optional[Dict] = None):
        self.graph = graph
        self.manifest_data = manifest_data or {}
        self.mermaid_builder = MermaidBuilder(graph)
    
    def generate_report(self, output_path: Path, include_graph: bool = True) -> None:
        """Generate complete HTML report."""
        
        # Get graph stats
        stats = self.graph.stats
        
        # Generate HTML content
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Attack Surface Report - {self.manifest_data.get('package', 'Unknown App')}</title>
    <script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}
        
        .header {{
            background: white;
            border-radius: 12px;
            padding: 30px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        
        h1 {{
            color: #333;
            font-size: 32px;
            margin-bottom: 10px;
        }}
        
        .subtitle {{
            color: #666;
            font-size: 16px;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }}
        
        .stat-card {{
            background: white;
            border-radius: 12px;
            padding: 20px;
            text-align: center;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            transition: transform 0.2s;
        }}
        
        .stat-card:hover {{
            transform: translateY(-2px);
        }}
        
        .stat-number {{
            font-size: 48px;
            font-weight: bold;
            color: #667eea;
        }}
        
        .stat-label {{
            color: #666;
            margin-top: 10px;
            font-size: 14px;
        }}
        
        .risk-section {{
            background: white;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        
        .risk-header {{
            font-size: 24px;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #e0e0e0;
        }}
        
        .risk-critical {{ color: #dc3545; }}
        .risk-high {{ color: #fd7e14; }}
        .risk-medium {{ color: #ffc107; }}
        .risk-low {{ color: #28a745; }}
        
        .component-table {{
            width: 100%;
            border-collapse: collapse;
        }}
        
        .component-table th,
        .component-table td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e0e0e0;
        }}
        
        .component-table th {{
            background: #f8f9fa;
            font-weight: 600;
            color: #333;
        }}
        
        .component-table tr:hover {{
            background: #f8f9fa;
        }}
        
        .badge {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
        }}
        
        .badge-critical {{ background: #dc3545; color: white; }}
        .badge-high {{ background: #fd7e14; color: white; }}
        .badge-medium {{ background: #ffc107; color: #333; }}
        .badge-low {{ background: #28a745; color: white; }}
        .badge-info {{ background: #17a2b8; color: white; }}
        
        .badge-exported {{
            background: #ff9800;
            color: white;
        }}
        
        .graph-container {{
            background: white;
            border-radius: 12px;
            padding: 20px;
            margin-top: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        
        .mermaid {{
            text-align: center;
            background: #fafafa;
            padding: 20px;
            border-radius: 8px;
            overflow-x: auto;
        }}
        
        .recommendations {{
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px;
            margin-top: 20px;
            border-radius: 4px;
        }}
        
        @media (max-width: 768px) {{
            .stats-grid {{
                grid-template-columns: 1fr;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Attack Surface Report</h1>
            <div class="subtitle">
                <strong>Package:</strong> {self.manifest_data.get('package', 'Unknown')} |
                <strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            </div>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number">{stats['total_nodes']}</div>
                <div class="stat-label">Total Components</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{stats['total_edges']}</div>
                <div class="stat-label">Connections</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{stats['nodes_by_risk'].get('critical', 0)}</div>
                <div class="stat-label">Critical Risks</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{len([n for n in self.graph.nodes.values() if n.exported])}</div>
                <div class="stat-label">Exported Components</div>
            </div>
        </div>
        
        <div class="risk-section">
            <div class="risk-header">📋 Component Analysis</div>
            <table class="component-table">
                <thead>
                    <tr>
                        <th>Component Name</th>
                        <th>Type</th>
                        <th>Exported</th>
                        <th>Permission</th>
                        <th>Risk Level</th>
                    </tr>
                </thead>
                <tbody>
                    {self._generate_component_rows()}
                </tbody>
            </table>
        </div>
        
        {"".join(self._generate_graph_section()) if include_graph else ""}
        
        <div class="risk-section">
            <div class="risk-header">💡 Security Recommendations</div>
            {self._generate_recommendations()}
        </div>
    </div>
    
    <script>
        mermaid.initialize({{
            startOnLoad: true,
            theme: 'base',
            themeVariables: {{
                'background': '#ffffff',
                'primaryColor': '#667eea',
                'primaryBorderColor': '#764ba2',
                'lineColor': '#999999',
                'secondaryColor': '#f0f0f0',
                'tertiaryColor': '#fafafa'
            }}
        }});
        
        function showTooltip(message) {{
            // Tooltip functionality can be added here
            console.log(message);
        }}
    </script>
</body>
</html>"""
        
        output_path.write_text(html, encoding='utf-8')
    
    def _generate_component_rows(self) -> str:
        """Generate HTML rows for components table."""
        rows = []
        for node in self.graph.nodes.values():
            risk_class = f"badge-{node.risk_level.value}"
            risk_text = node.risk_level.value.upper()
            
            exported_badge = '<span class="badge badge-exported">🔓 Exported</span>' if node.exported else '<span class="badge badge-info">🔒 Internal</span>'
            
            row = f"""
            <tr>
                <td><code>{node.name}</code></td>
                <td>{node.type.value}</td>
                <td>{exported_badge}</td>
                <td>{node.permission if node.permission else 'None'}</td>
                <td><span class="badge {risk_class}">{risk_text}</span></td>
            </tr>"""
            rows.append(row)
        return ''.join(rows)
    
    def _generate_graph_section(self):
        """Generate graph section HTML."""
        yield '<div class="graph-container">'
        yield '<div class="risk-header">🔄 Attack Surface Graph</div>'
        yield '<div class="mermaid">'
        yield self.mermaid_builder.build()
        yield '</div>'
        yield '</div>'
    
    def _generate_recommendations(self) -> str:
        """Generate security recommendations."""
        recommendations = []
        
        # Check for critical risk components
        critical_nodes = [n for n in self.graph.nodes.values() if n.risk_level.value == 'critical']
        if critical_nodes:
            recommendations.append(f"⚠️ Found {len(critical_nodes)} critical risk components that require immediate attention.")
        
        # Check for exported components
        exported_nodes = [n for n in self.graph.nodes.values() if n.exported]
        if exported_nodes:
            recommendations.append(f"🔓 {len(exported_nodes)} components are exported. Review if each truly needs to be accessible externally.")
        
        # Check for missing permissions on exported components
        exported_no_perm = [n for n in exported_nodes if not n.permission]
        if exported_no_perm:
            recommendations.append(f"🔐 {len(exported_no_perm)} exported components have no permission protection. Consider adding android:permission attributes.")
        
        # Generic recommendations
        recommendations.extend([
            "✅ Run complete penetration testing on all exported components",
            "✅ Implement certificate pinning for network communications",
            "✅ Enable ProGuard/R8 obfuscation for production builds",
            "✅ Regularly update dependencies and fix security patches"
        ])
        
        rec_html = '<ul>'
        for rec in recommendations:
            rec_html += f'<li>{rec}</li>'
        rec_html += '</ul>'
        
        return rec_html