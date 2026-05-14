"""Graph exporter for multiple formats."""

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Optional, Dict, Any
from .graph_model import GraphModel
from .mermaid_builder import MermaidBuilder


class GraphExporter:
    """Exports graph to various formats."""
    
    def __init__(self, graph_model: GraphModel):
        self.graph = graph_model
        self.mermaid_builder = MermaidBuilder(graph_model)
    
    def export_mermaid(self, output_path: Path) -> None:
        """Export to Mermaid markdown file."""
        mermaid_code = self.mermaid_builder.build()
        output_path.write_text(mermaid_code, encoding='utf-8')
    
    def export_json(self, output_path: Path) -> None:
        """Export to JSON format."""
        graph_data = self.graph.to_dict()
        output_path.write_text(json.dumps(graph_data, indent=2), encoding='utf-8')
    
    def export_graphml(self, output_path: Path) -> None:
        """Export to GraphML format."""
        graphml_lines = ['<?xml version="1.0" encoding="UTF-8"?>',
                        '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">',
                        '  <key id="label" for="all" attr.name="label" attr.type="string"/>',
                        '  <key id="type" for="node" attr.name="type" attr.type="string"/>',
                        '  <key id="risk" for="node" attr.name="risk" attr.type="string"/>',
                        '  <graph id="G" edgedefault="directed">']
        
        # Add nodes
        for node in self.graph.nodes.values():
            graphml_lines.append(f'    <node id="{node.id}">')
            graphml_lines.append(f'      <data key="label">{node.name}</data>')
            graphml_lines.append(f'      <data key="type">{node.type.value}</data>')
            graphml_lines.append(f'      <data key="risk">{node.risk_level.value}</data>')
            graphml_lines.append('    </node>')
        
        # Add edges
        for edge in self.graph.edges:
            graphml_lines.append(f'    <edge source="{edge.source_id}" target="{edge.target_id}">')
            if edge.label:
                graphml_lines.append(f'      <data key="label">{edge.label}</data>')
            graphml_lines.append('    </edge>')
        
        graphml_lines.append('  </graph>')
        graphml_lines.append('</graphml>')
        
        output_path.write_text('\n'.join(graphml_lines), encoding='utf-8')
    
    def export_html_embed(self, output_path: Path) -> None:
        """Export as HTML with embedded Mermaid."""
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Attack Surface Graph</title>
    <script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
            background: #f5f5f5;
        }}
        .container {{
            background: white;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .mermaid {{
            text-align: center;
        }}
        h1 {{
            color: #333;
            border-bottom: 2px solid #4CAF50;
            padding-bottom: 10px;
        }}
        .stats {{
            background: #e8f5e9;
            padding: 15px;
            border-radius: 4px;
            margin-bottom: 20px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Attack Surface Graph</h1>
        <div class="stats">
            <strong>Statistics:</strong>
            <ul>
                <li>Total Nodes: {self.graph.stats['total_nodes']}</li>
                <li>Total Edges: {self.graph.stats['total_edges']}</li>
                <li>Components: {', '.join([f"{k}: {v}" for k,v in self.graph.stats['nodes_by_type'].items()])}</li>
            </ul>
        </div>
        <div class="mermaid">
{self.mermaid_builder.build()}
        </div>
    </div>
    <script>
        mermaid.initialize({{ startOnLoad: true, theme: 'default' }});
    </script>
</body>
</html>"""
        output_path.write_text(html_content, encoding='utf-8')
    
    def export_svg(self, output_path: Path, mermaid_cli_path: Optional[str] = None) -> bool:
        """Export to SVG using mermaid-cli (requires mermaid-cli installed)."""
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.mmd', delete=False) as temp_file:
                self.export_mermaid(Path(temp_file.name))
                temp_path = temp_file.name
            
            svg_output = output_path.with_suffix('.svg')
            
            # Try using mmdc (mermaid-cli)
            cmd = ['mmdc', '-i', temp_path, '-o', str(svg_output)]
            if mermaid_cli_path:
                cmd = [mermaid_cli_path, '-i', temp_path, '-o', str(svg_output)]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            # Cleanup
            Path(temp_path).unlink()
            
            return result.returncode == 0
        except Exception as e:
            print(f"Failed to export SVG: {e}")
            return False