"""Command-line interface for attack-surface-mapper."""

import argparse
import sys
from pathlib import Path
from typing import Optional
import json

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from graph.graph_model import GraphModel, ComponentNode, IntentEdge, ComponentType, RiskLevel, EdgeType
from graph.mermaid_builder import MermaidBuilder
from graph.graph_exporter import GraphExporter
from ui.report_generator import ReportGenerator


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Attack Surface Mapper - Android Security Analysis Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --apk app.apk --output report.html
  %(prog)s --manifest AndroidManifest.xml --output graph.mmd
  %(prog)s --apk app.apk --format json --output analysis.json
  %(prog)s --apk app.apk --format svg --output graph.svg
        """
    )
    
    parser.add_argument(
        '--apk',
        type=str,
        help='Path to APK file for analysis'
    )
    
    parser.add_argument(
        '--manifest',
        type=str,
        help='Path to AndroidManifest.xml file'
    )
    
    parser.add_argument(
        '--output',
        type=str,
        default='report.html',
        help='Output file path (default: report.html)'
    )
    
    parser.add_argument(
        '--format',
        choices=['html', 'mmd', 'json', 'svg', 'graphml'],
        default='html',
        help='Output format (default: html)'
    )
    
    parser.add_argument(
        '--no-graph',
        action='store_true',
        help='Generate report without graph visualization'
    )
    
    parser.add_argument(
        '--verbose',
        '-v',
        action='store_true',
        help='Enable verbose output'
    )
    
    return parser.parse_args()


def create_demo_graph() -> GraphModel:
    """Create a demo graph for testing."""
    graph = GraphModel()
    
    # Create components
    components = [
        ComponentNode(id="main", name="MainActivity", type=ComponentType.ACTIVITY, 
                     exported=True, risk_level=RiskLevel.HIGH),
        ComponentNode(id="auth", name="AuthService", type=ComponentType.SERVICE,
                     exported=True, permission="android.permission.AUTH", risk_level=RiskLevel.MEDIUM),
        ComponentNode(id="data", name="DataProvider", type=ComponentType.CONTENT_PROVIDER,
                     exported=True, risk_level=RiskLevel.CRITICAL),
        ComponentNode(id="internal", name="InternalHelper", type=ComponentType.ACTIVITY,
                     exported=False, risk_level=RiskLevel.LOW),
        ComponentNode(id="broadcast", name="NetworkReceiver", type=ComponentType.BROADCAST_RECEIVER,
                     exported=True, risk_level=RiskLevel.HIGH),
    ]
    
    for comp in components:
        graph.add_node(comp)
    
    # Create edges
    edges = [
        IntentEdge(id="e1", source_id="main", target_id="auth", type=EdgeType.INTENT, label="start_auth"),
        IntentEdge(id="e2", source_id="main", target_id="data", type=EdgeType.INTENT, label="query_data"),
        IntentEdge(id="e3", source_id="auth", target_id="data", type=EdgeType.PERMISSION, label="requires_permission"),
        IntentEdge(id="e4", source_id="broadcast", target_id="main", type=EdgeType.INTENT, label="on_network_change"),
    ]
    
    for edge in edges:
        graph.add_edge(edge)
    
    return graph


def load_manifest_data(manifest_path: Path) -> dict:
    """Load and parse manifest data."""
    # This is a placeholder - in real implementation, this would parse the manifest
    # For demo purposes, we return a sample structure
    return {
        'package': 'com.example.app',
        'version': '1.0',
        'components': [
            {'name': 'MainActivity', 'type': 'activity', 'exported': True},
            {'name': 'AuthService', 'type': 'service', 'exported': True, 'permission': 'android.permission.AUTH'},
            {'name': 'DataProvider', 'type': 'provider', 'exported': True},
        ],
        'permissions': ['android.permission.INTERNET', 'android.permission.READ_CONTACTS'],
        'allow_backup': True,
        'debuggable': False
    }


def main():
    """Main entry point for CLI."""
    args = parse_arguments()
    
    print("🔍 Attack Surface Mapper - Android Security Analysis Tool")
    print("=" * 50)
    
    # Load or create graph
    graph = None
    
    if args.apk:
        print(f"📱 Analyzing APK: {args.apk}")
        # Here we would parse the APK
        # For demo, create demo graph
        graph = create_demo_graph()
        manifest_data = None
        
    elif args.manifest:
        print(f"📄 Parsing manifest: {args.manifest}")
        manifest_data = load_manifest_data(Path(args.manifest))
        graph = create_demo_graph()
        
    else:
        print("⚠️  No input file specified. Using demo data for demonstration.")
        print("   Use --apk or --manifest to analyze real applications.")
        graph = create_demo_graph()
        manifest_data = None
    
    if not graph:
        print("❌ Failed to create graph from input")
        sys.exit(1)
    
    # Print graph statistics
    print(f"\n📊 Graph Statistics:")
    print(f"   - Nodes: {graph.stats['total_nodes']}")
    print(f"   - Edges: {graph.stats['total_edges']}")
    print(f"   - By type: {graph.stats['nodes_by_type']}")
    print(f"   - By risk: {graph.stats['nodes_by_risk']}")
    
    # Export based on format
    output_path = Path(args.output)
    exporter = GraphExporter(graph)
    
    print(f"\n💾 Exporting to {args.format.upper()} format...")
    
    try:
        if args.format == 'html':
            report_gen = ReportGenerator(graph, manifest_data)
            report_gen.generate_report(output_path, include_graph=not args.no_graph)
            print(f"✅ HTML report saved to {output_path}")
            
        elif args.format == 'mmd':
            exporter.export_mermaid(output_path)
            print(f"✅ Mermaid file saved to {output_path}")
            
        elif args.format == 'json':
            exporter.export_json(output_path)
            print(f"✅ JSON file saved to {output_path}")
            
        elif args.format == 'graphml':
            exporter.export_graphml(output_path)
            print(f"✅ GraphML file saved to {output_path}")
            
        elif args.format == 'svg':
            success = exporter.export_svg(output_path)
            if success:
                print(f"✅ SVG file saved to {output_path.with_suffix('.svg')}")
            else:
                print("⚠️  Could not generate SVG. Install mermaid-cli (npm install -g @mermaid-js/mermaid-cli)")
    
    except Exception as e:
        print(f"❌ Error during export: {e}")
        sys.exit(1)
    
    print("\n✨ Analysis complete!")


if __name__ == "__main__":
    main()