"""Mermaid diagram builder for graph visualization."""

from typing import List, Dict, Optional
from .graph_model import GraphModel, ComponentNode, IntentEdge, ComponentType, RiskLevel, EdgeType


class MermaidBuilder:
    """Builds Mermaid flowchart code from graph model."""
    
    def __init__(self, graph_model: GraphModel):
        self.graph = graph_model
        self.node_ids: Dict[str, str] = {}  # Map original IDs to Mermaid IDs
        self._generate_node_ids()
    
    def _generate_node_ids(self) -> None:
        """Generate simplified IDs for Mermaid."""
        for idx, node_id in enumerate(self.graph.nodes.keys()):
            self.node_ids[node_id] = f"N{idx}"
    
    def _get_node_style(self, node: ComponentNode) -> str:
        """Get Mermaid node styling."""
        color_map = {
            RiskLevel.CRITICAL: "#ffcccc",
            RiskLevel.HIGH: "#ffe6cc", 
            RiskLevel.MEDIUM: "#ffffcc",
            RiskLevel.LOW: "#ccffcc",
            RiskLevel.INFO: "#cce5ff"
        }
        
        shape_map = {
            ComponentType.ACTIVITY: "([{}])",
            ComponentType.SERVICE: "{{{{{}}}}}",
            ComponentType.BROADCAST_RECEIVER: "(({}))",
            ComponentType.CONTENT_PROVIDER: "[({})]"
        }
        
        color = color_map.get(node.risk_level, "#e0e0e0")
        shape = shape_map.get(node.type, "[{}]")
        
        # Add export badge
        name = node.name
        if node.exported:
            name = f"{name} 🔓"
        
        return shape.format(name), color
    
    def _build_node_definition(self, node_id: str, node: ComponentNode) -> str:
        """Build a single node definition."""
        mermaid_id = self.node_ids[node_id]
        label, color = self._get_node_style(node)
        return f'    {mermaid_id}{label}'
    
    def _build_edge_definition(self, edge: IntentEdge) -> str:
        """Build a single edge definition."""
        source_id = self.node_ids[edge.source_id]
        target_id = self.node_ids[edge.target_id]
        
        # Different line styles for edge types
        style_map = {
            EdgeType.INTENT: "-->",
            EdgeType.PERMISSION: "-.->",
            EdgeType.DATA_FLOW: "-..->",
            EdgeType.EXPORT: "==>"
        }
        
        style = style_map.get(edge.type, "-->")
        
        if edge.label:
            return f'    {source_id} {style}|{edge.label}| {target_id}'
        else:
            return f'    {source_id} {style} {target_id}'
    
    def _build_styling_definitions(self) -> List[str]:
        """Build CSS class styling for nodes."""
        styles = []
        risk_classes = {}
        
        # Group nodes by risk level
        for node_id, node in self.graph.nodes.items():
            risk = node.risk_level.value
            if risk not in risk_classes:
                risk_classes[risk] = []
            risk_classes[risk].append(self.node_ids[node_id])
        
        # Define styles for each risk level
        style_map = {
            RiskLevel.CRITICAL.value: "fill:#ffcccc,stroke:#cc0000,stroke-width:3px",
            RiskLevel.HIGH.value: "fill:#ffe6cc,stroke:#ff6600,stroke-width:2px",
            RiskLevel.MEDIUM.value: "fill:#ffffcc,stroke:#ccaa00,stroke-width:2px", 
            RiskLevel.LOW.value: "fill:#ccffcc,stroke:#00aa00,stroke-width:1px",
            RiskLevel.INFO.value: "fill:#cce5ff,stroke:#0066cc,stroke-width:1px"
        }
        
        for risk, node_list in risk_classes.items():
            if node_list:
                style = style_map.get(risk, "fill:#e0e0e0,stroke:#666")
                class_name = f"{risk}Node"
                styles.append(f'    classDef {class_name} {style};')
                styles.append(f'    class {",".join(node_list)} {class_name};')
        
        return styles
    
    def build(self) -> str:
        """Build complete Mermaid flowchart code."""
        lines = ["```mermaid", "flowchart LR"]
        
        # Add subgraphs for exported vs internal
        exported_nodes = []
        internal_nodes = []
        
        for node_id, node in self.graph.nodes.items():
            if node.exported:
                exported_nodes.append(node_id)
            else:
                internal_nodes.append(node_id)
        
        # Build internal components subgraph
        if internal_nodes:
            lines.append("    subgraph InternalComponents[Internal Components]")
            for node_id in internal_nodes:
                if node_id in self.graph.nodes:
                    lines.append(self._build_node_definition(node_id, self.graph.nodes[node_id]))
            lines.append("    end")
        
        # Build exported components subgraph
        if exported_nodes:
            lines.append("    subgraph ExportedComponents[🔓 Exported Components]")
            for node_id in exported_nodes:
                if node_id in self.graph.nodes:
                    lines.append(self._build_node_definition(node_id, self.graph.nodes[node_id]))
            lines.append("    end")
        
        # Add standalone nodes not in subgraphs
        all_subgraph_nodes = set(internal_nodes + exported_nodes)
        for node_id, node in self.graph.nodes.items():
            if node_id not in all_subgraph_nodes:
                lines.append(self._build_node_definition(node_id, node))
        
        # Add edges
        lines.append("")
        for edge in self.graph.edges:
            lines.append(self._build_edge_definition(edge))
        
        # Add styling
        lines.extend(self._build_styling_definitions())
        
        lines.append("```")
        return "\n".join(lines)
    
    def build_html_embed(self) -> str:
        """Build HTML embed code for Mermaid."""
        mermaid_code = self.build()
        return f"""
<div class="mermaid-container">
    <div class="mermaid">
{mermaid_code}
    </div>
</div>
"""
    
    def build_with_interactivity(self) -> str:
        """Build Mermaid with interactive tooltips."""
        lines = ["```mermaid", "flowchart LR"]
        
        # Build nodes with tooltips
        for node_id, node in self.graph.nodes.items():
            mermaid_id = self.node_ids[node_id]
            label, color = self._get_node_style(node)
            tooltip = f"Component: {node.name}\\nType: {node.type.value}\\nExported: {node.exported}"
            if node.permission:
                tooltip += f"\\nPermission: {node.permission}"
            lines.append(f'    {mermaid_id}{label} click {mermaid_id} call showTooltip("{tooltip}")')
        
        # Build edges
        for edge in self.graph.edges:
            lines.append(self._build_edge_definition(edge))
        
        lines.append("```")
        return "\n".join(lines)