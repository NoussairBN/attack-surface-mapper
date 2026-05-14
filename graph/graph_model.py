"""Data models for graph structure."""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Any
from enum import Enum
import uuid


class ComponentType(Enum):
    ACTIVITY = "activity"
    SERVICE = "service"
    BROADCAST_RECEIVER = "receiver"
    CONTENT_PROVIDER = "provider"


class RiskLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class EdgeType(Enum):
    INTENT = "intent"
    PERMISSION = "permission"
    DATA_FLOW = "data_flow"
    EXPORT = "export"


@dataclass
class ComponentNode:
    """Represents a component node in the graph."""
    id: str
    name: str
    type: ComponentType
    exported: bool = False
    permission: Optional[str] = None
    risk_level: RiskLevel = RiskLevel.INFO
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        if not self.id:
            self.id = str(uuid.uuid4())
    
    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'name': self.name,
            'type': self.type.value,
            'exported': self.exported,
            'permission': self.permission,
            'risk_level': self.risk_level.value,
            'metadata': self.metadata
        }
    
    @property
    def color(self) -> str:
        """Get color based on risk level."""
        colors = {
            RiskLevel.CRITICAL: "#ff0000",
            RiskLevel.HIGH: "#ff6600", 
            RiskLevel.MEDIUM: "#ffcc00",
            RiskLevel.LOW: "#00cc00",
            RiskLevel.INFO: "#3399ff"
        }
        return colors.get(self.risk_level, "#cccccc")
    
    @property
    def shape(self) -> str:
        """Get shape based on component type."""
        shapes = {
            ComponentType.ACTIVITY: "rectangle",
            ComponentType.SERVICE: "diamond",
            ComponentType.BROADCAST_RECEIVER: "circle",
            ComponentType.CONTENT_PROVIDER: "hexagon"
        }
        return shapes.get(self.type, "rectangle")


@dataclass
class IntentEdge:
    """Represents an edge between components."""
    id: str
    source_id: str
    target_id: str
    type: EdgeType
    label: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        if not self.id:
            self.id = str(uuid.uuid4())
    
    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'source': self.source_id,
            'target': self.target_id,
            'type': self.type.value,
            'label': self.label,
            'metadata': self.metadata
        }
    
    @property
    def line_style(self) -> str:
        """Get line style based on edge type."""
        styles = {
            EdgeType.INTENT: "solid",
            EdgeType.PERMISSION: "dashed",
            EdgeType.DATA_FLOW: "dotted",
            EdgeType.EXPORT: "solid"
        }
        return styles.get(self.type, "solid")


@dataclass
class GraphModel:
    """Main graph model containing nodes and edges."""
    nodes: Dict[str, ComponentNode] = field(default_factory=dict)
    edges: List[IntentEdge] = field(default_factory=list)
    
    def add_node(self, node: ComponentNode) -> None:
        """Add a node to the graph."""
        self.nodes[node.id] = node
    
    def add_edge(self, edge: IntentEdge) -> None:
        """Add an edge to the graph."""
        self.edges.append(edge)
    
    def remove_node(self, node_id: str) -> None:
        """Remove a node and its associated edges."""
        if node_id in self.nodes:
            del self.nodes[node_id]
            self.edges = [e for e in self.edges if e.source_id != node_id and e.target_id != node_id]
    
    def get_node(self, node_id: str) -> Optional[ComponentNode]:
        """Get node by ID."""
        return self.nodes.get(node_id)
    
    def get_edges_for_node(self, node_id: str) -> List[IntentEdge]:
        """Get all edges connected to a node."""
        return [e for e in self.edges if e.source_id == node_id or e.target_id == node_id]
    
    def get_neighbors(self, node_id: str) -> List[ComponentNode]:
        """Get neighboring nodes."""
        neighbors = []
        for edge in self.edges:
            if edge.source_id == node_id and edge.target_id in self.nodes:
                neighbors.append(self.nodes[edge.target_id])
            elif edge.target_id == node_id and edge.source_id in self.nodes:
                neighbors.append(self.nodes[edge.source_id])
        return neighbors
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization."""
        return {
            'nodes': [node.to_dict() for node in self.nodes.values()],
            'edges': [edge.to_dict() for edge in self.edges]
        }
    
    @property
    def stats(self) -> Dict:
        """Get graph statistics."""
        stats = {
            'total_nodes': len(self.nodes),
            'total_edges': len(self.edges),
            'nodes_by_type': {},
            'nodes_by_risk': {},
            'edges_by_type': {}
        }
        
        for node in self.nodes.values():
            node_type = node.type.value
            stats['nodes_by_type'][node_type] = stats['nodes_by_type'].get(node_type, 0) + 1
            
            risk = node.risk_level.value
            stats['nodes_by_risk'][risk] = stats['nodes_by_risk'].get(risk, 0) + 1
        
        for edge in self.edges:
            edge_type = edge.type.value
            stats['edges_by_type'][edge_type] = stats['edges_by_type'].get(edge_type, 0) + 1
        
        return stats