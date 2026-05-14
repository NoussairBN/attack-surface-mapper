"""Layout engine for graph organization and clustering."""

from typing import List, Dict, Set, Tuple, Optional
from collections import defaultdict
from .graph_model import GraphModel, ComponentNode, IntentEdge, ComponentType, RiskLevel


class LayoutEngine:
    """Organizes graph layout with clustering and positioning."""
    
    def __init__(self, graph_model: GraphModel):
        self.graph = graph_model
        self.clusters: Dict[str, List[str]] = {}
    
    def detect_clusters(self) -> Dict[str, List[str]]:
        """Detect natural clusters in the graph based on connectivity."""
        clusters = {}
        visited = set()
        cluster_id = 0
        
        def dfs(node_id: str, current_cluster: List[str]) -> None:
            visited.add(node_id)
            current_cluster.append(node_id)
            neighbors = self.graph.get_neighbors(node_id)
            for neighbor in neighbors:
                if neighbor.id not in visited:
                    dfs(neighbor.id, current_cluster)
        
        for node_id in self.graph.nodes:
            if node_id not in visited:
                current_cluster = []
                dfs(node_id, current_cluster)
                if len(current_cluster) > 1:  # Only consider clusters with multiple nodes
                    clusters[f"cluster_{cluster_id}"] = current_cluster
                    cluster_id += 1
        
        self.clusters = clusters
        return clusters
    
    def group_by_component_type(self) -> Dict[ComponentType, List[str]]:
        """Group nodes by component type."""
        groups = defaultdict(list)
        for node_id, node in self.graph.nodes.items():
            groups[node.type].append(node_id)
        return dict(groups)
    
    def group_by_risk_level(self) -> Dict[RiskLevel, List[str]]:
        """Group nodes by risk level."""
        groups = defaultdict(list)
        for node_id, node in self.graph.nodes.items():
            groups[node.risk_level].append(node_id)
        return dict(groups)
    
    def suggest_layout(self) -> Dict[str, any]:
        """Suggest optimal layout configuration."""
        stats = self.graph.stats
        
        # Determine layout type based on graph size
        if stats['total_nodes'] < 10:
            layout_type = "simple"
        elif stats['total_nodes'] < 20:
            layout_type = "hierarchical"
        else:
            layout_type = "clustered"
        
        # Determine direction based on edge types
        has_export_edges = any(e.type.value == 'export' for e in self.graph.edges)
        direction = "LR" if has_export_edges else "TB"
        
        return {
            'layout_type': layout_type,
            'direction': direction,
            'clusters': self.detect_clusters(),
            'groups_by_type': self.group_by_component_type(),
            'groups_by_risk': self.group_by_risk_level()
        }
    
    def calculate_centrality(self) -> Dict[str, float]:
        """Calculate simple centrality scores for nodes."""
        centrality = {}
        
        for node_id in self.graph.nodes:
            # Degree centrality (number of connections)
            degree = len(self.graph.get_edges_for_node(node_id))
            # Normalize by max possible degree
            max_degree = len(self.graph.nodes) - 1
            centrality[node_id] = degree / max_degree if max_degree > 0 else 0
        
        return centrality
    
    def find_exported_components(self) -> List[str]:
        """Find all exported components."""
        return [node_id for node_id, node in self.graph.nodes.items() if node.exported]
    
    def find_entry_points(self) -> List[str]:
        """Find potential entry points (exported components with intent filters)."""
        entry_points = []
        for node_id, node in self.graph.nodes.items():
            if node.exported and 'has_intent_filter' in node.metadata:
                if node.metadata['has_intent_filter']:
                    entry_points.append(node_id)
        return entry_points
    
    def optimize_for_visualization(self) -> GraphModel:
        """Create optimized version of graph for visualization."""
        # Remove isolated nodes if too many
        isolated_nodes = []
        for node_id in self.graph.nodes:
            if len(self.graph.get_edges_for_node(node_id)) == 0:
                isolated_nodes.append(node_id)
        
        # Keep isolated nodes but mark them for simpler display
        optimized_graph = GraphModel()
        
        for node_id, node in self.graph.nodes.items():
            # Add all nodes
            optimized_graph.add_node(node)
            
            # Mark isolated nodes
            if node_id in isolated_nodes:
                node.metadata['isolated'] = True
        
        # Add all edges
        for edge in self.graph.edges:
            optimized_graph.add_edge(edge)
        
        return optimized_graph