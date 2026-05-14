"""Unit tests for graph module."""

import unittest
import tempfile
from pathlib import Path
import json
import sys
import os

sys.path.insert(0, str(Path(__file__).parent.parent))

from graph.graph_model import GraphModel, ComponentNode, IntentEdge, ComponentType, RiskLevel, EdgeType
from graph.mermaid_builder import MermaidBuilder
from graph.graph_exporter import GraphExporter
from graph.layout_engine import LayoutEngine


class TestGraphModel(unittest.TestCase):
    """Test graph model functionality."""
    
    def setUp(self):
        self.graph = GraphModel()
        
        # Create test nodes
        self.node1 = ComponentNode(
            id="test1",
            name="TestActivity",
            type=ComponentType.ACTIVITY,
            exported=True,
            risk_level=RiskLevel.HIGH
        )
        
        self.node2 = ComponentNode(
            id="test2", 
            name="TestService",
            type=ComponentType.SERVICE,
            exported=False,
            risk_level=RiskLevel.LOW
        )
        
        self.graph.add_node(self.node1)
        self.graph.add_node(self.node2)
        
        self.edge = IntentEdge(
            id="edge1",
            source_id="test1",
            target_id="test2",
            type=EdgeType.INTENT,
            label="test_edge"
        )
        self.graph.add_edge(self.edge)
    
    def test_add_node(self):
        """Test adding nodes to graph."""
        self.assertEqual(len(self.graph.nodes), 2)
        self.assertIn("test1", self.graph.nodes)
        self.assertIn("test2", self.graph.nodes)
    
    def test_add_edge(self):
        """Test adding edges to graph."""
        self.assertEqual(len(self.graph.edges), 1)
        self.assertEqual(self.graph.edges[0].source_id, "test1")
        self.assertEqual(self.graph.edges[0].target_id, "test2")
    
    def test_remove_node(self):
        """Test removing nodes."""
        self.graph.remove_node("test1")
        self.assertEqual(len(self.graph.nodes), 1)
        self.assertEqual(len(self.graph.edges), 0)
    
    def test_get_neighbors(self):
        """Test getting neighbors of a node."""
        neighbors = self.graph.get_neighbors("test1")
        self.assertEqual(len(neighbors), 1)
        self.assertEqual(neighbors[0].id, "test2")
    
    def test_stats(self):
        """Test graph statistics."""
        stats = self.graph.stats
        self.assertEqual(stats['total_nodes'], 2)
        self.assertEqual(stats['total_edges'], 1)
        self.assertEqual(stats['nodes_by_type']['activity'], 1)
        self.assertEqual(stats['nodes_by_type']['service'], 1)


class TestMermaidBuilder(unittest.TestCase):
    """Test Mermaid diagram builder."""
    
    def setUp(self):
        self.graph = GraphModel()
        node = ComponentNode(
            id="test",
            name="TestComponent",
            type=ComponentType.ACTIVITY,
            exported=True,
            risk_level=RiskLevel.CRITICAL
        )
        self.graph.add_node(node)
        self.builder = MermaidBuilder(self.graph)
    
    def test_build(self):
        """Test building Mermaid code."""
        mermaid_code = self.builder.build()
        self.assertIn("```mermaid", mermaid_code)
        self.assertIn("flowchart LR", mermaid_code)
        self.assertIn("TestComponent", mermaid_code)
    
    def test_node_styling(self):
        """Test node styling generation."""
        styles = self.builder._build_styling_definitions()
        self.assertTrue(len(styles) > 0)
        self.assertIn("classDef", styles[0])


class TestGraphExporter(unittest.TestCase):
    """Test graph exporter functionality."""
    
    def setUp(self):
        self.graph = GraphModel()
        node = ComponentNode(
            id="test",
            name="TestComponent",
            type=ComponentType.ACTIVITY,
            exported=True
        )
        self.graph.add_node(node)
        self.exporter = GraphExporter(self.graph)
    
    def test_export_json(self):
        """Test JSON export."""
        # Create temporary file path
        tmp_file = tempfile.NamedTemporaryFile(suffix='.json', delete=False)
        tmp_path = Path(tmp_file.name)
        tmp_file.close()  # Close the file handle
        
        try:
            # Export to the temp file
            self.exporter.export_json(tmp_path)
            
            # Read and verify
            with open(tmp_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            self.assertIn('nodes', data)
            self.assertEqual(len(data['nodes']), 1)
        finally:
            # Clean up
            if tmp_path.exists():
                tmp_path.unlink()
    
    def test_export_mermaid(self):
        """Test Mermaid export."""
        # Create temporary file path
        tmp_file = tempfile.NamedTemporaryFile(suffix='.mmd', delete=False)
        tmp_path = Path(tmp_file.name)
        tmp_file.close()  # Close the file handle
        
        try:
            # Export to the temp file
            self.exporter.export_mermaid(tmp_path)
            
            # Read and verify
            with open(tmp_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            self.assertIn("```mermaid", content)
        finally:
            # Clean up
            if tmp_path.exists():
                tmp_path.unlink()
    
    def test_export_html_embed(self):
        """Test HTML embed export."""
        # Create temporary file path
        tmp_file = tempfile.NamedTemporaryFile(suffix='.html', delete=False)
        tmp_path = Path(tmp_file.name)
        tmp_file.close()
        
        try:
            self.exporter.export_html_embed(tmp_path)
            
            with open(tmp_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            self.assertIn("<!DOCTYPE html>", content)
            self.assertIn("Attack Surface Graph", content)
        finally:
            if tmp_path.exists():
                tmp_path.unlink()


class TestLayoutEngine(unittest.TestCase):
    """Test layout engine functionality."""
    
    def setUp(self):
        self.graph = GraphModel()
        
        # Create a small graph
        nodes = [
            ComponentNode(id=f"node{i}", name=f"Node{i}", type=ComponentType.ACTIVITY)
            for i in range(3)
        ]
        for node in nodes:
            self.graph.add_node(node)
        
        edges = [
            IntentEdge(id=f"e{i}", source_id="node0", target_id=f"node{i+1}", type=EdgeType.INTENT)
            for i in range(2)
        ]
        for edge in edges:
            self.graph.add_edge(edge)
        
        self.engine = LayoutEngine(self.graph)
    
    def test_detect_clusters(self):
        """Test cluster detection."""
        clusters = self.engine.detect_clusters()
        self.assertIsInstance(clusters, dict)
    
    def test_group_by_component_type(self):
        """Test grouping by component type."""
        groups = self.engine.group_by_component_type()
        self.assertIn(ComponentType.ACTIVITY, groups)
        self.assertEqual(len(groups[ComponentType.ACTIVITY]), 3)
    
    def test_find_exported_components(self):
        """Test finding exported components."""
        exported = self.engine.find_exported_components()
        self.assertEqual(len(exported), 0)
    
    def test_calculate_centrality(self):
        """Test centrality calculation."""
        centrality = self.engine.calculate_centrality()
        self.assertEqual(len(centrality), 3)
        self.assertGreater(centrality['node0'], centrality['node1'])
    
    def test_find_entry_points(self):
        """Test finding entry points."""
        entry_points = self.engine.find_entry_points()
        self.assertIsInstance(entry_points, list)
    
    def test_suggest_layout(self):
        """Test layout suggestions."""
        layout = self.engine.suggest_layout()
        self.assertIn('layout_type', layout)
        self.assertIn('direction', layout)


if __name__ == '__main__':
    unittest.main()