from typing import Dict, List, Set, Any, Optional
from .indexer import FileIndex, SymbolInfo

class CodebaseGraph:
    def __init__(self):
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.edges: List[Dict[str, Any]] = []

    def add_node(self, node_id: str, label: str, kind: str, metadata: Optional[Dict[str, Any]] = None):
        if node_id not in self.nodes:
            self.nodes[node_id] = {
                "id": node_id,
                "label": label,
                "kind": kind,
                "metadata": metadata or {}
            }

    def add_edge(self, source: str, target: str, relation: str):
        self.edges.append({
            "source": source,
            "target": target,
            "relation": relation
        })

    def query_authentication(self) -> List[Dict[str, Any]]:
        results = []
        for n_id, node in self.nodes.items():
            text = (node["label"] + " " + n_id).lower()
            if any(k in text for k in ["auth", "login", "jwt", "session", "password", "oauth"]):
                results.append(node)
        return results

    def query_affected_by_file(self, file_path: str) -> List[str]:
        affected = set()
        clean_file = file_path.replace("\\", "/")

        # Direct callers/importers
        for edge in self.edges:
            if edge["relation"] in ["IMPORTS", "CALLS"] and edge["target"] == clean_file:
                affected.add(edge["source"])
            elif edge["source"] == clean_file and edge["relation"] in ["CONTAINS"]:
                # Symbols inside file
                symbol_id = edge["target"]
                for sub_edge in self.edges:
                    if sub_edge["target"] == symbol_id:
                        affected.add(sub_edge["source"])

        return sorted(list(affected))

    def query_dependents(self, target_id: str) -> List[str]:
        dependents = set()
        for edge in self.edges:
            if edge["target"] == target_id:
                dependents.add(edge["source"])
        return sorted(list(dependents))

    def to_cytoscape_json(self) -> Dict[str, Any]:
        elements = []
        for node in self.nodes.values():
            elements.append({"data": node})
        for idx, edge in enumerate(self.edges):
            elements.append({
                "data": {
                    "id": f"edge-{idx}",
                    "source": edge["source"],
                    "target": edge["target"],
                    "label": edge["relation"]
                }
            })
        return {"elements": elements}

class GraphBuilder:
    @classmethod
    def build_from_index(cls, index: Dict[str, FileIndex]) -> CodebaseGraph:
        graph = CodebaseGraph()

        for rel_path, f_idx in index.items():
            # Add File Node
            graph.add_node(
                node_id=rel_path,
                label=rel_path.split("/")[-1],
                kind="file",
                metadata={"language": f_idx.language, "full_path": f_idx.file_path}
            )

            # Add Symbol Nodes & CONTAINS edges
            for sym in f_idx.symbols:
                sym_id = f"{rel_path}#{sym.name}"
                graph.add_node(
                    node_id=sym_id,
                    label=sym.name,
                    kind=sym.kind,
                    metadata={"line_start": sym.line_start, "line_end": sym.line_end}
                )
                graph.add_edge(source=rel_path, target=sym_id, relation="CONTAINS")

            # Add Route Nodes & DEFINES_API edges
            for route in f_idx.routes:
                route_id = f"API:{route}"
                graph.add_node(node_id=route_id, label=route, kind="api")
                graph.add_edge(source=rel_path, target=route_id, relation="DEFINES_API")

            # Add Imports & IMPORTS edges
            for imp in f_idx.imports:
                imp_id = f"DEP:{imp}"
                graph.add_node(node_id=imp_id, label=imp, kind="dependency")
                graph.add_edge(source=rel_path, target=imp_id, relation="IMPORTS")

                # If import matches another file in project
                for other_file in index.keys():
                    base = other_file.rsplit(".", 1)[0]
                    if imp in base or base.endswith(imp.replace(".", "/")):
                        graph.add_edge(source=rel_path, target=other_file, relation="IMPORTS_LOCAL")

        return graph
