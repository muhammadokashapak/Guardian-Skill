from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from ..codebase.graph_builder import CodebaseGraph
from ..ai.router import AIRouter

class ChangeImpactReport(BaseModel):
    change_description: str
    target_files: List[str] = Field(default_factory=list)
    affected_components: List[str] = Field(default_factory=list)
    affected_apis: List[str] = Field(default_factory=list)
    affected_database_tables: List[str] = Field(default_factory=list)
    affect_tests: List[str] = Field(default_factory=list)
    security_implications: List[str] = Field(default_factory=list)
    backward_compatible: bool = True
    migration_required: bool = False
    rollback_strategy: str = "Revert git commit"
    deployment_risk: str = "LOW"
    ai_reasoning: str = ""

class ChangeImpactAnalyzer:
    def __init__(self, ai_router: AIRouter):
        self.ai_router = ai_router

    def analyze(self, graph: CodebaseGraph, change_description: str, target_file: Optional[str] = None) -> ChangeImpactReport:
        affected_files = set()
        affected_apis = []
        affected_tables = []
        affect_tests = []
        security_implications = []
        migration_required = False
        backward_compatible = True
        risk = "LOW"

        c_lower = change_description.lower()

        # 1. Query Codebase Graph
        if target_file:
            affected_files.add(target_file)
            for aff in graph.query_affected_by_file(target_file):
                affected_files.add(aff)

        for n_id, node in graph.nodes.items():
            kind = node.get("kind")
            label = node.get("label", "")
            if kind == "api" and any(k in label.lower() for k in c_lower.split()):
                affected_apis.append(label)
            if kind == "file" and ("test" in label.lower() or "spec" in label.lower()):
                affect_tests.append(label)

        # 2. Risk heuristics
        if any(k in c_lower for k in ["database", "migration", "column", "table", "schema"]):
            migration_required = True
            affected_tables.append("primary_entities")
            risk = "MEDIUM"

        if any(k in c_lower for k in ["auth", "token", "password", "crypto", "permission", "security"]):
            security_implications.append("Modifies core security/authentication perimeter; requires regression testing.")
            risk = "HIGH"

        if any(k in c_lower for k in ["delete", "remove", "drop", "deprecate", "break"]):
            backward_compatible = False
            risk = "HIGH"

        # 3. Correlate with AI Gateway
        ai_resp = self.ai_router.reason(
            task_instruction=f"Assess impact of proposed change: '{change_description}'",
            untrusted_context=f"Target: {target_file}\nAffected files: {list(affected_files)}\nAffected APIs: {affected_apis}"
        )

        return ChangeImpactReport(
            change_description=change_description,
            target_files=sorted(list(affected_files)),
            affected_components=[f"Component({f})" for f in list(affected_files)[:5]],
            affected_apis=affected_apis,
            affected_database_tables=affected_tables,
            affect_tests=affect_tests,
            security_implications=security_implications,
            backward_compatible=backward_compatible,
            migration_required=migration_required,
            deployment_risk=risk,
            ai_reasoning=ai_resp.content
        )
