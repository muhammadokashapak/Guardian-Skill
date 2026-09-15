import os
import ast
import re
from typing import Dict, List, Optional, Set, Any
from pydantic import BaseModel, Field

class SymbolInfo(BaseModel):
    name: str
    kind: str  # function, class, route, model, import
    file_path: str
    line_start: int
    line_end: int
    docstring: Optional[str] = None
    parameters: List[str] = Field(default_factory=list)

class FileIndex(BaseModel):
    file_path: str
    relative_path: str
    language: str
    file_hash: str
    symbols: List[SymbolInfo] = Field(default_factory=list)
    imports: List[str] = Field(default_factory=list)
    routes: List[str] = Field(default_factory=list)

class CodebaseIndexer:
    IGNORE_DIRS = {".git", "node_modules", "vendor", "__pycache__", ".next", "dist", "build"}

    def index_directory(self, root_path: str) -> Dict[str, FileIndex]:
        abs_root = os.path.realpath(os.path.abspath(root_path))
        index: Dict[str, FileIndex] = {}

        for dirpath, dirnames, filenames in os.walk(abs_root):
            dirnames[:] = [d for d in dirnames if d not in self.IGNORE_DIRS]
            for filename in filenames:
                full_path = os.path.join(dirpath, filename)
                rel_path = os.path.relpath(full_path, abs_root).replace("\\", "/")
                ext = os.path.splitext(filename)[1].lower()

                if ext in [".py", ".js", ".ts", ".jsx", ".tsx", ".php"]:
                    file_idx = self._index_file(abs_root, full_path, rel_path, ext)
                    if file_idx:
                        index[rel_path] = file_idx

        return index

    def _index_file(self, root: str, full_path: str, rel_path: str, ext: str) -> Optional[FileIndex]:
        try:
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception:
            return None

        import hashlib
        f_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()

        symbols: List[SymbolInfo] = []
        imports: List[str] = []
        routes: List[str] = []

        if ext == ".py":
            symbols, imports, routes = self._index_python(content, rel_path)
        elif ext in [".js", ".ts", ".jsx", ".tsx"]:
            symbols, imports, routes = self._index_javascript(content, rel_path)
        elif ext == ".php":
            symbols, imports, routes = self._index_php(content, rel_path)

        lang_map = {
            ".py": "Python", ".js": "JavaScript", ".ts": "TypeScript",
            ".jsx": "JavaScript", ".tsx": "TypeScript", ".php": "PHP"
        }

        return FileIndex(
            file_path=full_path,
            relative_path=rel_path,
            language=lang_map.get(ext, "Unknown"),
            file_hash=f_hash,
            symbols=symbols,
            imports=imports,
            routes=routes
        )

    def _index_python(self, content: str, rel_path: str):
        symbols = []
        imports = []
        routes = []

        try:
            tree = ast.parse(content)
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef) or isinstance(node, ast.AsyncFunctionDef):
                    # Check decorators for routes
                    for dec in node.decorator_list:
                        dec_repr = ast.unparse(dec) if hasattr(ast, "unparse") else ""
                        if any(k in dec_repr for k in ["get", "post", "put", "delete", "route"]):
                            routes.append(f"{dec_repr} -> {node.name}")

                    symbols.append(SymbolInfo(
                        name=node.name,
                        kind="function",
                        file_path=rel_path,
                        line_start=node.lineno,
                        line_end=getattr(node, "end_lineno", node.lineno),
                        docstring=ast.get_docstring(node),
                        parameters=[a.arg for a in node.args.args]
                    ))
                elif isinstance(node, ast.ClassDef):
                    symbols.append(SymbolInfo(
                        name=node.name,
                        kind="class",
                        file_path=rel_path,
                        line_start=node.lineno,
                        line_end=getattr(node, "end_lineno", node.lineno),
                        docstring=ast.get_docstring(node)
                    ))
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.append(alias.name)
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        imports.append(node.module)
        except Exception:
            # Fallback regex
            for line_idx, line in enumerate(content.splitlines(), start=1):
                m_fn = re.search(r"^\s*def\s+([a-zA-Z0-9_]+)\s*\(", line)
                if m_fn:
                    symbols.append(SymbolInfo(name=m_fn.group(1), kind="function", file_path=rel_path, line_start=line_idx, line_end=line_idx))
                m_cl = re.search(r"^\s*class\s+([a-zA-Z0-9_]+)", line)
                if m_cl:
                    symbols.append(SymbolInfo(name=m_cl.group(1), kind="class", file_path=rel_path, line_start=line_idx, line_end=line_idx))

        return symbols, imports, routes

    def _index_javascript(self, content: str, rel_path: str):
        symbols = []
        imports = []
        routes = []

        lines = content.splitlines()
        for idx, line in enumerate(lines, start=1):
            # Imports
            imp_m = re.search(r"(?:import\s+.*?from\s+['\"](.*?)['\"]|require\(['\"](.*?)['\"]\))", line)
            if imp_m:
                imports.append(imp_m.group(1) or imp_m.group(2))

            # Functions / Arrow functions / Components
            fn_m = re.search(r"(?:function\s+([a-zA-Z0-9_]+)|const\s+([a-zA-Z0-9_]+)\s*=\s*(?:async\s*)?\()", line)
            if fn_m:
                name = fn_m.group(1) or fn_m.group(2)
                symbols.append(SymbolInfo(name=name, kind="function", file_path=rel_path, line_start=idx, line_end=idx))

            # Classes
            cl_m = re.search(r"class\s+([a-zA-Z0-9_]+)", line)
            if cl_m:
                symbols.append(SymbolInfo(name=cl_m.group(1), kind="class", file_path=rel_path, line_start=idx, line_end=idx))

            # Routes (e.g. app.get('/...', ...))
            route_m = re.search(r"\bapp\.(get|post|put|delete|patch)\s*\(\s*['\"]([^'\"]+)['\"]", line)
            if route_m:
                routes.append(f"{route_m.group(1).upper()} {route_m.group(2)}")

        return symbols, imports, routes

    def _index_php(self, content: str, rel_path: str):
        symbols = []
        imports = []
        routes = []

        lines = content.splitlines()
        for idx, line in enumerate(lines, start=1):
            # Use statements
            use_m = re.search(r"^\s*use\s+([^;]+);", line)
            if use_m:
                imports.append(use_m.group(1).strip())

            # Classes
            cl_m = re.search(r"^\s*(?:abstract\s+)?class\s+([a-zA-Z0-9_]+)", line)
            if cl_m:
                symbols.append(SymbolInfo(name=cl_m.group(1), kind="class", file_path=rel_path, line_start=idx, line_end=idx))

            # Methods / Functions
            fn_m = re.search(r"^\s*(?:public|protected|private|static)?\s*function\s+([a-zA-Z0-9_]+)", line)
            if fn_m:
                symbols.append(SymbolInfo(name=fn_m.group(1), kind="function", file_path=rel_path, line_start=idx, line_end=idx))

            # Laravel Route::get/post
            route_m = re.search(r"Route::(get|post|put|delete|patch)\s*\(\s*['\"]([^'\"]+)['\"]", line)
            if route_m:
                routes.append(f"{route_m.group(1).upper()} {route_m.group(2)}")

        return symbols, imports, routes
