import os
import hashlib
from typing import Dict, List, Set, Any
from pydantic import BaseModel, Field

class DiscoveryProfile(BaseModel):
    root_path: str
    tree_hash: str
    total_files: int
    languages: List[str] = Field(default_factory=list)
    frameworks: List[str] = Field(default_factory=list)
    package_managers: List[str] = Field(default_factory=list)
    databases: List[str] = Field(default_factory=list)
    ci_cd: List[str] = Field(default_factory=list)
    containers: List[str] = Field(default_factory=list)
    test_frameworks: List[str] = Field(default_factory=list)
    entry_points: List[str] = Field(default_factory=list)

class ProjectDiscoveryService:
    EXTENSION_MAP = {
        ".php": "PHP",
        ".js": "JavaScript",
        ".jsx": "JavaScript",
        ".ts": "TypeScript",
        ".tsx": "TypeScript",
        ".py": "Python",
        ".go": "Go",
        ".rs": "Rust",
        ".java": "Java",
        ".rb": "Ruby",
        ".cs": "C#",
        ".html": "HTML",
        ".css": "CSS",
        ".sql": "SQL",
    }

    IGNORE_DIRS = {
        ".git", "node_modules", "vendor", "__pycache__", ".next", "dist", "build", "storage"
    }

    def discover(self, root_path: str) -> DiscoveryProfile:
        abs_root = os.path.realpath(os.path.abspath(root_path))
        languages: Set[str] = set()
        frameworks: Set[str] = set()
        package_managers: Set[str] = set()
        databases: Set[str] = set()
        ci_cd: Set[str] = set()
        containers: Set[str] = set()
        test_frameworks: Set[str] = set()
        entry_points: List[str] = []

        total_files = 0
        hasher = hashlib.sha256()

        for dirpath, dirnames, filenames in os.walk(abs_root):
            # Prune ignored directories
            dirnames[:] = [d for d in dirnames if d not in self.IGNORE_DIRS]

            for filename in filenames:
                total_files += 1
                rel_path = os.path.relpath(os.path.join(dirpath, filename), abs_root)
                hasher.update(rel_path.encode("utf-8"))

                # Extension / Language
                ext = os.path.splitext(filename)[1].lower()
                if ext in self.EXTENSION_MAP:
                    languages.add(self.EXTENSION_MAP[ext])

                # Frameworks / Manifests
                fl = filename.lower()
                if fl == "composer.json":
                    package_managers.add("Composer")
                elif fl == "package.json":
                    package_managers.add("npm")
                elif fl in ["yarn.lock"]:
                    package_managers.add("Yarn")
                elif fl in ["pnpm-lock.yaml"]:
                    package_managers.add("pnpm")
                elif fl in ["requirements.txt", "pyproject.toml", "pipfile"]:
                    package_managers.add("pip")

                # Framework signatures
                if fl == "artisan":
                    frameworks.add("Laravel")
                    entry_points.append(rel_path)
                elif fl in ["next.config.js", "next.config.mjs", "next.config.ts"]:
                    frameworks.add("Next.js")
                elif "vite.config" in fl:
                    frameworks.add("Vite")

                # Containers
                if "dockerfile" in fl:
                    containers.add("Docker")
                elif "docker-compose" in fl:
                    containers.add("Docker Compose")

                # CI/CD
                if ".github/workflows" in dirpath.replace("\\", "/"):
                    ci_cd.add("GitHub Actions")
                elif fl in [".gitlab-ci.yml"]:
                    ci_cd.add("GitLab CI")

                # Test Frameworks
                if "phpunit.xml" in fl:
                    test_frameworks.add("PHPUnit")
                elif "jest.config" in fl:
                    test_frameworks.add("Jest")
                elif fl in ["pytest.ini", "conftest.py"] or filename.startswith("test_"):
                    test_frameworks.add("Pytest")

                # Entry points
                if fl in ["app.js", "server.js", "index.js", "index.ts", "main.py", "app.py", "server.py"]:
                    entry_points.append(rel_path)

        # Content inspection for frameworks & databases if files exist
        req_file = os.path.join(abs_root, "package.json")
        if os.path.exists(req_file):
            try:
                with open(req_file, "r", encoding="utf-8") as f:
                    content = f.read().lower()
                    if "express" in content:
                        frameworks.add("Express")
                    if "react" in content:
                        frameworks.add("React")
                    if "next" in content:
                        frameworks.add("Next.js")
                    if "mysql" in content or "mysql2" in content:
                        databases.add("MySQL")
                    if "pg" in content or "postgres" in content:
                        databases.add("PostgreSQL")
                    if "mongodb" in content or "mongoose" in content:
                        databases.add("MongoDB")
            except Exception:
                pass

        composer_file = os.path.join(abs_root, "composer.json")
        if os.path.exists(composer_file):
            try:
                with open(composer_file, "r", encoding="utf-8") as f:
                    c_content = f.read().lower()
                    if "laravel/framework" in c_content:
                        frameworks.add("Laravel")
            except Exception:
                pass

        py_req = os.path.join(abs_root, "requirements.txt")
        if os.path.exists(py_req):
            try:
                with open(py_req, "r", encoding="utf-8") as f:
                    p_content = f.read().lower()
                    if "fastapi" in p_content:
                        frameworks.add("FastAPI")
                    if "flask" in p_content:
                        frameworks.add("Flask")
                    if "django" in p_content:
                        frameworks.add("Django")
            except Exception:
                pass

        return DiscoveryProfile(
            root_path=abs_root,
            tree_hash=hasher.hexdigest(),
            total_files=total_files,
            languages=sorted(list(languages)),
            frameworks=sorted(list(frameworks)),
            package_managers=sorted(list(package_managers)),
            databases=sorted(list(databases)),
            ci_cd=sorted(list(ci_cd)),
            containers=sorted(list(containers)),
            test_frameworks=sorted(list(test_frameworks)),
            entry_points=sorted(entry_points),
        )
