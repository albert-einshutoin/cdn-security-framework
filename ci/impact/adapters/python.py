#!/usr/bin/env python3
"""Select Python tests through reverse imports using only the standard library."""

from __future__ import annotations

import ast
import json
from pathlib import Path
import sys
from typing import Any


def normalize(path: Path) -> str:
    return path.as_posix().removeprefix("./")


def module_name(project_root: Path, file_path: Path) -> str:
    relative = file_path.relative_to(project_root).with_suffix("")
    parts = list(relative.parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def is_test(path_value: str) -> bool:
    name = Path(path_value).name
    return (
        path_value.startswith("tests/")
        or path_value.startswith("test/")
        or name.startswith("test_")
        or name.endswith("_test.py")
    )


def imported_modules(tree: ast.AST, current_module: str) -> list[tuple[str, bool]]:
    imports: list[tuple[str, bool]] = []
    package_parts = current_module.split(".")[:-1]
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend((alias.name, False) for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            base_parts = package_parts[:] if node.level else []
            if node.level:
                trim = max(node.level - 1, 0)
                if trim:
                    base_parts = base_parts[:-trim]
            module_parts = node.module.split(".") if node.module else []
            base = ".".join([*base_parts, *module_parts])
            if base:
                imports.append((base, node.level > 0))
            for alias in node.names:
                candidate = ".".join(part for part in [base, alias.name] if part)
                if candidate:
                    imports.append((candidate, node.level > 0))
    return imports


def main() -> int:
    payload: dict[str, Any] = json.load(sys.stdin)
    repository_root = Path(payload["repositoryRoot"]).resolve()
    project_relative = payload["projectRoot"]
    project_root = (
        repository_root if project_relative == "." else repository_root / project_relative
    ).resolve()
    changed_paths = [normalize(Path(value)) for value in payload["changedPaths"]]

    files = sorted(
        path for path in project_root.rglob("*.py")
        if not any(part in {".git", ".venv", "venv", "__pycache__"} for part in path.parts)
    )
    module_to_file = {
        module_name(project_root, file_path): normalize(file_path.relative_to(project_root))
        for file_path in files
    }
    reverse: dict[str, set[str]] = {}
    diagnostics: list[str] = []

    for file_path in files:
        relative = normalize(file_path.relative_to(project_root))
        try:
            tree = ast.parse(file_path.read_text(encoding="utf-8"), filename=relative)
        except (OSError, SyntaxError) as error:
            if relative in changed_paths:
                diagnostics.append(f"unable to parse changed Python source {relative}: {error}")
            continue
        current_module = module_name(project_root, file_path)
        for imported, relative_import in imported_modules(tree, current_module):
            candidates = [imported]
            while "." in candidates[-1]:
                candidates.append(candidates[-1].rsplit(".", 1)[0])
            dependency = next((module_to_file[name] for name in candidates if name in module_to_file), None)
            if dependency is None:
                if relative_import and relative in changed_paths:
                    diagnostics.append(
                        f"unresolved relative import in {relative}: {imported}"
                    )
                continue
            reverse.setdefault(dependency, set()).add(relative)

    queue = list(changed_paths)
    visited = set(changed_paths)
    for changed in changed_paths:
        if changed.endswith(".py") and not (project_root / changed).is_file():
            diagnostics.append(f"changed Python source is unavailable: {changed}")
    while queue:
        current = queue.pop(0)
        for importer in reverse.get(current, set()):
            if importer not in visited:
                visited.add(importer)
                queue.append(importer)

    json.dump(
        {
            "testFiles": sorted(path_value for path_value in visited if is_test(path_value)),
            "diagnostics": sorted(set(diagnostics)),
        },
        sys.stdout,
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:  # Fail closed; the core converts this to full validation.
        json.dump({"testFiles": [], "diagnostics": [f"python adapter failed: {error}"]}, sys.stdout)
        raise SystemExit(0)
