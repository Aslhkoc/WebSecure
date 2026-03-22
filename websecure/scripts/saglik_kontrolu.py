import os
import json
import ast
import sys
from pathlib import Path

PROJECT_ROOT = Path("c:/Users/Acer/PycharmProjects/WebSecure/websecure")
OUTPUT_FILE = Path("c:/Users/Acer/PycharmProjects/WebSecure/output/saglik_raporu.txt")

def log(msg, mode="a"):
    with open(OUTPUT_FILE, mode, encoding="utf-8") as f:
        f.write(msg + "\n")

def check_config_paths():
    log("--- Config Path Check ---", mode="w")
    config_path = PROJECT_ROOT / "config.json"
    if not config_path.exists():
        log("CRITICAL: config.json not found!")
        return

    with open(config_path, "r", encoding="utf-8") as f:
        try:
            cfg = json.load(f)
        except json.JSONDecodeError as e:
            log(f"CRITICAL: config.json is invalid JSON: {e}")
            return

    def recursive_check(d):
        if isinstance(d, dict):
            for k, v in d.items():
                recursive_check(v)
        elif isinstance(d, list):
            for i in d:
                recursive_check(i)
        elif isinstance(d, str):
            if d.startswith("./") or (d.startswith("/") and not d.startswith("/")):
                rel_path = d.replace("./", "")
                full_path = PROJECT_ROOT.parent / rel_path
                full_path_2 = PROJECT_ROOT / rel_path
                if not full_path.exists() and not full_path_2.exists():
                    log(f"MISSING: {d}")

    recursive_check(cfg)

def get_all_python_files(root):
    return {str(p.resolve()) for p in root.rglob("*.py") if "venv" not in str(p) and "__pycache__" not in str(p)}

def get_imports_from_file(filepath):
    imports = set()
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=filepath)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.add(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imports.add(node.module)
    except Exception as e:
        log(f"Error parsing {filepath}: {e}")
    return imports

def check_orphans():
    log("\n--- Orphan File Check ---")
    all_files = get_all_python_files(PROJECT_ROOT)
    entry_point = str((PROJECT_ROOT / "main.py").resolve())
    
    # Also ignore scripts dir from orphan check as they are standalone
    scripts_dir = str((PROJECT_ROOT / "scripts").resolve())
    
    visit_queue = [entry_point]
    visited = set()
    
    while visit_queue:
        current = visit_queue.pop(0)
        if current in visited:
            continue
        visited.add(current)
        
        # Imports
        for imp in get_imports_from_file(current):
            # Try to map import to file
            parts = imp.split(".")
            
            # Common patterns relative to project root
            # websecure.x.y -> websecure/x/y.py
            # x.y -> websecure/x/y.py (implicit)
            
            candidates = []
            
            # Absolute project styles
            base = PROJECT_ROOT.parent
            candidates.append(base.joinpath(*parts).with_suffix(".py"))
            candidates.append(base.joinpath(*parts) / "__init__.py")
            
            # Local style
            candidates.append(PROJECT_ROOT.joinpath(*parts).with_suffix(".py"))
            candidates.append(PROJECT_ROOT.joinpath(*parts) / "__init__.py")

            for c in candidates:
                cstr = str(c.resolve())
                if cstr in all_files and cstr not in visited and cstr not in visit_queue:
                    visit_queue.append(cstr)

    orphans = []
    for f in all_files:
        if f not in visited:
            # Exclude specific files/dirs
            if scripts_dir in f: continue
            if "tests" in f: continue
            if "__init__.py" in f: continue
            if "setup.py" in f: continue
            orphans.append(f)
            
    for o in sorted(orphans):
        log(f"ORPHAN: {Path(o).name}  ({o})")

if __name__ == "__main__":
    check_config_paths()
    check_orphans()
