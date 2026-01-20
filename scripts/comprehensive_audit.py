
import os
import ast
import sys
import importlib.util
import re
from pathlib import Path
from collections import defaultdict

PROJECT_ROOT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(r"c:\Users\Acer\PycharmProjects\WebSecure")
IGNORE_DIRS = {".git", ".idea", "__pycache__", "build", "dist", ".gemini", "venv", "scripts"}
IGNORE_FILES = {"setup.py"}

report = {
    "syntax_errors": [],
    "import_errors": [],
    "unused_imports": [],
    "bare_excepts": [],
    "todos": [],
    "definitions": defaultdict(list),
    "usages": set(),
    "orphan_files": []
}

def is_ignored(path):
    parts = path.parts
    for part in parts:
        if part in IGNORE_DIRS:
            return True
    return False

def check_syntax(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
        tree = ast.parse(content, filename=file_path.name)
        return tree, content
    except SyntaxError as e:
        report["syntax_errors"].append(f"{file_path}: {e}")
        return None, None
    except Exception as e:
        report["syntax_errors"].append(f"{file_path}: Read error - {e}")
        return None, None

def check_imports(tree, file_path):
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            # Basic static check could go here, but complex to resolve paths perfectly without running
            pass
            
def find_bare_excepts(tree, file_path):
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            if node.type is None: # Bare except
                # Check if body is just pass or log
                if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
                     report["bare_excepts"].append(f"{file_path}:{node.lineno} - Bare except pass")

def find_todos(content, file_path):
    for i, line in enumerate(content.splitlines(), 1):
        if "TODO" in line or "FIXME" in line:
            report["todos"].append(f"{file_path}:{i} - {line.strip()}")

def collect_symbols(tree, file_path):
    # Collect defined classes and functions
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            report["definitions"][node.name].append(str(file_path))
            
    # Collect usages (simple text based for now to avoid complex scope analysis)
    # This is rough estimate
    pass

def scan_file(file_path):
    tree, content = check_syntax(file_path)
    if not tree:
        return

    find_bare_excepts(tree, file_path)
    find_todos(content, file_path)
    collect_symbols(tree, file_path)
    
    # regex for usages (very rough)
    tokens = set(re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', content))
    report["usages"].update(tokens)

def main():
    print(f"Scanning {PROJECT_ROOT}...")
    all_files = []
    
    for root, dirs, files in os.walk(PROJECT_ROOT):
        # Filter dirs in place
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        
        for file in files:
            if file.endswith(".py") and file not in IGNORE_FILES:
                full_path = Path(root) / file
                if not is_ignored(full_path):
                    all_files.append(full_path)

    for f in all_files:
        scan_file(f)

    # Analyze orphans (Defined but never used)
    # This is fuzzy because usage might be dynamic or in ignored files
    # Only report significant ones?
    
    params = ["syntax_errors", "bare_excepts"]
    for p in params:
        if report[p]:
            print(f"\n[{p.upper().replace('_', ' ')}]")
            for item in report[p]:
                print(f"  - {item}")
        else:
            print(f"\n[{p.upper().replace('_', ' ')}] - None found")

    print(f"\n[TOTAL FILES SCANNED]: {len(all_files)}")

if __name__ == "__main__":
    main()
