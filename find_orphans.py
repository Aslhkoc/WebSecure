
import os
import re
import sys

PROJECT_ROOT = r"c:\Users\Acer\PycharmProjects\WebSecure\websecure"

def get_all_py_files(root):
    files = []
    for r, d, f in os.walk(root):
        if "venv" in r or "__pycache__" in r:
            continue
        for file in f:
            if file.endswith(".py"):
                files.append(os.path.join(r, file))
    return files

def get_module_name(path, root):
    rel = os.path.relpath(path, os.path.dirname(root)) # websecure/...
    name = rel.replace("\\", ".").replace("/", ".").replace(".py", "")
    if name.endswith(".__init__"):
        name = name[:-9]
    return name

def parse_imports(file_path):
    imports = set()
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Regex for imports (simple heuristic)
        # from websecure.core import X
        # import websecure.scanners.sqli
        
        # 1. from X import Y
        from_matches = re.findall(r'from\s+([a-zA-Z0-9_.]+)\s+import', content)
        imports.update(from_matches)
        
        # 2. import X
        import_matches = re.findall(r'^\s*import\s+([a-zA-Z0-9_.]+)', content, re.MULTILINE)
        imports.update(import_matches)
        
    except Exception:
        pass
    return imports

def main():
    print("Building Dependency Graph...")
    all_files = get_all_py_files(PROJECT_ROOT)
    
    file_map = {} # module_name -> file_path
    for f in all_files:
        mod = get_module_name(f, PROJECT_ROOT)
        file_map[mod] = f
        
    # Roots
    roots = ["websecure.main", "websecure.cfg", "websecure.setup"]
    # Mark files that are implicitly used (like plugins loaded dynamically if any)
    # Ideally scan content for string imports but difficult.
    
    visited = set()
    
    # BFS
    queue = []
    
    # Add roots to queue if exist
    for r in roots:
        if r in file_map:
            queue.append(r)
            visited.add(r)
        # Check for websecure.scanners.* as they might be dynamically loaded by main?
        # If main imports them, they are covered. If main does implicit import, we miss them.
        # But main.py lines 60-90 check explicit imports usually.
        
    # Also add ALL tests as roots
    for mod in file_map:
        if "tests" in mod:
            queue.append(mod)
            visited.add(mod)

    while queue:
        current = queue.pop(0)
        path = file_map.get(current)
        if not path:
            continue
            
        imports = parse_imports(path)
        for imp in imports:
            # Resolve relative imports? heuristic: match known modules
            # Check direct match
            if imp in file_map and imp not in visited:
                visited.add(imp)
                queue.append(imp)
            # Check prefix match (import websecure.core -> visits websecure.core.* ?)
            # Actually weak.
            # python imports are exact usually.
            
            # Helper: if import is "websecure.core.utils", we marked it.
            
    # Find Orphans
    orphans = []
    for mod, path in file_map.items():
        if mod not in visited:
            # Filter init
            if mod.endswith("__init__"): continue
            orphans.append(mod)

    print(f"\nAnalyzed {len(file_map)} modules.")
    print(f"Reachable: {len(visited)}")
    print(f"Potential Orphans: {len(orphans)}")
    
    for o in orphans:
        print(f"  ? {o}")

if __name__ == "__main__":
    main()
