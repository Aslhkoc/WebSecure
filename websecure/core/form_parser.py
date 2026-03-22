from __future__ import annotations
import re
from urllib.parse import urljoin
from typing import List, Dict, Any, Optional

# [WS3] Integration of AdvancedFormFuzzer logic
def extract_all_forms(html_content: str, base_url: str) -> List[Dict[str, Any]]:
    """
    Extracts all forms and dynamic inputs using robust regex logic.
    Integrates user's AdvancedFormFuzzer logic (script extraction).
    """
    forms = []
    
    # 1. Standard HTML Forms
    # <form ...> ... </form>
    # Using regex as requested (BeautifulSoup optional but regex handles broken HTML well for fuzzing)
    form_tags = re.finditer(r"<form(.*?)>(.*?)</form>", html_content, re.IGNORECASE | re.DOTALL)
    
    for match in form_tags:
        attrs_str = match.group(1)
        inner_html = match.group(2)
        
        # Extract action
        action_match = re.search(r'action=["\']([^"\']+)["\']', attrs_str, re.IGNORECASE)
        raw_action = action_match.group(1) if action_match else ""
        action = urljoin(base_url, raw_action)
        
        # Extract method
        method_match = re.search(r'method=["\']([^"\']+)["\']', attrs_str, re.IGNORECASE)
        method = (method_match.group(1) if method_match else "GET").upper()
        
        # Extract inputs
        inputs = []
        # <input ...>
        for im in re.finditer(r"<input(.*?)>", inner_html, re.IGNORECASE):
            i_attrs = im.group(1)
            name_m = re.search(r'name=["\']([^"\']+)["\']', i_attrs, re.IGNORECASE)
            type_m = re.search(r'type=["\']([^"\']+)["\']', i_attrs, re.IGNORECASE)
            val_m = re.search(r'value=["\']([^"\']+)["\']', i_attrs, re.IGNORECASE)
            
            if name_m:
                inputs.append({
                    "name": name_m.group(1),
                    "type": (type_m.group(1) if type_m else "text").lower(),
                    "value": val_m.group(1) if val_m else ""
                })
        
        # <textarea ...>
        for tm in re.finditer(r"<textarea(.*?)name=[\"']([^\"']+)[\"']", inner_html, re.IGNORECASE):
            inputs.append({"name": tm.group(2), "type": "textarea"})
            
        # <select ...>
        for sm in re.finditer(r"<select(.*?)name=[\"']([^\"']+)[\"']", inner_html, re.IGNORECASE):
            inputs.append({"name": sm.group(2), "type": "select"})

        if inputs:
            forms.append({
                "action": action,
                "method": method,
                "inputs": inputs
            })

    # 2. Dynamic/Script Inputs (User's Logic)
    # Javascript patterns often reveal hidden API params or client-side logic inputs
    scripts = re.findall(r"<script[^>]*>(.*?)</script>", html_content, re.DOTALL | re.IGNORECASE)
    for script_content in scripts:
        if not script_content: continue
        
        # Common patterns: name="foo", data: { foo: bar }
        # The user's specific regex: name=["']([^"']+)["']
        patterns = re.findall(r'name=["\']([^"\']+)["\']', script_content)
        
        # Also look for simplified JSON keys? Maybe too noisy. Stick to user request.
        
        known_names = set()
        for f in forms:
            for i in f["inputs"]:
                known_names.add(i["name"])
        
        new_inputs = []
        for p in patterns:
            # Filter out common false positives (meta tags, charset, etc usually not in script but be careful)
            if p not in known_names and len(p) < 30 and " " not in p:
                new_inputs.append({"name": p, "type": "text", "value": "1"})
        
        if new_inputs:
            # Group these into a "virtual" form targeting base_url
            forms.append({
                "action": base_url, # Assume current page
                "method": "GET", # Assume GET or generic probe
                "inputs": new_inputs,
                "is_virtual": True
            })

    return forms
