import json
import os
import sys

def get_input(prompt, default=None):
    """Safe input wrapper with default value."""
    p_text = f"{prompt}"
    if default:
        p_text += f" [{default}]"
    p_text += ": "
    
    try:
        val = input(p_text).strip()
    except KeyboardInterrupt:
        print("\n[!] Wizard cancelled.")
        sys.exit(0)
        
    if not val:
        return default
    return val

def run_wizard():
    print("\n" + "="*50)
    print("   WebSecure Configuration Wizard 🧙‍♂️")
    print("="*50 + "\n")
    print("This wizard will help you create a 'config.json' file for your scan.\n")

    # 1. Target
    target = ""
    while not target:
        target = get_input("1. Target URL (e.g. https://example.com)")
        if not target:
            print("   [!] Target URL is required.")
    
    # Auto-fix scheme
    if "://" not in target:
        target = "https://" + target
        
    # 2. Scan Profile
    print("\n2. Scan Profile:")
    print("   (a) Normal     : Balanced speed and coverage [Default]")
    print("   (b) Aggressive : Fast, noisy, full coverage")
    print("   (c) Smart      : Healthy, full coverage, WAF evasive + Tor")
    print("   (d) Stealth    : Minimal noise")
    print("   (e) Deep       : Maximum scrutiny (Slow)")
    
    profile_choice = get_input("   Select profile (a/b/c/d/e)", "a").lower()
    profile_map = {"a": "normal", "b": "aggressive", "c": "smart", "d": "stealth", "e": "deep"}
    profile = profile_map.get(profile_choice, "normal")

    # 3. Authentication
    print("\n3. Authentication:")
    print("   (n) No Auth [Default]")
    print("   (l) Login Form (Auto-login)")
    print("   (h) Header / Token (e.g. Bearer)")
    
    auth_choice = get_input("   Select auth type (n/l/h)", "n").lower()
    
    auth_config = {}
    if auth_choice == "l":
        login_url = get_input("   Login Page URL (leave empty if same as target)", target)
        username = get_input("   Username")
        password = get_input("   Password")
        auth_config = {
            "enabled": True,
            "type": "auto_login",
            "login_url": login_url,
            "username": username,
            "password": password
        }
    elif auth_choice == "h":
        header_name = get_input("   Header Name", "Authorization")
        header_val = get_input("   Header Value (e.g. Bearer ...)")
        auth_config = {
            "enabled": True,
            "type": "header",
            "headers": {header_name: header_val}
        }
    else:
        auth_config = {"enabled": False}

    # 4. Modules
    print("\n4. Modules:")
    print("   By default, all relevant modules for the profile will run.")
    custom_modules = get_input("   Do you want to customize modules (enable/disable)? (y/N)", "n").lower()
    
    selected_modules = []
    if custom_modules == "y":
        all_mods = ["sqli", "xss", "nosqli", "ssrf", "graphql", "files", "cve"]
        print(f"   Available: {', '.join(all_mods)}")
        mods_in = get_input("   Enter modules to ENABLE (comma separated, e.g. sqli,xss)")
        if mods_in:
            selected_modules = [m.strip() for m in mods_in.split(",") if m.strip()]
            
    # 5. Output
    print("\n5. Reporting:")
    report_html = get_input("   Generate HTML Dashboard? (Y/n)", "y").lower() == "y"
    
    # --- Generate Config ---
    config = {
        "target": target,
        "settings": {
            "scan_profile": profile,
            "logging": {"level": "INFO"}
        },
        "authentication": auth_config,
        "reporting": {
            "formats": ["json", "md", "html"] if report_html else ["json", "md"],
            "output_dir": "output"
        }
    }
    
    # Allow-list modules if selected
    if selected_modules:
        # Dictionary format for new structure
        # (Assuming main.py respects a top-level or structured 'modules' config)
        # For compatibility with current structure, we might need to enable/disable keys.
        # But 'profile' usually controls this. We'll simply note it in settings/modules overrides
        # Or better, just set the keys at root if that's how config works.
        # Based on previous file reads, config structure is flat for modules often.
        pass

    # Save
    out_file = "config.json"
    if os.path.exists(out_file):
        ow = get_input(f"\n[!] '{out_file}' already exists. Overwrite? (y/N)", "n").lower()
        if ow != "y":
            print("[*] Skipped saving configuration.")
            return

    try:
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=4)
        print(f"\n[+] Configuration saved to '{os.path.abspath(out_file)}'")
        print("[+] You can now run the scan using: python main.py")
        
        run_now = get_input("\n🚀 Do you want to start the scan NOW? (y/N)", "n").lower()
        if run_now == "y":
            # Re-exec main.py with this config is complex inside python. 
            # Better to return True to main, or just os.system (simple but risky).
            # Returning boolean to main.py is cleanest if main calls this.
            return True
            
    except Exception as e:
        print(f"\n[!] Error saving config: {e}")

    return False
