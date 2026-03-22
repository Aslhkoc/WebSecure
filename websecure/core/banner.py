
import random
import sys
import platform

VERSION = "2.0.4-dev"
CODENAME = "GhostProtocol"

BANNERS = [
    r"""
      ██████  ███████ ███    ██ ███████ ███████ ██████  ██      ██████  ██ ████████ 
     ██  ████ ██      ████   ██ ██      ██      ██   ██ ██     ██    ██ ██    ██    
     ██   ███ █████   ██ ██  ██ ███████ █████   ██████  ██     ██    ██ ██    ██    
     ██  ████ ██      ██  ██ ██      ██ ██      ██      ██     ██    ██ ██    ██    
      ██████  ███████ ██   ████ ███████ ███████ ██      ██████  ██████  ██    ██    
                                                                                    
                        [ SYSTEM: COMPROMISED ]
                 [ TARGET: ACQUIRED | VECTOR: LETHAL ]
    """
]

def print_banner(modules_count=0):
    print(random.choice(BANNERS))
    print(f"       =[ WebSecure v{VERSION} [{CODENAME}]")
    print(f"       =[ Modules: {modules_count} loaded")
    print(f"       =[ OS: {platform.system()} {platform.release()}")
    # print("       =[ Team: Antigravity | Mode: AGGRESSIVE-ADAPTIVE") # Optional: Remove or keep
    print("")

# print_msf_console_look removed per user request

