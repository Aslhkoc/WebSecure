from typing import Any, Dict, List, Optional
import ssl
import json
import time
import logging
import threading

logger = logging.getLogger(__name__)

# Try to import websocket client
try:
    import websocket
except ImportError:
    websocket = None

def run(url: str, session=None, debug: bool = False, auth_ctx=None) -> List[Dict[str, Any]]:
    """
    Fuzzes WebSocket endpoints if the URL is ws:// or wss://, or upgrades http/https to ws/wss.
    """
    results = []
    
    if not websocket:
        if debug:
            logger.warning("websocket-client not installed. Skipping WS fuzz.")
        return []

    # Convert HTTP URL to WS URL if needed
    target_ws = url
    if url.startswith("http://"):
        target_ws = url.replace("http://", "ws://")
    elif url.startswith("https://"):
        target_ws = url.replace("https://", "wss://")
        
    if not (target_ws.startswith("ws://") or target_ws.startswith("wss://")):
        return []

    # Detect if endpoint actually speaks WS
    if not _is_websocket_alive(target_ws):
        return []

    # Fuzzing Phases
    fuzz_payloads = [
        # Large payload (Buffer Overflow check)
        ("A" * 5000, "Buffer Overflow Probe"),
        # JSON Injection
        ('{"type": "admin", "cmd": "shutdown"}', "JSON Injection Probe"),
        # SQLi
        ("' OR '1'='1", "WS SQLi Probe"),
        # XSS
        ("<script>alert(1)</script>", "WS XSS Probe"),
        # Bad Control Frames (Client lib handles framing, but we send payload data)
        (b'\xFF\xFF\xFF\xFF', "Binary Garbage"),
    ]

    for payload, name in fuzz_payloads:
        try:
            error = _send_ws_message(target_ws, payload)
            if error:
                # If sending caused a crash or weird error
                results.append({
                    "type": "ws_fuzz",
                    "severity": "low",
                    "url": target_ws,
                    "method": "WS",
                    "message": f"WebSocket Anomaly: {name}",
                    "details": f"Error or disconnect observed after sending payload: {error}"
                })
        except Exception as e:
            pass

    return results

def _is_websocket_alive(url: str) -> bool:
    try:
        ws = websocket.create_connection(url, timeout=3, suppress_origin=True)
        ws.close()
        return True
    except Exception:
        return False

def _send_ws_message(url: str, payload) -> Optional[str]:
    ws = None
    try:
        ws = websocket.create_connection(url, timeout=3, suppress_origin=True)
        if isinstance(payload, str):
            ws.send(payload)
        else:
            ws.send_binary(payload)
        
        # Wait a bit for response or close
        ws.settimeout(2)
        try:
            resp = ws.recv()
        except websocket.WebSocketTimeoutException:
            pass # No reply is fine
            
        ws.close()
        return None
    except Exception as e:
        return str(e)
    finally:
        if ws:
            try:
                ws.close()
            except:
                pass
