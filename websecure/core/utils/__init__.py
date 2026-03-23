# Facade for backward compatibility
from .net import *
from .helpers import *
from .system import *
from .config import *
from .wordlists import *
# from .ports import *  # REMOVED: Legacy port scanner deleted.

# Legacy aliases if needed
import sys
import importlib
import importlib.util as _iul
from typing import Any, Optional

# Common helpers often imported
def _truthy(v): return bool(v)

def _ws_import_any(*names: str) -> Optional[Any]:
    """
    Belirtilen modül adlarını sırayla dener ve ilkini import eder.
    Sessizce başarısız olur ve None döner.
    """
    for n in names:
        if not isinstance(n, str) or not n.strip():
            continue
        try:
            if _iul.find_spec(n) is not None:
                return importlib.import_module(n)
        except Exception:
            continue
    return None

def _ws_maybe_import_any(*names: str) -> Optional[Any]:
    """
    _ws_import_any ile aynı işlevi görür (alias).
    """
    return _ws_import_any(*names)
