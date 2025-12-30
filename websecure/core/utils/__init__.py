# Facade for backward compatibility
from .net import *
from .text import *
from .system import *
from .config import *
from .cache import *

# Legacy aliases if needed
import sys

# Common helpers often imported
def _truthy(v): return bool(v)
