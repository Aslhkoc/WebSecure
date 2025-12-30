"""
WebSecure Analysis Framework
"""
__version__ = "1.0.0"

# Expose core components for easy access
from .core.utils import setup_logging
from .scanners.base import BaseScanner

__all__ = ["setup_logging", "BaseScanner", "__version__"]
