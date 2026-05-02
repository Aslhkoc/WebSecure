from pathlib import Path
from websecure.core.utils import load_config

def test_config_schema_validation():
    # config.json lives at the project root; resolve relative to this file's repo root
    root = Path(__file__).resolve().parent.parent.parent
    cfg = load_config(str(root / 'config.json'))
    assert isinstance(cfg, dict)
    assert 'offensive' in cfg and isinstance(cfg['offensive'], dict)
    assert 'enabled' in cfg['offensive']
