from pathlib import Path
from websecure.core.utils import load_config

def test_config_schema_validation():
    cfg = load_config(str(Path('websecure/config.json')))
    assert isinstance(cfg, dict)
    assert 'offensive' in cfg and isinstance(cfg['offensive'], dict)
    assert 'enabled' in cfg['offensive']
