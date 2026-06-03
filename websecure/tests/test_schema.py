import json
from pathlib import Path

import pytest

from websecure.core.utils import load_config


def _root() -> Path:
    # config.json + config.schema.json live at the project root.
    return Path(__file__).resolve().parent.parent.parent


def test_config_loads_with_required_sections():
    cfg = load_config(str(_root() / "config.json"))
    assert isinstance(cfg, dict)
    assert "offensive" in cfg and isinstance(cfg["offensive"], dict)
    assert "enabled" in cfg["offensive"]


def test_config_conforms_to_schema():
    """config.json must validate against config.schema.json (real JSON-Schema check)."""
    jsonschema = pytest.importorskip("jsonschema")
    root = _root()
    schema = json.loads((root / "config.schema.json").read_text(encoding="utf-8"))
    cfg = json.loads((root / "config.json").read_text(encoding="utf-8"))
    # Raises jsonschema.ValidationError on mismatch — fails the test loudly.
    jsonschema.validate(instance=cfg, schema=schema)
