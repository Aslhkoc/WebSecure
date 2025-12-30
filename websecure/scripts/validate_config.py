#!/usr/bin/env python3
import sys, json
from pathlib import Path

def die(msg: str, code: int=1) -> None:
    sys.stderr.write(msg + "\n")
    sys.exit(code)

def main() -> None:
    args = sys.argv[1:]
    if "-c" in args:
        ci = args.index("-c"); cfg_path = Path(args[ci+1])
    elif "--config" in args:
        ci = args.index("--config"); cfg_path = Path(args[ci+1])
    else:
        die("usage: validate_config.py -c <config.json> -s <config.schema.json> [--strict] [--prune]")
    if "-s" in args:
        si = args.index("-s"); sch_path = Path(args[si+1])
    elif "--schema" in args:
        si = args.index("--schema"); sch_path = Path(args[si+1])
    else:
        die("usage: validate_config.py -c <config.json> -s <config.schema.json> [--strict] [--prune]")

    strict = "--strict" in args
    prune = "--prune" in args

    cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    schema = json.loads(sch_path.read_text(encoding="utf-8"))

    try:
        import jsonschema
    except Exception as e:
        die("jsonschema not installed (pip install jsonschema): %s" % (e,))

    # validate
    jsonschema.validate(instance=cfg, schema=schema)

    # optional prune (best-effort: only top-level and first-level objects)
    if prune:
        def prune_obj(obj, sch):
            if not isinstance(obj, dict) or not isinstance(sch, dict):
                return obj
            props = sch.get("properties", {})
            keep = set(props.keys())
            cleaned = {}
            for k,v in obj.items():
                if k in keep:
                    cleaned[k] = prune_obj(v, props.get(k, {}))
            return cleaned
        cfg = prune_obj(cfg, schema)
        cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))

    print("OK: %s validates against %s%s%s" % (
        cfg_path, sch_path,
        " [strict]" if strict else "",
        " [pruned]" if prune else "",
    ))

if __name__ == "__main__":
    main()
