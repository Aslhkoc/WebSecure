def render(report: dict) -> str:
    return '<html><body><pre>' + __import__('json').dumps(report, ensure_ascii=False, indent=2) + '</pre></body></html>'
