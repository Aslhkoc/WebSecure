def render(report: dict) -> str:
    return '# WebSecure Rapor\n\n```json\n' + __import__('json').dumps(report, ensure_ascii=False, indent=2) + '\n```\n'
