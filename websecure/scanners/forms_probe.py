
from __future__ import annotations
import logging, re
from typing import Dict, Any, List, Tuple, Optional
from urllib.parse import urlparse
from importlib.util import find_spec as _find_spec

def _looks_interesting(u: str) -> bool:
    p = (urlparse(u).path or '').lower()
    if any(x in p for x in ('login','signin','register','signup','account','comment','review','feedback','contact','search','sorgu','arama')):
        return True
    return bool(re.search(r'[?&](q|query|search|s)=', u, re.I))

def run(ctx, *, limit_per_host: int = 30, debug: bool = False) -> int:
    try:
        from websecure.core.detect import detect_get_parameters_and_forms
        from websecure.core.injection import run_injection_checks
        from websecure.core.reporting import add_result
    except Exception as e:
        logging.error(f"[forms_probe] imports failed: {e}")
        return 0

    sess = getattr(ctx, 'session', None)
    results = getattr(ctx, 'results', {})
    driver = getattr(ctx, 'driver', None)
    endpoints = list((results or {}).get('endpoints') or [])
    if not endpoints:
        return 0

    target_urls = [u for u in endpoints if _looks_interesting(u)]
    target_urls = target_urls[:limit_per_host]

    attempts = 0
    detected_forms: List[Dict[str, Any]] = results.setdefault('detected_forms', [])

    def _fetch(url: str) -> str:
        try:
            r = sess.get(url, timeout=10)
            return r.text or ''
        except Exception:
            return ''

    for url in target_urls:
        try:
            nurl, get_keys, forms = detect_get_parameters_and_forms(url, driver=None, debug=debug, fetcher=_fetch)
            seen = {(f.get('action_abs'), f.get('method')) for f in detected_forms}
            for f in forms:
                key = (f.get('action_abs'), f.get('method'))
                if key not in seen:
                    detected_forms.append(f)
                    seen.add(key)

            prev = set(results.get('detected_get_params') or [])
            results['detected_get_params'] = list(prev.union(set(get_keys or [])))

            run_injection_checks(nurl, nurl, results, sess, driver=None, form_data=None, debug=debug)
            attempts += 1

            for fm in forms[:3]:
                data = {}
                for inp in (fm.get('inputs') or []):
                    n = inp.get('name')
                    t = (inp.get('type') or 'text').lower()
                    if not n or t in ('button','submit','reset','image'):
                        continue
                    if 'pass' in n.lower():
                        data[n] = 'P@ssw0rd!123'
                    elif 'mail' in n.lower() or 'email' in n.lower():
                        data[n] = 'tester@example.com'
                    elif 'user' in n.lower() or 'name' in n.lower():
                        data[n] = 'tester'
                    else:
                        data[n] = '1'
                if data:
                    run_injection_checks(nurl, nurl, results, sess, driver=None, form_data=data, debug=debug)
                    attempts += 1

        except Exception as e:
            add_result('errors', {'stage':'forms_probe', 'url': url, 'error': str(e)})
            continue

    add_result('forms_probe', {'attempts': attempts, 'targets': len(target_urls), 'forms_detected': len(detected_forms)})
    return attempts
