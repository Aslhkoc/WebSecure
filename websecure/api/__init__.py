"""
websecure.api
~~~~~~~~~~~~~
REST API sunucusu — Adım 20.

Bileşenler
----------
server  : HTTP API sunucusu (stdlib http.server tabanlı)
auth    : API key kimlik doğrulama
routes  : REST endpoint tanımları

Hızlı Kullanım
--------------
```python
from websecure.api import APIServer, get_api_server

server = get_api_server(port=8080)
server.start()
# GET  /api/v1/scans
# POST /api/v1/scans
# GET  /api/v1/scans/{id}
# GET  /api/v1/findings?scan_id=...
# GET  /api/v1/score?target=...
# GET  /api/v1/health
```
"""
from websecure.api.server import APIServer, get_api_server

__all__ = [
    "APIServer",
    "get_api_server",
]
