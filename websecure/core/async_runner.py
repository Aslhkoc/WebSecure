"""
websecure.core.async_runner
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Tam async I/O tarama motoru — asyncio + aiohttp tabanlı.

Özellikler
----------
* asyncio event loop ile eşzamanlı HTTP istekleri
* aiohttp oturumu — connection pooling, timeout, retry
* Semaphore ile concurrency kontrolü (max_concurrent)
* AsyncScanTask — tek tarama birimi (URL + payload)
* AsyncScanRunner — birden fazla görevi paralel koştur
* Sonuçları async generator olarak yield et
* aiohttp yoksa threading fallback (stdlib uyumu)

SOLID
-----
- SRP  : AsyncScanTask sadece tek görevi; AsyncScanRunner orkestre eder.
- OCP  : Yeni tarama stratejisi eklenmek için Runner subclass edilir.
- DIP  : Runner, HTTP adapter soyutlamasına bağlı.
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# aiohttp varlık kontrolü
# ---------------------------------------------------------------------------

try:
    import aiohttp
    _HAS_AIOHTTP = True
except ImportError:
    _HAS_AIOHTTP = False
    logger.debug("[AsyncRunner] aiohttp bulunamadı — threading fallback kullanılacak.")

# ---------------------------------------------------------------------------
# AsyncScanTask — tek tarama görevi
# ---------------------------------------------------------------------------

@dataclass
class AsyncScanTask:
    """Tek bir async tarama görevi."""
    url: str
    method: str = "GET"
    payload: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    timeout_s: float = 10.0
    tag: str = ""                      # Görev etiketi (hangi scanner/test)
    meta: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AsyncScanResult:
    """Tek görev sonucu."""
    task: AsyncScanTask
    status_code: int = 0
    body: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    elapsed_ms: float = 0.0
    error: Optional[str] = None
    findings: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.error is None and 100 <= self.status_code < 600

    @property
    def is_error(self) -> bool:
        return self.error is not None


# ---------------------------------------------------------------------------
# HTTP Adapter — aiohttp veya fallback
# ---------------------------------------------------------------------------

class _AiohttpAdapter:
    """aiohttp tabanlı async HTTP adapter."""

    def __init__(
        self,
        timeout_s: float = 10.0,
        max_connections: int = 100,
        verify_ssl: bool = False,
        proxy: Optional[str] = None,
    ) -> None:
        self._timeout = aiohttp.ClientTimeout(total=timeout_s)
        self._connector = aiohttp.TCPConnector(
            limit=max_connections,
            ssl=False if not verify_ssl else None,
        )
        self._proxy = proxy
        self._session: Optional[aiohttp.ClientSession] = None

    async def start(self) -> None:
        self._session = aiohttp.ClientSession(
            connector=self._connector,
            timeout=self._timeout,
            headers={"User-Agent": "websecure/20.0"},
        )

    async def stop(self) -> None:
        if self._session:
            await self._session.close()
            self._session = None

    async def request(self, task: AsyncScanTask) -> AsyncScanResult:
        if not self._session:
            await self.start()

        t0 = time.monotonic()
        try:
            kwargs: Dict[str, Any] = {
                "url": task.url,
                "headers": task.headers,
                "allow_redirects": True,
            }
            if task.payload:
                kwargs["data"] = task.payload
            if self._proxy:
                kwargs["proxy"] = self._proxy

            timeout = aiohttp.ClientTimeout(total=task.timeout_s)
            async with self._session.request(  # type: ignore[union-attr]
                task.method, timeout=timeout, **kwargs
            ) as resp:
                body = await resp.text(errors="replace")
                elapsed = (time.monotonic() - t0) * 1000
                return AsyncScanResult(
                    task=task,
                    status_code=resp.status,
                    body=body,
                    headers=dict(resp.headers),
                    elapsed_ms=round(elapsed, 2),
                )
        except asyncio.TimeoutError:
            return AsyncScanResult(task=task, error="timeout")
        except Exception as exc:
            return AsyncScanResult(task=task, error=str(exc))


class _ThreadingFallbackAdapter:
    """
    aiohttp yokken stdlib urllib tabanlı senkron adapter.
    asyncio.get_event_loop().run_in_executor ile async gibi çalıştırılır.
    """

    def __init__(
        self,
        timeout_s: float = 10.0,
        proxy: Optional[str] = None,
        verify_ssl: bool = False,
    ) -> None:
        self._timeout = timeout_s
        self._proxy = proxy
        self._verify_ssl = verify_ssl

    async def start(self) -> None:
        pass  # setup gerekmez

    async def stop(self) -> None:
        pass

    async def request(self, task: AsyncScanTask) -> AsyncScanResult:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._sync_request, task)

    def _sync_request(self, task: AsyncScanTask) -> AsyncScanResult:
        import urllib.request
        import urllib.error
        t0 = time.monotonic()
        try:
            req = urllib.request.Request(
                task.url,
                data=task.payload.encode() if task.payload else None,
                headers={**task.headers, "User-Agent": "websecure/20.0"},
                method=task.method,
            )
            handlers = []
            if self._proxy:
                handlers.append(urllib.request.ProxyHandler({"http": self._proxy, "https": self._proxy}))
            if not self._verify_ssl:
                import ssl
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                handlers.append(urllib.request.HTTPSHandler(context=ctx))
            opener = urllib.request.build_opener(*handlers)
            with opener.open(req, timeout=self._timeout) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                elapsed = (time.monotonic() - t0) * 1000
                return AsyncScanResult(
                    task=task,
                    status_code=resp.status,
                    body=body,
                    headers=dict(resp.headers),
                    elapsed_ms=round(elapsed, 2),
                )
        except Exception as exc:
            return AsyncScanResult(task=task, error=str(exc))


# ---------------------------------------------------------------------------
# AsyncScanRunner
# ---------------------------------------------------------------------------

class AsyncScanRunner:
    """
    Birden fazla AsyncScanTask'ı paralel koşturan motor.

    Kullanım
    --------
    ```python
    runner = AsyncScanRunner(max_concurrent=50)

    tasks = [
        AsyncScanTask(url="https://example.com/login", payload="' OR 1=1--"),
        AsyncScanTask(url="https://example.com/search", payload="<script>alert(1)</script>"),
    ]

    results = asyncio.run(runner.run_all(tasks))
    for result in results:
        if result.ok:
            print(result.status_code, result.elapsed_ms)
    ```
    """

    def __init__(
        self,
        max_concurrent: int = 50,
        timeout_s: float = 10.0,
        proxy: Optional[str] = None,
        verify_ssl: bool = False,
        analyzer: Optional[Callable[[AsyncScanResult], List[Dict[str, Any]]]] = None,
    ) -> None:
        """
        Parametreler
        ------------
        max_concurrent : Aynı anda kaç istek gönderilsin
        timeout_s      : Her istek için timeout
        proxy          : HTTP proxy URL (opsiyonel)
        verify_ssl     : SSL doğrulama (varsayılan False)
        analyzer       : Her sonucu analiz eden callback (bulguları çıkarır)
        """
        self._max_concurrent = max_concurrent
        self._timeout_s = timeout_s
        self._proxy = proxy
        self._verify_ssl = verify_ssl
        self._analyzer = analyzer
        self._adapter: Optional[Any] = None
        self._semaphore: Optional[asyncio.Semaphore] = None

    def _make_adapter(self) -> Any:
        if _HAS_AIOHTTP:
            return _AiohttpAdapter(
                timeout_s=self._timeout_s,
                max_connections=self._max_concurrent * 2,
                verify_ssl=self._verify_ssl,
                proxy=self._proxy,
            )
        return _ThreadingFallbackAdapter(
            timeout_s=self._timeout_s,
            proxy=self._proxy,
            verify_ssl=self._verify_ssl,
        )

    async def _run_task(
        self,
        task: AsyncScanTask,
        sem: asyncio.Semaphore,
    ) -> AsyncScanResult:
        async with sem:
            result = await self._adapter.request(task)
            if self._analyzer and result.ok:
                try:
                    result.findings = self._analyzer(result) or []
                except Exception as exc:
                    logger.debug(f"[AsyncRunner] Analiz hatası {task.url}: {exc}")
            return result

    async def run_all(
        self,
        tasks: List[AsyncScanTask],
    ) -> List[AsyncScanResult]:
        """Tüm görevleri çalıştır, sonuçları döndür."""
        if not tasks:
            return []

        self._adapter = self._make_adapter()
        await self._adapter.start()
        sem = asyncio.Semaphore(self._max_concurrent)

        try:
            coros = [self._run_task(t, sem) for t in tasks]
            results = await asyncio.gather(*coros, return_exceptions=False)
            return list(results)
        finally:
            await self._adapter.stop()

    async def run_stream(
        self,
        tasks: List[AsyncScanTask],
    ) -> AsyncIterator[AsyncScanResult]:
        """
        Görevleri çalıştır, biter bitmez yield et.

        ```python
        async for result in runner.run_stream(tasks):
            print(result.status_code, result.url)
        ```
        """
        if not tasks:
            return

        self._adapter = self._make_adapter()
        await self._adapter.start()
        sem = asyncio.Semaphore(self._max_concurrent)

        queue: asyncio.Queue[Optional[AsyncScanResult]] = asyncio.Queue()

        async def worker(task: AsyncScanTask) -> None:
            result = await self._run_task(task, sem)
            await queue.put(result)

        pending = len(tasks)
        workers = [asyncio.create_task(worker(t)) for t in tasks]

        try:
            while pending > 0:
                result = await queue.get()
                pending -= 1
                yield result
        finally:
            for w in workers:
                w.cancel()
            await self._adapter.stop()

    def run_sync(self, tasks: List[AsyncScanTask]) -> List[AsyncScanResult]:
        """
        Senkron wrapper — mevcut kod ile uyumluluk için.

        ```python
        results = runner.run_sync(tasks)
        ```
        """
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # Zaten bir event loop varsa yeni thread'de çalıştır
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                    future = executor.submit(asyncio.run, self.run_all(tasks))
                    return future.result()
            else:
                return loop.run_until_complete(self.run_all(tasks))
        except RuntimeError:
            return asyncio.run(self.run_all(tasks))

    # ------------------------------------------------------------------
    # Kolaylık metodları
    # ------------------------------------------------------------------

    @staticmethod
    def make_tasks(
        urls: List[str],
        method: str = "GET",
        payloads: Optional[List[str]] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout_s: float = 10.0,
    ) -> List[AsyncScanTask]:
        """
        URL listesi + opsiyonel payload'lardan task listesi üret.

        Payload varsa: her URL × her payload kombinasyonu.
        Payload yoksa: her URL için tek GET görevi.
        """
        tasks = []
        hdrs = headers or {}
        if payloads:
            for url in urls:
                for payload in payloads:
                    tasks.append(AsyncScanTask(
                        url=url,
                        method=method,
                        payload=payload,
                        headers=hdrs,
                        timeout_s=timeout_s,
                    ))
        else:
            for url in urls:
                tasks.append(AsyncScanTask(
                    url=url,
                    method=method,
                    headers=hdrs,
                    timeout_s=timeout_s,
                ))
        return tasks

    def stats(self, results: List[AsyncScanResult]) -> Dict[str, Any]:
        """Sonuç istatistikleri."""
        total = len(results)
        if not total:
            return {"total": 0}
        success = [r for r in results if r.ok]
        errors = [r for r in results if r.is_error]
        findings = sum(len(r.findings) for r in results)
        elapsed = [r.elapsed_ms for r in success]
        return {
            "total": total,
            "success": len(success),
            "errors": len(errors),
            "findings": findings,
            "avg_ms": round(sum(elapsed) / len(elapsed), 2) if elapsed else 0,
            "max_ms": round(max(elapsed), 2) if elapsed else 0,
            "min_ms": round(min(elapsed), 2) if elapsed else 0,
            "has_aiohttp": _HAS_AIOHTTP,
        }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "AsyncScanTask",
    "AsyncScanResult",
    "AsyncScanRunner",
]
