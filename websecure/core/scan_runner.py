"""
websecure.core.scan_runner
~~~~~~~~~~~~~~~~~~~~~~~~~~~
Scanner orchestration yardımcıları.
`_call_scanner_if_available()` ve `_bind_offensive()` main.py'den taşındı.

FAZ 4.2: main.py'den ayrıştırıldı.
FAZ 16 : checkpoint + ETA entegrasyonu eklendi.

Geriye dönük uyumluluk: main.py bu modülden import edip re-export eder.
"""
from __future__ import annotations

import importlib
import importlib.util
import inspect
import logging
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Checkpoint & ETA — lazy import (isteğe bağlı bağımlılıklar)
# ---------------------------------------------------------------------------

def _import_checkpoint():
    """checkpoint modülünü lazy olarak import eder."""
    try:
        from websecure.core.checkpoint import (
            make_checkpoint,
            CheckpointHook,
            get_manager,
        )
        return make_checkpoint, CheckpointHook, get_manager
    except ImportError as exc:
        logger.debug(f"[scan_runner] checkpoint modülü yüklenemedi: {exc!r}")
        return None, None, None


def _import_eta():
    """ETACalculator'ı lazy olarak import eder."""
    try:
        from websecure.core.concurrency import ETACalculator
        return ETACalculator
    except ImportError as exc:
        logger.debug(f"[scan_runner] ETACalculator yüklenemedi: {exc!r}")
        return None


# ---------------------------------------------------------------------------
# Modül keşif yardımcısı
# ---------------------------------------------------------------------------

def _spec_exists(name: str):
    """Modülün import edilebilir olup olmadığını kontrol eder (None veya ModuleSpec döner)."""
    try:
        return importlib.util.find_spec(name)
    except (ImportError, ModuleNotFoundError, AttributeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Scanner çağırma
# ---------------------------------------------------------------------------

def _call_scanner_if_available(
    mod_name: str,
    url: str,
    session=None,
    debug: bool = False,
    auth_ctx=None,
) -> Any:
    """
    Bir scanner modülünü dinamik olarak yükler ve `run()` fonksiyonunu çağırır.
    Modül bulunamazsa `None` döner — hata fırlatmaz.

    Parametre keşfi: `inspect.signature` ile `run()` imzasına bakılır;
    sadece desteklenen parametreler iletilir.

    FAZ 4.2: main.py:906'dan taşındı.
    """
    spec = _spec_exists(mod_name)
    mod = None

    if spec is not None:
        try:
            mod = importlib.import_module(mod_name)
        except ImportError as exc:
            logger.warning(f"[scan_runner] {mod_name} import edilemedi: {exc!r}")
            return None
    else:
        # Fallback: "websecure.scanners.xxx" -> "scanners.xxx" -> "xxx"
        if "." in mod_name:
            fallback = mod_name.split(".", 1)[1]
            fb_spec = _spec_exists(fallback)
            if fb_spec is not None:
                try:
                    mod = importlib.import_module(fallback)
                except ImportError as exc:
                    logger.debug(f"[scan_runner] {fallback} fallback import başarısız: {exc!r}")

    if mod is None:
        logger.debug(f"[scan_runner] Modül bulunamadı, atlanıyor: {mod_name}")
        return None

    run_fn = getattr(mod, "run", None)
    if not callable(run_fn):
        logger.debug(f"[scan_runner] {mod_name}.run() çağrılabilir değil")
        return None

    try:
        sig = inspect.signature(run_fn)
        params = sig.parameters
    except (TypeError, ValueError) as exc:
        logger.warning(f"[scan_runner] {mod_name}.run() imzası alınamadı: {exc!r}")
        return None

    kw: dict = {}
    if "url" in params:
        kw["url"] = url
    if "session" in params:
        kw["session"] = session
    if "debug" in params:
        kw["debug"] = debug
    if "auth_ctx" in params:
        kw["auth_ctx"] = auth_ctx

    try:
        return run_fn(**kw)
    except Exception as exc:
        logger.error(f"[scan_runner] {mod_name}.run() çalışırken hata: {exc!r}", exc_info=True)
        return None


# ---------------------------------------------------------------------------
# Offensive scanner bağlama
# ---------------------------------------------------------------------------

def _bind_offensive(modname: str, fallback_name: str) -> Callable:
    """
    Bir offensive scanner modülünü yükler ve `run` fonksiyonunu döner.
    Modül yoksa veya `run` bulunamazsa, sessiz bir no-op fallback döner.

    FAZ 4.2: main.py:938'den taşındı.
    """
    fn: Optional[Callable] = None

    if _spec_exists(modname) is not None:
        try:
            _m = importlib.import_module(modname)
            _r = getattr(_m, "run", None)
            if callable(_r):
                fn = _r
            else:
                logger.debug(f"[scan_runner] {modname}.run() bulunamadı veya çağrılabilir değil")
        except ImportError as exc:
            logger.debug(f"[scan_runner] {modname} import edilemedi: {exc!r}")

    if fn is None:
        def _fallback(*a, **k):
            return None

        _fallback.__name__ = fallback_name
        return _fallback

    return fn


# ---------------------------------------------------------------------------
# ScanSession — Tarama oturum yöneticisi (checkpoint + ETA birleştirici)
# ---------------------------------------------------------------------------

class ScanSession:
    """
    Tek bir tarama oturumunu temsil eden orkestrasyon sınıfı.

    Sorumluluklar
    -------------
    * Checkpoint oluşturma / yükleme / otomatik kaydetme
    * ETA (Tahmini Bitiş Süresi) hesaplama ve loglama
    * Modül bazlı ilerleme takibi
    * Önceki taramadan devam (resume) desteği

    Kullanım
    --------
    ```python
    session = ScanSession.new("https://example.com", profile="aggressive")
    # veya devam:
    session = ScanSession.resume_from("scan-id-abc123")

    with session:
        for url in urls:
            result = do_scan(url)
            session.on_task_done(task_hash, duration_s=elapsed)
        session.on_module_done("sqli")
    ```
    """

    def __init__(
        self,
        scan_id: str,
        target: str,
        profile: str,
        total_tasks: int = 0,
        checkpoint_enabled: bool = True,
        checkpoint_dir: Optional[Path] = None,
        auto_save_interval_s: float = 60.0,
        log_interval_s: float = 120.0,
    ) -> None:
        self.scan_id = scan_id
        self.target = target
        self.profile = profile

        make_cp, CheckpointHook, _ = _import_checkpoint()
        ETACalc = _import_eta()

        # Checkpoint
        if make_cp is not None and checkpoint_enabled:
            self._checkpoint = make_cp(
                scan_id=scan_id,
                target=target,
                profile=profile,
                checkpoint_dir=checkpoint_dir,
                auto_save_interval_s=auto_save_interval_s,
                enabled=True,
            )
        else:
            try:
                from websecure.core.checkpoint import NoopCheckpoint
                self._checkpoint = NoopCheckpoint(scan_id=scan_id)
            except ImportError:
                self._checkpoint = None  # type: ignore[assignment]

        # ETA
        self._eta = None
        if ETACalc is not None and total_tasks > 0:
            try:
                self._eta = ETACalc(total_tasks=total_tasks)
            except Exception:
                pass

        # Hook
        self._hook = None
        if CheckpointHook is not None and self._checkpoint is not None:
            self._hook = CheckpointHook(
                checkpoint=self._checkpoint,
                eta_calculator=self._eta,
                log_interval_s=log_interval_s,
            )
            self._checkpoint.set_total_tasks(total_tasks)

        # Arka plan tick thread'i
        self._tick_stop = threading.Event()
        self._tick_thread: Optional[threading.Thread] = None

    # ------------------------------------------------------------------
    # Fabrika metotları
    # ------------------------------------------------------------------

    @classmethod
    def new(
        cls,
        target: str,
        profile: str = "default",
        total_tasks: int = 0,
        checkpoint_enabled: bool = True,
        checkpoint_dir: Optional[Path] = None,
        tenant_id: Optional[str] = None,
        project_id: Optional[str] = None,
    ) -> "ScanSession":
        """Yeni bir tarama oturumu başlatır ve DB'ye 'running' kaydı oluşturur."""
        scan_id = _generate_scan_id()
        session = cls(
            scan_id=scan_id,
            target=target,
            profile=profile,
            total_tasks=total_tasks,
            checkpoint_enabled=checkpoint_enabled,
            checkpoint_dir=checkpoint_dir,
        )
        session.tenant_id = tenant_id
        session.project_id = project_id
        logger.info(f"[scan_runner] Yeni oturum başlatıldı: {scan_id}  ->  {target}")

        # DB'ye scan başlangıç kaydı (status=running) — crash recovery için
        try:
            import datetime as _dt
            from websecure.db import get_db as _get_db_new, ScanRepository as _SR, Scan as _Scan
            _db_new = _get_db_new()
            _scan_obj = _Scan(
                id=scan_id,
                target=target,
                profile=profile,
                status="running",
                started_at=_dt.datetime.utcnow().isoformat(),
                tenant_id=tenant_id,
                project_id=project_id,
            )
            _SR(_db_new).create(_scan_obj)
            logger.debug(f"[scan_runner] DB scan başlangıç kaydı: {scan_id}")
        except Exception as _dbs_exc:
            logger.debug(f"[scan_runner] DB scan başlangıç kaydı atlandı: {_dbs_exc!r}")

        return session

    @classmethod
    def resume_from(
        cls,
        scan_id: str,
        deduplicator: Any = None,
        checkpoint_dir: Optional[Path] = None,
    ) -> Optional["ScanSession"]:
        """
        Mevcut bir taramayı kaldığı yerden devam ettirir.

        Parameters
        ----------
        scan_id      : Devam edilecek tarama ID'si
        deduplicator : ScanDeduplicator (varsa tamamlanan görevler enjekte edilir)
        checkpoint_dir : Checkpoint dizini

        Returns
        -------
        ScanSession veya None (checkpoint bulunamazsa)
        """
        _, _, get_mgr = _import_checkpoint()
        if get_mgr is None:
            logger.warning("[scan_runner] Checkpoint modülü yüklü değil, resume imkânsız.")
            return None

        manager = get_mgr(checkpoint_dir=checkpoint_dir)
        state = manager.resume(scan_id, deduplicator) if deduplicator else None

        cp = manager.get(scan_id)
        if cp is None:
            return None

        s = cp.state
        session = cls(
            scan_id=scan_id,
            target=s.target,
            profile=s.profile,
            total_tasks=s.total_tasks,
            checkpoint_enabled=True,
            checkpoint_dir=checkpoint_dir,
        )
        # Mevcut checkpoint'i kullan
        session._checkpoint = cp  # noqa: SLF001
        if session._hook is not None:
            session._hook._cp = cp  # noqa: SLF001

        logger.info(
            f"[scan_runner] Devam ediliyor: {scan_id}  "
            f"%{s.progress_pct:.1f} daha önce tamamlandı  "
            f"({s.completed_count}/{s.total_tasks} görev)"
        )
        return session

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> "ScanSession":
        self._start_tick_thread()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self._stop_tick_thread()
        if self._hook:
            self._hook.on_scan_complete()

    # ------------------------------------------------------------------
    # Olay callback'leri
    # ------------------------------------------------------------------

    def on_task_done(self, task_hash: str, duration_s: float = 0.0) -> None:
        """Bir görev tamamlandığında çağır."""
        if self._hook:
            self._hook.on_task_done(task_hash, duration_s)

    def on_module_done(self, module: str) -> None:
        """Bir modül bittiğinde çağır."""
        if self._hook:
            self._hook.on_module_done(module)

    def save_now(self) -> None:
        """Anında checkpoint kaydet."""
        if self._checkpoint:
            self._checkpoint.save(force=True)

    def add_finding(self, key: str, finding: Any) -> None:
        """Bulgu ekle ve checkpoint'e yaz."""
        if self._checkpoint:
            self._checkpoint.add_finding(key, finding)

    def eta_snapshot(self) -> Dict[str, Any]:
        """ETA anlık görüntüsü döner (ETA yoksa boş dict)."""
        if self._eta is None:
            return {}
        try:
            return self._eta.snapshot()
        except Exception:
            return {}

    def progress(self) -> Dict[str, Any]:
        """İlerleme bilgisi döner."""
        if self._checkpoint is None:
            return {}
        s = self._checkpoint.state
        info: Dict[str, Any] = {
            "scan_id":         self.scan_id,
            "target":          self.target,
            "profile":         self.profile,
            "progress_pct":    round(s.progress_pct, 1),
            "completed_count": s.completed_count,
            "total_tasks":     s.total_tasks,
            "elapsed_seconds": round(s.elapsed_seconds, 1),
        }
        info.update(self.eta_snapshot())
        return info

    # ------------------------------------------------------------------
    # Arka plan tick
    # ------------------------------------------------------------------

    def _start_tick_thread(self) -> None:
        if self._hook is None:
            return
        self._tick_stop.clear()
        self._tick_thread = threading.Thread(
            target=self._tick_loop,
            name=f"cp-tick-{self.scan_id[:8]}",
            daemon=True,
        )
        self._tick_thread.start()

    def _stop_tick_thread(self) -> None:
        self._tick_stop.set()
        if self._tick_thread and self._tick_thread.is_alive():
            self._tick_thread.join(timeout=5)

    def _tick_loop(self) -> None:
        while not self._tick_stop.is_set():
            time.sleep(10)
            if self._hook:
                try:
                    self._hook.tick()
                except Exception as exc:
                    logger.debug(f"[scan_runner] tick hatası: {exc!r}")


# ---------------------------------------------------------------------------
# Yardımcı fonksiyonlar
# ---------------------------------------------------------------------------

def _generate_scan_id() -> str:
    """Kısa, benzersiz tarama kimliği üretir."""
    return uuid.uuid4().hex[:12]


def list_checkpoints(checkpoint_dir: Optional[Path] = None) -> List[Dict[str, Any]]:
    """
    Kaydedilmiş tüm checkpoint'leri listeler.

    Returns
    -------
    List[Dict] — scan_id, target, profile, progress_pct, saved_at vb.
    """
    _, _, get_mgr = _import_checkpoint()
    if get_mgr is None:
        return []
    return get_mgr(checkpoint_dir=checkpoint_dir).list_checkpoints()


def cleanup_checkpoints(
    max_age_days: int = 7,
    checkpoint_dir: Optional[Path] = None,
) -> int:
    """Eski checkpoint dosyalarını temizler. Silinen dosya sayısını döner."""
    _, _, get_mgr = _import_checkpoint()
    if get_mgr is None:
        return 0
    return get_mgr(checkpoint_dir=checkpoint_dir).cleanup(max_age_days)


# ---------------------------------------------------------------------------
# Adım 20 — Tarama sonrası kalıcılık köprüsü
# ---------------------------------------------------------------------------

def post_scan_persist(
    scan_id: str,
    target: str,
    findings: List[Dict[str, Any]],
    profile: str = "default",
    duration_s: float = 0.0,
    tenant_id: Optional[str] = None,
    project_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Tarama tamamlandıktan sonra:
    1. Bulgular FPLearner ile filtrelenir (bilinen FP'ler çıkarılır)
    2. Temiz bulgular DB'ye kaydedilir
    3. Güvenlik skoru hesaplanır ve kaydedilir
    4. Özet döndürülür

    Parametreler
    ------------
    scan_id    : Tarama kimliği
    target     : Hedef URL
    findings   : Ham bulgu listesi (dict)
    profile    : Tarama profili
    duration_s : Tarama süresi (saniye)
    tenant_id  : Tenant ID (çok kiracılı)
    project_id : Proje ID

    Döndürür
    --------
    dict — {scan_id, target, original, after_fp, score, risk_level, db_saved}
    """
    result: Dict[str, Any] = {
        "scan_id": scan_id,
        "target": target,
        "original_count": len(findings),
        "after_fp_count": len(findings),
        "score": 100.0,
        "risk_level": "Minimal",
        "db_saved": False,
        "fp_filtered": 0,
    }

    # 1. FP filtreleme
    clean_findings = findings
    try:
        from websecure.core.fp_learner import get_fp_learner
        learner = get_fp_learner()
        clean_findings = learner.filter_findings(findings, tenant_id=tenant_id)
        result["fp_filtered"] = len(findings) - len(clean_findings)
        result["after_fp_count"] = len(clean_findings)
        logger.info(
            f"[scan_runner] FP filtresi: {result['fp_filtered']} bulgu çıkarıldı "
            f"({len(clean_findings)}/{len(findings)} kaldı)"
        )
    except Exception as exc:
        logger.debug(f"[scan_runner] FP filtresi atlandı: {exc}")

    # 2. Skor hesaplama
    try:
        from websecure.core.score_tracker import get_score_tracker
        from websecure.db import get_db as _get_db
        _db = None
        try:
            _db = _get_db()
        except Exception:
            pass
        tracker = get_score_tracker(db=_db)
        snapshot = tracker.record(
            scan_id=scan_id,
            target=target,
            findings=clean_findings,
            project_id=project_id,
            tenant_id=tenant_id,
        )
        result["score"] = snapshot.score
        result["risk_level"] = snapshot.risk_level
        logger.info(
            f"[scan_runner] Güvenlik skoru: {snapshot.score:.1f}/100 "
            f"({snapshot.risk_level})"
        )
    except Exception as exc:
        logger.debug(f"[scan_runner] Skor kaydı atlandı: {exc}")

    # 3. DB kayıt
    try:
        from websecure.db import get_db, ScanRepository, FindingRepository, Scan, Finding
        import hashlib, datetime as _dt
        db = get_db()
        scan_repo = ScanRepository(db)
        find_repo = FindingRepository(db)

        # Scan kaydı
        scan_obj = Scan(
            id=scan_id,
            target=target,
            profile=profile,
            status="completed",
            completed_at=_dt.datetime.utcnow().isoformat(),
            duration_s=duration_s,
            finding_count=len(clean_findings),
            score=result.get("score"),
            tenant_id=tenant_id,
            project_id=project_id,
        )
        # Mevcut tarama varsa güncelle, yoksa oluştur
        existing = scan_repo.get(scan_id)
        if existing:
            scan_repo.update(scan_obj)
        else:
            scan_repo.create(scan_obj)

        # Bulgular
        db_findings = []
        for f in clean_findings:
            fid = f.get("id") or hashlib.sha256(
                f"{scan_id}{f.get('title','')}{f.get('url','')}".encode()
            ).hexdigest()[:16]
            fp = hashlib.sha256(
                f"{f.get('title','')}{f.get('url','')}{f.get('type','')}".encode()
            ).hexdigest()[:16]
            db_findings.append(Finding(
                id=fid,
                scan_id=scan_id,
                tenant_id=tenant_id,
                project_id=project_id,
                fingerprint=f.get("fingerprint") or fp,
                title=f.get("title") or f.get("type") or "Unknown",
                severity=f.get("severity") or f.get("cvss_severity") or "Info",
                url=f.get("url") or target,
                tool=f.get("tool") or "websecure",
                category=f.get("category") or f.get("type") or "",
                description=str(f.get("description") or "")[:1000],
                evidence=str(f.get("evidence") or f.get("payload") or "")[:500],
                cwe=str(f.get("cwe") or ""),
                cvss=f.get("cvss_score"),
                verified=bool(f.get("verified")),
                remediation=str(f.get("remediation") or "")[:500],
                extra={"raw": {k: v for k, v in f.items()
                               if k not in ("title","severity","url","tool","description",
                                            "evidence","cwe","cvss_score","verified","remediation")}},
            ))

        saved = find_repo.bulk_create(db_findings)
        result["db_saved"] = True
        result["db_findings_saved"] = saved
        logger.info(f"[scan_runner] DB: {saved}/{len(db_findings)} bulgu kaydedildi.")
    except Exception as exc:
        logger.warning(f"[scan_runner] DB kayıt atlandı: {exc}")

    # 4. Exploitation pipeline (opt-in)
    try:
        from websecure.core.exploit_orchestrator import exploit_from_results
        exploitation_results = exploit_from_results(
            scan_results={"findings": clean_findings},
            cfg={"exploitation": {"enabled": False}},  # default off, callers set True
        )
        if exploitation_results.get("exploit_results"):
            result["exploitation"] = {
                "total": exploitation_results["summary"]["total"],
                "successful": exploitation_results["summary"]["successful"],
            }
            logger.info(
                f"[scan_runner] Exploitation: "
                f"{exploitation_results['summary']['successful']}/"
                f"{exploitation_results['summary']['total']} başarılı"
            )
    except Exception as exc:
        logger.debug(f"[scan_runner] Exploitation pipeline atlandı: {exc}")

    return result


def make_human_session(profile: str = "stealth"):
    """
    İnsan gibi davranan bir requests session döner.

    HumanLikeAdapter ile sarılmış session — tüm isteklere gerçekçi
    timing, browser fingerprinting ve WAF/CAPTCHA tespiti eklenir.

    Parametreler
    ------------
    profile : "casual" | "stealth" | "aggressive" | "paranoid"
        Tarama profiline göre davranış hızı/gizliliği.

    Döndürür
    --------
    HumanLikeAdapter  (requests.Session uyumlu get/post arayüzü)
    """
    try:
        from websecure.core.human_adapter import make_human_session as _make
        return _make(profile)
    except ImportError as exc:
        logger.debug(f"[scan_runner] HumanLikeAdapter yüklenemedi, ham session: {exc}")
        import requests
        return requests.Session()


def filter_false_positives(
    findings: List[Dict[str, Any]],
    tenant_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Bulgular listesini FPLearner ile filtrele.
    Bağımsız yardımcı — main.py veya diğer modüller doğrudan çağırabilir.
    """
    try:
        from websecure.core.fp_learner import get_fp_learner
        return get_fp_learner().filter_findings(findings, tenant_id=tenant_id)
    except Exception as exc:
        logger.debug(f"[scan_runner] FP filtre hatası: {exc}")
        return findings


__all__ = [
    # Orijinal yardımcılar
    "_call_scanner_if_available",
    "_bind_offensive",
    # Oturum yönetimi
    "ScanSession",
    "list_checkpoints",
    "cleanup_checkpoints",
    "_generate_scan_id",
    # Adım 20 — Kalıcılık entegrasyonu
    "post_scan_persist",
    "filter_false_positives",
    # Yeni entegrasyonlar
    "make_human_session",
]
