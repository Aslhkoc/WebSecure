"""
websecure.reporters
~~~~~~~~~~~~~~~~~~~~
Rapor renderer paketi (markdown / html_dashboard / pdf).

Format'lar arası ORTAK severity yardımcıları burada TEK KAYNAK olarak tutulur;
eskiden markdown (_norm_sev_tr/_norm_sev_en/_sev_rank) ve html_dashboard (iki ayrı
{Critical:4..Info:0} haritası) bunu kendi içinde tekrar ediyordu. ``severity_rank``
normalize-ederek-sıralar; bu sayede hem TR/EN string varyantları hem de zaten
büyük-harf kanonik etiketler doğru sıralanır.
"""
from __future__ import annotations

from typing import Optional

# Severity string varyantları → kanonik İngilizce etiket (TR + EN superset).
_SEVERITY_VARIANTS = {
    "critical": "Critical", "crit": "Critical", "severe": "Critical", "kritik": "Critical",
    "high": "High", "yüksek": "High", "yuksek": "High",
    "medium": "Medium", "med": "Medium", "orta": "Medium",
    "low": "Low", "düşük": "Low", "dusuk": "Low", "düsük": "Low",
    "info": "Info", "informational": "Info", "bilgi": "Info",
}

# Kanonik etiket → sıralama rütbesi (critical en yüksek).
_SEVERITY_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}


def normalize_severity(s: Optional[str]) -> str:
    """Severity string'ini kanonik İngilizce etikete indir (TR/EN varyantları dahil)."""
    return _SEVERITY_VARIANTS.get((s or "Info").strip().lower(), "Info")


def severity_rank(s: Optional[str]) -> int:
    """Severity'yi sayısal rütbeye çevir: Critical=4 > High=3 > Medium=2 > Low=1 > Info=0.

    Önce ``normalize_severity`` ile kanonikleştirir → hem 'critical'/'kritik'/'yüksek'
    gibi varyantlar hem de zaten 'Critical' olan etiketler doğru sıralanır.
    """
    return _SEVERITY_RANK.get(normalize_severity(s), 0)


__all__ = ["normalize_severity", "severity_rank"]
