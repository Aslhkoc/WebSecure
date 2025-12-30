from __future__ import annotations
from dataclasses import dataclass, field
from typing import Set, Iterable, List

@dataclass
class EndpointStore:
    items: Set[str] = field(default_factory=set)

    def add_many(self, urls: Iterable[str]) -> None:
        for u in urls:
            if isinstance(u, str) and u.strip():
                self.items.add(u.strip())

    def to_list(self) -> List[str]:
        return sorted(self.items)
