"""A TTL-respecting DNS record cache with an injectable clock (for testing)."""
from __future__ import annotations

import threading
import time
from typing import Callable

from .wire import RR


class Cache:
    def __init__(self, clock: Callable[[], float] = time.time) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        # key: (name_lower, rtype) -> list[(expiry_abs, RR)]
        self._store: dict[tuple[str, int], list[tuple[float, RR]]] = {}

    def put(self, rr: RR) -> None:
        if rr.ttl <= 0:
            return
        key = (rr.name.lower().rstrip("."), rr.rtype)
        exp = self._clock() + rr.ttl
        with self._lock:
            self._store.setdefault(key, [])
            # de-dupe identical rdata, keep the fresher expiry
            self._store[key] = [(e, r) for (e, r) in self._store[key] if r.rdata != rr.rdata]
            self._store[key].append((exp, rr))

    def put_many(self, rrs: list[RR]) -> None:
        for rr in rrs:
            self.put(rr)

    def get(self, name: str, rtype: int) -> list[RR]:
        key = (name.lower().rstrip("."), rtype)
        now = self._clock()
        with self._lock:
            entries = self._store.get(key, [])
            live = [(e, r) for (e, r) in entries if e > now]
            if len(live) != len(entries):
                if live:
                    self._store[key] = live
                else:
                    self._store.pop(key, None)
            # return RRs with remaining TTL reflected
            out = []
            for exp, rr in live:
                out.append(RR(rr.name, rr.rtype, rr.rclass, int(exp - now), rr.rdata, rr.parsed))
            return out

    def __len__(self) -> int:
        with self._lock:
            return sum(len(v) for v in self._store.values())
