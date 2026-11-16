"""Iterative (recursive-from-the-roots) DNS resolver.

Resolution logic is separated from I/O: a :class:`~minidns.transport.Transport`
supplies responses, so the resolver is driven by a fake transport in tests and a
real UDP socket in production. A :class:`~minidns.cache.Cache` honours TTLs.
"""
from __future__ import annotations

from typing import Callable

from .cache import Cache
from .wire import (
    QType, RCode, RR, build_query, Message,
)

# A subset of the IANA root hints (a/b/c/f/j) -- enough for iterative start.
ROOT_SERVERS = [
    "198.41.0.4",      # a.root-servers.net
    "199.9.14.201",    # b.root-servers.net
    "192.33.4.12",     # c.root-servers.net
    "192.5.5.241",     # f.root-servers.net
    "192.58.128.30",   # j.root-servers.net
]

MAX_DEPTH = 16


class ResolutionError(Exception):
    pass


class NXDomain(ResolutionError):
    pass


class ServFail(ResolutionError):
    pass


class Resolver:
    def __init__(self, transport, cache: Cache | None = None,
                 roots: list[str] | None = None) -> None:
        self.transport = transport
        self.cache = cache or Cache()
        self.roots = roots or list(ROOT_SERVERS)

    # -- public -------------------------------------------------------------
    def resolve(self, name: str, qtype: int) -> list[RR]:
        """Return the answer RRs for (name, qtype), using cache + iteration."""
        return self._resolve(name, qtype, depth=0, cname_chain=())

    # -- internals ----------------------------------------------------------
    def _resolve(self, name: str, qtype: int, depth: int, cname_chain: tuple) -> list[RR]:
        if depth > MAX_DEPTH:
            raise ResolutionError("maximum resolution depth exceeded")

        cached = self.cache.get(name, qtype)
        if cached:
            return cached

        nameservers = list(self.roots)
        tried: set[str] = set()

        while nameservers:
            ns_ip = nameservers.pop(0)
            if ns_ip in tried:
                continue
            tried.add(ns_ip)

            resp = self._query(ns_ip, name, qtype)
            if resp is None:
                continue

            rcode = resp.header.rcode
            if rcode == RCode.NXDOMAIN:
                raise NXDomain(name)
            if rcode == RCode.SERVFAIL:
                continue
            if rcode not in (RCode.NOERROR,):
                continue

            self.cache.put_many(resp.answers + resp.authorities + resp.additionals)

            # 1) direct answer of the requested type
            answers = [rr for rr in resp.answers if rr.rtype == qtype
                       and rr.name.lower().rstrip(".") == name.lower().rstrip(".")]
            if answers:
                return answers

            # 2) CNAME chase
            cnames = [rr for rr in resp.answers if rr.rtype == QType.CNAME]
            if cnames and qtype != QType.CNAME:
                target = cnames[0].parsed
                if target.lower() in cname_chain:
                    raise ResolutionError("CNAME loop")
                chased = self._resolve(target, qtype, depth + 1,
                                       cname_chain + (name.lower(),))
                return cnames + chased

            # 3) delegation: follow NS referrals
            ns_records = [rr for rr in resp.authorities if rr.rtype == QType.NS]
            if ns_records:
                glue = self._glue_ips(ns_records, resp.additionals)
                if not glue:
                    # no glue -> resolve an NS name's address, then continue
                    glue = self._resolve_ns_addresses(ns_records, depth + 1)
                if glue:
                    nameservers = glue + nameservers
                    tried.clear()
                    continue

            # NOERROR but nothing useful -> treat as no data
            if rcode == RCode.NOERROR and not resp.answers and not ns_records:
                return []

        raise ServFail(f"no nameserver could resolve {name!r}")

    def _query(self, ns_ip: str, name: str, qtype: int) -> Message | None:
        packet = build_query(name, qtype)
        try:
            return self.transport.query(ns_ip, packet)
        except Exception:
            return None

    @staticmethod
    def _glue_ips(ns_records: list[RR], additionals: list[RR]) -> list[str]:
        ns_names = {rr.parsed.lower() for rr in ns_records}
        ips = []
        for rr in additionals:
            if rr.rtype in (QType.A, QType.AAAA) and rr.name.lower().rstrip(".") in ns_names:
                if rr.rtype == QType.A:          # prefer IPv4 for reachability
                    ips.insert(0, rr.parsed)
                else:
                    ips.append(rr.parsed)
        return ips

    def _resolve_ns_addresses(self, ns_records: list[RR], depth: int) -> list[str]:
        for rr in ns_records:
            try:
                a = self._resolve(rr.parsed, QType.A, depth + 1, ())
                if a:
                    return [r.parsed for r in a]
            except ResolutionError:
                continue
        return []


def make_live_resolver(timeout: float = 3.0) -> Resolver:
    from .transport import UDPTransport
    return Resolver(UDPTransport(timeout))
