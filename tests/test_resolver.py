"""Resolver + cache tests driven by a fake transport (no network)."""
import struct

import pytest

from minidns.cache import Cache
from minidns.resolver import NXDomain, Resolver
from minidns.wire import (
    Header, Message, QType, Question, RCode, RR, encode_name, build_query, unpack_message,
)


def A(name, ip, ttl=3600):
    return RR(name, QType.A, 1, ttl, bytes(int(x) for x in ip.split(".")), ip)


def NS(name, target, ttl=3600):
    return RR(name, QType.NS, 1, ttl, encode_name(target), target)


def CNAME(name, target, ttl=3600):
    return RR(name, QType.CNAME, 1, ttl, encode_name(target), target)


def referral(qname, qtype, ns_name, ns_ip):
    return Message(Header(id=1, qr=1, rcode=RCode.NOERROR), [Question(qname, qtype)],
                   authorities=[NS(_zone(qname), ns_name)], additionals=[A(ns_name, ns_ip)])


def answer(qname, qtype, rrs):
    return Message(Header(id=1, qr=1, aa=1, rcode=RCode.NOERROR),
                   [Question(qname, qtype)], answers=rrs)


def _zone(qname):
    # crude: the parent zone a referral is "for"
    return ".".join(qname.split(".")[-2:]) if qname.count(".") >= 1 else qname


class FakeTransport:
    """Maps (server_ip) -> handler(qname, qtype) -> Message, simulating a hierarchy."""

    def __init__(self, table):
        self.table = table
        self.queries = []

    def query(self, server_ip, packet):
        msg = unpack_message(packet)
        q = msg.questions[0]
        self.queries.append((server_ip, q.name, q.qtype))
        handler = self.table.get(server_ip)
        if handler is None:
            raise OSError("unreachable")
        return handler(q.name, q.qtype)


# A three-level hierarchy: root -> com TLD -> example.com authoritative.
ROOT_IP, COM_IP, AUTH_IP = "198.41.0.4", "192.5.6.30", "93.1.1.1"


def build_table():
    def root(name, qtype):
        return Message(Header(qr=1, rcode=RCode.NOERROR), [Question(name, qtype)],
                       authorities=[NS("com", "a.gtld-servers.net")],
                       additionals=[A("a.gtld-servers.net", COM_IP)])

    def com(name, qtype):
        return Message(Header(qr=1, rcode=RCode.NOERROR), [Question(name, qtype)],
                       authorities=[NS("example.com", "ns.example.com")],
                       additionals=[A("ns.example.com", AUTH_IP)])

    def auth(name, qtype):
        n = name.lower().rstrip(".")
        if n == "example.com" and qtype == QType.A:
            return answer(name, qtype, [A("example.com", "93.184.216.34")])
        if n == "www.example.com" and qtype == QType.A:
            return answer(name, qtype, [CNAME("www.example.com", "example.com"),
                                        A("example.com", "93.184.216.34")])
        if n == "ns.example.com" and qtype == QType.A:
            return answer(name, qtype, [A("ns.example.com", AUTH_IP)])
        if n == "nope.example.com":
            return Message(Header(qr=1, aa=1, rcode=RCode.NXDOMAIN), [Question(name, qtype)])
        return Message(Header(qr=1, aa=1, rcode=RCode.NOERROR), [Question(name, qtype)])

    return {ROOT_IP: root, COM_IP: com, AUTH_IP: auth}


def test_resolves_a_record_iteratively():
    t = FakeTransport(build_table())
    r = Resolver(t, roots=[ROOT_IP])
    rrs = r.resolve("example.com", QType.A)
    assert [x.parsed for x in rrs] == ["93.184.216.34"]
    # it walked root -> com -> auth
    assert t.queries[0][0] == ROOT_IP and t.queries[-1][0] == AUTH_IP


def test_cname_is_chased():
    t = FakeTransport(build_table())
    r = Resolver(t, roots=[ROOT_IP])
    rrs = r.resolve("www.example.com", QType.A)
    types = {x.rtype for x in rrs}
    assert QType.CNAME in types and QType.A in types
    assert any(x.parsed == "93.184.216.34" for x in rrs if x.rtype == QType.A)


def test_nxdomain_raised():
    t = FakeTransport(build_table())
    r = Resolver(t, roots=[ROOT_IP])
    with pytest.raises(NXDomain):
        r.resolve("nope.example.com", QType.A)


def test_cache_hit_avoids_second_walk():
    t = FakeTransport(build_table())
    r = Resolver(t, roots=[ROOT_IP])
    r.resolve("example.com", QType.A)
    n_after_first = len(t.queries)
    r.resolve("example.com", QType.A)       # should be served from cache
    assert len(t.queries) == n_after_first  # no new queries


def test_cache_honours_ttl_with_fake_clock():
    clock = {"t": 1000.0}
    cache = Cache(clock=lambda: clock["t"])
    cache.put(A("example.com", "1.2.3.4", ttl=60))
    assert cache.get("example.com", QType.A)        # fresh
    clock["t"] += 59
    assert cache.get("example.com", QType.A)        # still within TTL
    clock["t"] += 2                                  # now past 60s
    assert cache.get("example.com", QType.A) == []  # expired
    assert len(cache) == 0


def test_cache_remaining_ttl_counts_down():
    clock = {"t": 0.0}
    cache = Cache(clock=lambda: clock["t"])
    cache.put(A("x.com", "1.1.1.1", ttl=100))
    clock["t"] = 30
    rr = cache.get("x.com", QType.A)[0]
    assert rr.ttl == 70
