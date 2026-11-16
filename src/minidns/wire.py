"""DNS wire-format codec (RFC 1035) with name-compression support.

Pure standard library. The parser is written defensively: every read is
bounds-checked and compression-pointer loops are detected, so malformed or
hostile packets raise :class:`DNSFormatError` rather than crashing or looping.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import IntEnum


class DNSFormatError(ValueError):
    """Raised when a packet cannot be parsed as well-formed DNS."""


class QType(IntEnum):
    A = 1
    NS = 2
    CNAME = 5
    SOA = 6
    PTR = 12
    MX = 15
    TXT = 16
    AAAA = 28


class QClass(IntEnum):
    IN = 1


class RCode(IntEnum):
    NOERROR = 0
    FORMERR = 1
    SERVFAIL = 2
    NXDOMAIN = 3
    NOTIMP = 4
    REFUSED = 5


# -- names ------------------------------------------------------------------
def encode_name(name: str) -> bytes:
    """Encode a domain name as length-prefixed labels (no compression)."""
    name = name.rstrip(".")
    if name == "":
        return b"\x00"
    out = bytearray()
    for label in name.split("."):
        b = label.encode("idna") if any(ord(c) > 127 for c in label) else label.encode("ascii")
        if not 1 <= len(b) <= 63:
            raise DNSFormatError(f"label length out of range: {label!r}")
        out.append(len(b))
        out += b
    out.append(0)
    return bytes(out)


def decode_name(data: bytes, offset: int) -> tuple[str, int]:
    """Decode a (possibly compressed) name. Returns (name, offset_after).

    ``offset_after`` is the position just past the name *in the original
    stream* -- for a compressed name that is just past the 2-byte pointer.
    """
    labels: list[str] = []
    pos = offset
    jumped = False
    end_offset = offset
    seen_pointers: set[int] = set()
    n = len(data)

    while True:
        if pos >= n:
            raise DNSFormatError("name runs past end of packet")
        length = data[pos]
        if length & 0xC0 == 0xC0:          # compression pointer
            if pos + 1 >= n:
                raise DNSFormatError("truncated compression pointer")
            pointer = ((length & 0x3F) << 8) | data[pos + 1]
            if not jumped:
                end_offset = pos + 2
            if pointer in seen_pointers:
                raise DNSFormatError("compression pointer loop")
            seen_pointers.add(pointer)
            if pointer >= pos:
                raise DNSFormatError("forward/self compression pointer")
            pos = pointer
            jumped = True
            continue
        if length & 0xC0:
            raise DNSFormatError("reserved label length bits set")
        if length == 0:                     # root label -> end
            pos += 1
            if not jumped:
                end_offset = pos
            break
        pos += 1
        if pos + length > n:
            raise DNSFormatError("label runs past end of packet")
        labels.append(data[pos:pos + length].decode("ascii", "replace"))
        pos += length

    return (".".join(labels) if labels else "", end_offset)


# -- records ----------------------------------------------------------------
@dataclass
class Question:
    name: str
    qtype: int
    qclass: int = QClass.IN


@dataclass
class RR:
    name: str
    rtype: int
    rclass: int
    ttl: int
    rdata: bytes                      # raw RDATA
    parsed: object = None             # decoded value (str / tuple), best-effort


@dataclass
class Header:
    id: int = 0
    qr: int = 0
    opcode: int = 0
    aa: int = 0
    tc: int = 0
    rd: int = 1
    ra: int = 0
    rcode: int = 0
    qdcount: int = 0
    ancount: int = 0
    nscount: int = 0
    arcount: int = 0


@dataclass
class Message:
    header: Header
    questions: list[Question] = field(default_factory=list)
    answers: list[RR] = field(default_factory=list)
    authorities: list[RR] = field(default_factory=list)
    additionals: list[RR] = field(default_factory=list)


# -- header pack/unpack -----------------------------------------------------
def _pack_header(h: Header) -> bytes:
    flags = (
        (h.qr & 1) << 15 | (h.opcode & 0xF) << 11 | (h.aa & 1) << 10
        | (h.tc & 1) << 9 | (h.rd & 1) << 8 | (h.ra & 1) << 7 | (h.rcode & 0xF)
    )
    return struct.pack(">HHHHHH", h.id, flags, h.qdcount, h.ancount, h.nscount, h.arcount)


def _unpack_header(data: bytes) -> Header:
    if len(data) < 12:
        raise DNSFormatError("packet shorter than DNS header")
    id_, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
    return Header(
        id=id_, qr=(flags >> 15) & 1, opcode=(flags >> 11) & 0xF, aa=(flags >> 10) & 1,
        tc=(flags >> 9) & 1, rd=(flags >> 8) & 1, ra=(flags >> 7) & 1, rcode=flags & 0xF,
        qdcount=qd, ancount=an, nscount=ns, arcount=ar,
    )


# -- RDATA parsing ----------------------------------------------------------
def _parse_rdata(rtype: int, data: bytes, rdstart: int, rdlen: int):
    end = rdstart + rdlen
    if end > len(data):
        raise DNSFormatError("rdata runs past end of packet")
    rd = data[rdstart:end]
    if rtype == QType.A:
        if rdlen != 4:
            raise DNSFormatError("A record rdata must be 4 bytes")
        return ".".join(str(b) for b in rd)
    if rtype == QType.AAAA:
        if rdlen != 16:
            raise DNSFormatError("AAAA record rdata must be 16 bytes")
        import ipaddress
        return str(ipaddress.IPv6Address(rd))
    if rtype in (QType.NS, QType.CNAME, QType.PTR):
        name, _ = decode_name(data, rdstart)
        return name
    if rtype == QType.MX:
        if rdlen < 3:
            raise DNSFormatError("MX rdata too short")
        pref = struct.unpack(">H", rd[:2])[0]
        name, _ = decode_name(data, rdstart + 2)
        return (pref, name)
    if rtype == QType.TXT:
        out, i = [], 0
        while i < len(rd):
            ln = rd[i]; i += 1
            if i + ln > len(rd):
                raise DNSFormatError("TXT segment past rdata end")
            out.append(rd[i:i + ln].decode("ascii", "replace")); i += ln
        return out
    if rtype == QType.SOA:
        mname, p = decode_name(data, rdstart)
        rname, p = decode_name(data, p)
        if p + 20 > end:
            raise DNSFormatError("SOA rdata too short")
        serial, refresh, retry, expire, minimum = struct.unpack(">IIIII", data[p:p + 20])
        return (mname, rname, serial, refresh, retry, expire, minimum)
    return rd  # unknown type: keep raw


def _read_rr(data: bytes, offset: int) -> tuple[RR, int]:
    name, pos = decode_name(data, offset)
    if pos + 10 > len(data):
        raise DNSFormatError("truncated RR fixed fields")
    rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", data[pos:pos + 10])
    pos += 10
    parsed = _parse_rdata(rtype, data, pos, rdlen)
    rdata = data[pos:pos + rdlen]
    pos += rdlen
    return RR(name, rtype, rclass, ttl, rdata, parsed), pos


# -- message pack/unpack ----------------------------------------------------
def pack_message(msg: Message) -> bytes:
    h = msg.header
    h.qdcount, h.ancount = len(msg.questions), len(msg.answers)
    h.nscount, h.arcount = len(msg.authorities), len(msg.additionals)
    out = bytearray(_pack_header(h))
    for q in msg.questions:
        out += encode_name(q.name)
        out += struct.pack(">HH", q.qtype, q.qclass)
    for section in (msg.answers, msg.authorities, msg.additionals):
        for rr in section:
            out += encode_name(rr.name)
            out += struct.pack(">HHIH", rr.rtype, rr.rclass, rr.ttl, len(rr.rdata))
            out += rr.rdata
    return bytes(out)


def unpack_message(data: bytes) -> Message:
    h = _unpack_header(data)
    pos = 12
    questions: list[Question] = []
    for _ in range(h.qdcount):
        name, pos = decode_name(data, pos)
        if pos + 4 > len(data):
            raise DNSFormatError("truncated question")
        qtype, qclass = struct.unpack(">HH", data[pos:pos + 4])
        pos += 4
        questions.append(Question(name, qtype, qclass))
    answers, authorities, additionals = [], [], []
    for section, count in ((answers, h.ancount), (authorities, h.nscount), (additionals, h.arcount)):
        for _ in range(count):
            rr, pos = _read_rr(data, pos)
            section.append(rr)
    return Message(h, questions, answers, authorities, additionals)


def build_query(name: str, qtype: int, qid: int = 0x1234, rd: bool = True) -> bytes:
    msg = Message(Header(id=qid, rd=1 if rd else 0), [Question(name, qtype)])
    return pack_message(msg)
