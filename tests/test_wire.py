import random
import struct

import pytest

from minidns.wire import (
    DNSFormatError, Header, Message, QType, Question, RR,
    build_query, decode_name, encode_name, pack_message, unpack_message,
)


def _rr_a(name, ip, ttl=300):
    return RR(name, QType.A, 1, ttl, bytes(int(x) for x in ip.split(".")), ip)


def test_question_round_trip():
    msg = Message(Header(id=0x4142), [Question("www.example.com", QType.A)])
    back = unpack_message(pack_message(msg))
    assert back.header.id == 0x4142
    assert back.questions[0].name == "www.example.com"
    assert back.questions[0].qtype == QType.A


@pytest.mark.parametrize("qtype,name,value,rdata", [
    (QType.A, "example.com", "93.184.216.34", bytes([93, 184, 216, 34])),
    (QType.NS, "example.com", "a.iana-servers.net", encode_name("a.iana-servers.net")),
    (QType.CNAME, "www.example.com", "example.com", encode_name("example.com")),
    (QType.TXT, "example.com", ["hello world"], b"\x0bhello world"),
])
def test_rr_round_trip_all_types(qtype, name, value, rdata):
    rr = RR(name, qtype, 1, 300, rdata, None)
    msg = Message(Header(id=1, qr=1), [Question(name, qtype)], answers=[rr])
    back = unpack_message(pack_message(msg))
    assert back.answers[0].parsed == value


def test_mx_round_trip():
    rdata = struct.pack(">H", 10) + encode_name("mail.example.com")
    rr = RR("example.com", QType.MX, 1, 300, rdata, None)
    back = unpack_message(pack_message(Message(Header(id=1, qr=1), answers=[rr])))
    assert back.answers[0].parsed == (10, "mail.example.com")


def test_name_compression_pointer_followed():
    # hand-build: header + question 'example.com' + an answer whose NAME is a
    # compression pointer back to the question name at offset 12.
    header = struct.pack(">HHHHHH", 1, 0x8000, 1, 1, 0, 0)
    qname = encode_name("example.com")          # starts at offset 12
    question = qname + struct.pack(">HH", QType.A, 1)
    ptr = struct.pack(">H", 0xC000 | 12)         # pointer to offset 12
    answer = ptr + struct.pack(">HHIH", QType.A, 1, 300, 4) + bytes([1, 2, 3, 4])
    packet = header + question + answer
    msg = unpack_message(packet)
    assert msg.answers[0].name == "example.com"   # pointer resolved
    assert msg.answers[0].parsed == "1.2.3.4"


def test_compression_pointer_loop_rejected():
    # a pointer at offset 12 that points to itself
    data = struct.pack(">HHHHHH", 1, 0, 1, 0, 0, 0) + struct.pack(">H", 0xC000 | 12)
    with pytest.raises(DNSFormatError):
        decode_name(data, 12)


def test_encode_rejects_oversize_label():
    with pytest.raises(DNSFormatError):
        encode_name("x" * 64 + ".com")


def test_fuzz_parser_never_crashes():
    rng = random.Random(1234)
    for _ in range(5000):
        n = rng.randint(0, 60)
        blob = bytes(rng.getrandbits(8) for _ in range(n))
        try:
            unpack_message(blob)
        except DNSFormatError:
            pass          # the only acceptable failure mode
        # any other exception propagates and fails the test


def test_fuzz_structured_but_corrupt():
    """Valid header, random body -- exercises RR/name parsing paths."""
    rng = random.Random(99)
    base = build_query("example.com", QType.A)
    for _ in range(3000):
        body = bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 40)))
        hdr = struct.pack(">HHHHHH", 1, 0x8000, 1, rng.randint(0, 3), rng.randint(0, 3), 0)
        try:
            unpack_message(hdr + base[12:] + body)
        except DNSFormatError:
            pass
