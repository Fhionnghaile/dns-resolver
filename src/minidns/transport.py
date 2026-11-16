"""Query transports: a real UDP one for live use, injectable for tests."""
from __future__ import annotations

import socket
from typing import Protocol

from .wire import DNSFormatError, Message, unpack_message


class Transport(Protocol):
    def query(self, server_ip: str, packet: bytes) -> Message:  # pragma: no cover
        ...


class UDPTransport:
    """Send a query over UDP/53 with a timeout and TCP fallback on truncation."""

    def __init__(self, timeout: float = 3.0) -> None:
        self.timeout = timeout

    def query(self, server_ip: str, packet: bytes) -> Message:
        fam = socket.AF_INET6 if ":" in server_ip else socket.AF_INET
        with socket.socket(fam, socket.SOCK_DGRAM) as s:
            s.settimeout(self.timeout)
            s.sendto(packet, (server_ip, 53))
            data, _ = s.recvfrom(4096)
        msg = unpack_message(data)
        if msg.header.tc:                      # truncated -> retry over TCP
            return self._tcp(server_ip, packet, fam)
        return msg

    def _tcp(self, server_ip: str, packet: bytes, fam: int) -> Message:
        import struct
        with socket.socket(fam, socket.SOCK_STREAM) as s:
            s.settimeout(self.timeout)
            s.connect((server_ip, 53))
            s.sendall(struct.pack(">H", len(packet)) + packet)
            ln = struct.unpack(">H", _recvn(s, 2))[0]
            return unpack_message(_recvn(s, ln))


def _recvn(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise DNSFormatError("connection closed mid-message")
        buf += chunk
    return buf
