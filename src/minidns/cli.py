"""A tiny dig-like CLI: iterative resolution from the roots over real UDP.

    python -m minidns.cli example.com A
    python -m minidns.cli www.github.com AAAA
"""
from __future__ import annotations

import sys

from .resolver import NXDomain, ResolutionError, make_live_resolver
from .wire import QType


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        print("usage: python -m minidns.cli <name> [A|AAAA|MX|TXT|NS]", file=sys.stderr)
        return 2
    name = argv[0]
    tname = (argv[1].upper() if len(argv) > 1 else "A")
    try:
        qtype = QType[tname]
    except KeyError:
        print(f"unsupported type {tname!r}", file=sys.stderr)
        return 2

    resolver = make_live_resolver()
    try:
        rrs = resolver.resolve(name, qtype)
    except NXDomain:
        print(f";; NXDOMAIN {name}")
        return 1
    except ResolutionError as e:
        print(f";; resolution failed: {e}", file=sys.stderr)
        return 1

    if not rrs:
        print(f";; no {tname} records for {name}")
        return 0
    print(f";; {name} {tname}")
    for rr in rrs:
        print(f"{rr.name:<32} {rr.ttl:>6}  {QType(rr.rtype).name:<6} {rr.parsed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
