# minidns — a DNS resolver from scratch

<!-- at-a-glance -->
> **A recursive DNS resolver built from scratch — wire format up, no library shortcuts.**  
> **Result:** 14 tests; parses and builds real DNS packets and resolves recursively.  
> **Reproduce:** `pytest -q`  
> ![CI](https://github.com/fhionnghaile/dns-resolver/actions/workflows/ci.yml/badge.svg)
>
> **What this is worth:** Demonstrates systems depth — understanding a protocol at the byte level is what separates using a stack from being able to fix it.


A recursive (iterative-from-the-roots) DNS resolver built on the **standard library
only**: the wire format is hand-parsed, resolution follows real delegations, and a
TTL-respecting cache sits in front. No `dnspython`, no `socket` tricks hidden in a
library — the RFC 1035 bytes are decoded here.

> **What it proves:** networking fundamentals (the DNS wire format, name compression,
> iterative resolution, caching) and defensive systems programming (a parser that never
> crashes on hostile input).

## What's inside

```
src/minidns/
  wire.py        RFC 1035 codec: header, questions, RRs, RDATA for
                 A / AAAA / NS / CNAME / MX / TXT / SOA / PTR, and
                 name-compression pointers (with loop detection)
  cache.py       TTL cache with an injectable clock
  transport.py   UDP transport (+ TCP fallback on truncation); a Protocol
                 so tests inject a fake and live use gets a real socket
  resolver.py    iterative resolution from the root hints: follow NS
                 referrals + glue, chase CNAMEs, honour the cache
  cli.py         a dig-like command-line front end
```

**I/O is separated from logic.** `Resolver` is driven by a `Transport`, so every
resolution path — delegation, glue, CNAME chasing, NXDOMAIN, caching — is tested
against a simulated root→TLD→authoritative hierarchy with **no network at all**.

## Run it

```bash
# live resolution from the roots (needs outbound UDP/53)
python -m minidns.cli example.com A
python -m minidns.cli github.com MX

# tests (hermetic — no network)
pip install -e ".[dev]" && pytest -q
```

## What the tests pin down (the spec's acceptance cases)

| Test | Guarantee |
|------|-----------|
| `test_question_round_trip`, `test_rr_round_trip_all_types`, `test_mx_round_trip` | Encode→decode is identity for every supported record type |
| `test_name_compression_pointer_followed` | Compression pointers are resolved to the full name |
| `test_compression_pointer_loop_rejected` | A pointer loop raises, it does not hang |
| `test_fuzz_parser_never_crashes`, `test_fuzz_structured_but_corrupt` | 8,000 random/corrupt packets → only `DNSFormatError`, never a crash |
| `test_resolves_a_record_iteratively` | Walks root → `.com` → authoritative and returns the A record |
| `test_cname_is_chased` | A CNAME answer is followed to its target's A record |
| `test_nxdomain_raised` | `NXDOMAIN` surfaces as an exception |
| `test_cache_hit_avoids_second_walk` | A second lookup within TTL issues **zero** new queries |
| `test_cache_honours_ttl_with_fake_clock` | Records expire exactly at their TTL (fake clock) |

## Notes & limits

- Iterative resolver (talks to authoritative servers directly); it does not implement
  DNSSEC validation or EDNS0 — deliberately, to keep the wire code readable.
- The parser is the security surface, so it is the most defensively written part and the
  most heavily fuzzed: every read is bounds-checked and compression pointers must point
  strictly backwards.

## Key decisions

- Hand-rolled wire-format parser/builder, so the protocol is understood, not abstracted away.
- Recursive resolution from the roots, with caching that respects TTLs.
- Defensive parsing against malformed or hostile packets.

## Scope & limits

- An educational resolver, not a hardened production server (no DNSSEC validation or rate-limiting).

