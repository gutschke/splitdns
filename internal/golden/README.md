# Golden parity harness

This package pins **behavioral parity**: it proves the resolver produces the answers
the design promises, byte-for-byte, for the resolution behaviors it must preserve.

## How it works

Each fixture is a JSON file describing a zone's Cloudflare records plus a list of
queries with their **expected** answers (canonical RR-presentation strings). The
harness feeds the records through the *real* pipeline —

```
mockedge Cloudflare → cfapi client → mirror.BuildSnapshot → resolver.Resolve
```

— and compares the produced ANSWER/AUTHORITY RRsets (order-independent) plus the
RCODE and AA bit against the golden. There is no shortcut mock of the resolver; the
whole authoritative assembler, tunnel flattening, wildcard/ENT logic and vhost
redirect run for real.

## Running

```
make test                       # runs the goldens as part of the suite
go test ./internal/golden/      # just the goldens
SPLITDNS_GOLDEN_UPDATE=1 go test ./internal/golden/   # regenerate expected fields
```

After an update, **review the diff** before committing — the harness freezes
whatever the resolver currently emits, so a regression would otherwise be baked in.

## Fixture format

```jsonc
{
  "description": "...",
  "config": {
    "local_zones": ["example.com"],   // zones mirrored authoritatively
    "vhost_v4": "192.0.2.10",          // nginx redirect target (optional)
    "vhost_v6": "2001:db8::10",
    "vhosts": ["shop"]                  // extra single-label vhost owners (besides apex/www)
  },
  "zones": [ { "name": "...", "id": "...", "records": [ {type,name,content,proxied,ttl,priority} ] } ],
  "tunnel_addrs": { "app.example.com.": { "v4": [...], "v6": [...] } },  // what a *.cfargotunnel/*.tcpshield owner flattens to
  "reverse_zones": ["2.0.192.in-addr.arpa."],
  "queries": [ { "name","type", "outcome":"answer|forward|stub", "rcode","aa","answer":[...],"authority":[...] } ]
}
```

`outcome` defaults to `answer` (the resolver replies directly). Use `forward`/`stub`
to assert only the routing decision (no answer body).

## MUST-MATCH behaviors (locked by `testdata/`)

These are the behaviors the design deliberately guarantees:

- **Redirected apex/www/vhost → nginx** for address queries, while the apex's
  non-address RRsets (MX/TXT/…) stay real, and a non-vhost host serves its real A.
- **Excluded apex zones** (those listed in `[vhost] exclude_zones`) are *not*
  redirected — they serve their real records / flattened tunnel addresses.
- **Tunnel flattening**: a `*.cfargotunnel.com` / `*.tcpshield.com` CNAME is replaced
  by the owner's presented A/AAAA; the CNAME itself is never served.
- **IPv4-only tcpshield** flattens to A only; the AAAA query is a clean NODATA.
- **Wildcard synthesis** for absent names, and **ENT suppression**: a name that has a
  child but no RRset of its own yields NODATA, not a wildcard match.

## Behaviors deliberately NOT asserted here

A full `dig` capture against another resolver will differ here on purpose — these are
either added at a different layer or are intentional departures, so do **not** expect
resolver-level goldens to cover them, and partition real captures accordingly:

- **EDNS0/OPT + TC truncation** on the wire (added at the server layer; not in these
  resolver-level goldens).
- **RFC 8482 minimal-ANY** on the forward path.
- **DNS-rebinding filter**: private/blocked addresses are stripped from *forwarded*
  answers.
- **`.lan` 2-label fix-up** is not yet implemented (D13, deferred) — no golden for it.
- Synthesized **SOA serial**: these goldens run without the SOA poller, so the
  authority SOA carries the cold synthesized serial `1`. In production the mirror
  folds the real Cloudflare serial in (covered by `internal/mirror` tests).

## Real-capture goldens (operator)

The synthetic fixtures above use placeholder data and are committed. To verify true
byte-identical parity against your *actual* production resolver, drop captured fixtures
in `local/goldens/*.json` (gitignored, never packaged). `TestGoldens` runs them
automatically when that directory exists. Build each from your real zone export +
your resolver's captured answers, then trim the deliberately-not-asserted cases above.
