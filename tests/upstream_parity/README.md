# Upstream parity fixtures

This directory pins the upstream `hydra` feature surface that `lancer-hydra` must
match. CI fails if any flag is unsupported or output diverges.

## What runs the matrix

- **In-process matrix** — `crates/hydra-core/tests/upstream_parity.rs`. Asserts
  every protocol scheme resolves through the registry, the credential modes
  generate correctly, and every flag-derived option type parses. Run with:

  ```
  cargo test -p hydra-core --test upstream_parity
  ```

- **Runtime self-test** — `lancer-hydra --self-test` prints the registered module
  matrix and the build-feature parity table (PCRE2 / FreeRDP3 / libsmbclient /
  libsmb2 are `N/A` because they are reimplemented in pure Rust).

## Canned-output fixtures (this directory)

`<service>/<case>.cmd` + `<service>/<case>.expected` pairs pin a flag combination
and its expected `-b jsonv1` document for a bundled reference target. The schema
that must round-trip byte-equivalent is:

```json
{
  "generator": { "version": "...", "built": "...", "binary": "lancer-hydra", "arguments": "..." },
  "errormessages": [ { "error": "...", "host": "..." } ],
  "success": true,
  "quantityfound": 0,
  "results": [ { "host": "...", "port": 0, "service": "...", "login": "...", "password": "...", "time_ms": 0 } ]
}
```

## Coverage contract

Every upstream protocol module is ported (see `REQUIRED_SCHEMES` in the test).
Modules whose full auth crypto is reserved (RDP CredSSP, SMB NTLMv2 session
setup, Oracle O5LOGIN, and the proprietary binaries — ICQ, TeamSpeak, SAP R/3,
S7-300, ADAM-6500, AFP, NCP, Radmin2, CobaltStrike, rpcap, pcAnywhere, PC-NFS)
register and probe reachability but return `Unknown` rather than asserting a
false hit. They are tracked here so the matrix stays honest about coverage.
