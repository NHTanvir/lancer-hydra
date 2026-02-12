# RESEARCH DOSSIER: Hydra

> Part of the Lancer ecosystem. A Rust clone of THC-Hydra — parallelized network-protocol login brute-forcer. Build with Claude Code.
> Upstream: github.com/vanhauser-thc/thc-hydra (C, 9.x as of 2026, AGPL-3.0, ~10k stars). Long-standing van Hauser / THC project, active since 2001.

## Feature Parity Mandate

**`lancer-hydra` MUST ship with 100% feature parity to the upstream `hydra` tool — every flag, every subcommand, every output format, every probe / detector / module / payload / mode — plus a native Rust GUI on top.** This is not a "subset clone" — this is a full reimplementation in Rust with a GUI wrapper.

### Parity contract

- **Every CLI flag** documented in upstream `hydra --help` (and the long-form man page / docs) must work in `lancer-hydra --cli`.
- **Every output format** the upstream tool emits (text, JSON, XML, CSV, SARIF, custom formats) must round-trip through `lancer-hydra` byte-equivalent where the format allows.
- **Every probe / detector / module / category / payload class / built-in script** must be ported. None silently dropped.
- **Every supported target type / input format / protocol / file format / language** must work.
- **Every configuration option** (config files, env vars, registry / settings entries) must be honoured.
- **Companion binaries / sub-tools** in the upstream suite (if any) must each get their own binary in this workspace.

### GUI on top

Every feature reachable via CLI is also reachable from the GUI (see `## GUI (Lancer-standard pattern)` below). The GUI is not a subset — it is an alternate frontend over the same `core` library that the CLI uses. The `core` crate is GUI-agnostic.

### Verification

- The `## Granular feature catalog` section below enumerates everything that must be supported.
- Reference: `tests/upstream_parity/` will pin upstream flag combinations + canned outputs as parity tests. CI fails if any flag is unsupported or output diverges.
- A `lancer-hydra --self-test` flag runs the full parity matrix against a bundled reference target and prints pass/fail per upstream feature group.

### What is allowed to diverge

- **Performance** — Rust-native, async-first; we are allowed to be faster.
- **Memory footprint** — we are allowed to be smaller.
- **GUI** — entirely new (no upstream GUI to copy except where the upstream ships its own GUI like Zenmap / Wireshark UI / Ghidra GUI / jadx-gui — in which case our GUI must cover every panel the upstream GUI has, plus the Lancer-standard layout from `## GUI` below).
- **AI augmentation** — net-new (see `## AI augmentation ideas`).

### What is NOT allowed to diverge

- Any flag silently dropped, renamed, or behavior-changed compared to upstream.
- Any output format / record schema diverging in field names, types, or semantics.
- Any built-in script / detector / module not ported (mark explicitly with `[N/A — see note]` if genuinely impossible in Rust, e.g. NSE Lua scripts requiring features not in `mlua`).

## What it actually does

Hydra is a parallelized, multi-protocol online password cracker. Given a target (IP, hostname, or list), a service (SSH, FTP, HTTP-form, SMTP, RDP, SMB, etc.) and a credential corpus (`-l user -P passwords.txt`, `-L users.txt -p pass`, or `-C combo.txt`), it spawns N concurrent workers per target and tries every credential combination, stopping on first success or exhausting the list. Hydra differs from offline crackers (hashcat, john) because it talks the live protocol — it does a real TCP handshake, real protocol-level auth dialog, and observes the actual success/failure signal of the wire protocol. It's the **only tool of its kind** with this protocol breadth.

Hydra supports **50+ protocols**: SSH (v1 + v2), SSHKEY (private-key auth probing), FTP / FTPS / SFTP, Telnet / Telnets, POP3 / POP3S, IMAP / IMAPS, SMTP / SMTPS / SMTP-Enum (LOGIN/PLAIN/CRAM-MD5/DIGEST-MD5/NTLM), RDP (with NLA via FreeRDP3), VNC (RFB 3.3/3.7/3.8), SMB / SMB2 (NTLM + Kerberos, via libsmb2 + libsmbclient), LDAP2 / LDAP3 (with cram-md5 / digest-md5 sub-variants) / LDAPS, MySQL, PostgreSQL (custom port supported since 9.6), MSSQL, Oracle (listener + SID + DB), MongoDB (v1 + v2 since 9.7), Redis, SNMP (v1/v2c/v3), NNTP, Asterisk Call Manager, Cisco AAA / Cisco auth / Cisco enable / TACACS+, ICQ, IRC, XMPP, MQTT, CVS, SVN / Subversion, PCAnywhere, PCNFS, RTSP, Teamspeak (TS2), SAP/R3, HTTP-{HEAD,GET,POST,GET-FORM,POST-FORM}, HTTP-Proxy, HTTP-Proxy-Urlenum, HTTPS-{HEAD,GET,POST,GET-FORM,POST-FORM}, SOCKS5, AFP, NCP (NetWare), Firebird, S7-300 (Siemens PLC), RPCAP, Memcached, Adam-6500 (PLC), Radmin2, CobaltStrike (C2 framework, added 9.3), VMware-Auth (vmauthd), Rlogin, Rsh, Rexec, SIP, Time, and more.

**Why Hydra in Lancer.** Lancer's Intruder covers HTTP brute-force (sniper, pitchfork, cluster bomb in the proxy UI). Hydra covers **everything else** — every non-HTTP protocol you'd want to brute-force during a pentest. The Lancer-hydra clone is the "long tail" of online credential testing: SSH on misconfigured admin boxes, RDP on Internet-facing terminal servers, SMB on exposed file shares, MySQL/Postgres/MSSQL/Mongo/Redis on dev databases, LDAP/AD on identity providers, SMTP/IMAP on mail relays, SNMP on legacy network gear.

## Internal architecture

**Workspace** (`Cargo.toml`):
```
[workspace]
members = ["lancer-hydra", "hydra-core", "hydra-protocols", "hydra-credlist", "hydra-output"]
```

- **`lancer-hydra`** — CLI binary (`clap` 4.5). Parses 30+ flags, picks protocol module, calls `hydra-core::Engine`.
- **`hydra-core`** — Orchestration: target list, credential queue, worker pool, rate-limit, restore-file, global stop-on-found, results aggregation.
- **`hydra-protocols`** — Per-protocol modules. Each protocol is a Rust struct implementing the `Protocol` trait: `connect(target)`, `try_credential(user, pass)`, `disconnect()`. Async-only, built on `tokio`.
- **`hydra-credlist`** — Credential generation: `-l/-L/-p/-P` file loading, `-C` colon-combo, `-x` charset brute-force generator, `-e nsr` extra modes (null / same-as-login / reversed), default credential corpus per protocol (e.g., `admin:admin`, `root:root`, `cisco:cisco`).
- **`hydra-output`** — Text/JSON output (mirroring upstream's `-b text|json|jsonv1`), live progress bar, restore-file writer/reader.

**Key modules in `hydra-core/src/`:**
- `engine.rs` — `Engine` holds the worker pool, target queue, credential queue, results channel, restore state. Entry: `run(opts) -> Result<Vec<Hit>, Error>`.
- `target.rs` — Parses `-M target.txt` and CLI positional target, normalizes `proto://host:port` form. Resolves DNS once per target.
- `credqueue.rs` — Produces `(username, password)` tuples lazily from `-l/-L/-p/-P/-C/-x/-e`. Backed by a bounded `tokio::sync::mpsc` so memory stays flat on 10M-line wordlists.
- `worker.rs` — Per-target worker pool (`-t` tasks). Each worker pulls a credential from the queue, calls the protocol's `try_credential`, posts the result. Honors `-w` wait time, `-W` per-thread waittime, `-c` retry time.
- `ratelimit.rs` — `governor::RateLimiter` per-target + global. Default 16 tasks per target, 64 global, no rate cap — but rate cap available.
- `restore.rs` — On SIGINT (or `-I` ignore mode), writes `hydra.restore` JSON with `{target, protocol, cred_offset, hits_so_far}`. Resume via `hydra -R`.
- `stopon.rs` — `-f` first-found global stop; `-F` first-found per target.
- `results.rs` — `Hit { target, service, login, password, time_ms }` aggregator.

**Key modules in `hydra-protocols/src/`:**
- `traits.rs` — The `Protocol` trait:
  ```rust
  #[async_trait]
  pub trait Protocol: Send + Sync {
      fn name(&self) -> &'static str;
      fn default_port(&self) -> u16;
      fn supports_ssl(&self) -> bool { false }
      async fn try_credential(
          &self,
          target: &Target,
          user: &str,
          pass: &str,
          opts: &ModuleOpts,
      ) -> Result<AuthOutcome, ProtocolError>;
  }
  pub enum AuthOutcome { Success, Failure, Lockout, Unknown }
  ```
- `ssh.rs` — SSHv2 via `russh` (async) or `ssh2` (sync fallback). Password + keyboard-interactive auth. **Most popular module.**
- `ftp.rs`, `ftps.rs`, `sftp.rs` — `async-ftp` for plain, `rustls` for FTPS explicit/implicit, `russh-sftp` for SFTP.
- `telnet.rs` — `tokio::net::TcpStream` + raw IAC handling + login prompt matcher.
- `smtp.rs`, `smtps.rs` — `lettre` async or hand-rolled; supports LOGIN, PLAIN, CRAM-MD5, DIGEST-MD5, NTLM, OAuth2 (M365).
- `imap.rs`, `imaps.rs` — `async-imap` 0.10 with `LOGIN` and `AUTHENTICATE PLAIN`.
- `pop3.rs`, `pop3s.rs` — `async-pop3` (lighter than imap).
- `http_form.rs`, `https_form.rs` — `reqwest` async; supports the upstream `http[s]-{get,post}-form` mini-DSL: `path:body:F=failstring:H=Header:S=successstring:C=cookie_path`.
- `http_basic.rs`, `https_basic.rs` — basic-auth via `reqwest` with `Authorization: Basic`.
- `rdp.rs` — `rdp-rs` for the X.224/RDP negotiation; supports CredSSP/NLA, with NLA fall-back to legacy RDP if NLA disabled.
- `vnc.rs` — Raw `tokio::net::TcpStream` implementing RFB 3.3/3.7/3.8 auth (DES-encrypted challenge for legacy, plus VeNCrypt/TLS for modern).
- `smb.rs`, `smb2.rs` — Custom SMB client (no good Rust SMB crate yet; vendor `samba-client` C binding or hand-roll over `tokio` using `ntlmclient` for NTLMv2 + GSS-API for Kerberos).
- `ldap.rs`, `ldaps.rs` — `ldap3` 0.11 with `simple_bind` and `sasl_external_bind`.
- `mysql.rs` — `mysql_async` 0.34. Native + caching_sha2_password.
- `postgresql.rs` — `tokio-postgres` 0.7. md5 + scram-sha-256.
- `mssql.rs` — `tiberius` 0.12, SQL Server auth + Windows Auth via NTLM.
- `oracle.rs` — Hand-rolled TNS protocol over `tokio`; supports listener-bypass + SID enumeration + finalize auth. (No first-class Rust Oracle driver.)
- `mongodb.rs` — `mongodb` 3.x async driver, SCRAM-SHA-256.
- `redis.rs` — `redis` async + `AUTH` command, with ACL multi-user support since Redis 6.
- `snmp.rs` — Custom UDP probe; v1/v2c community strings, v3 with USM auth (HMAC-SHA / HMAC-MD5).
- `nntp.rs`, `irc.rs`, `xmpp.rs`, `mqtt.rs`, `cvs.rs`, `svn.rs`, `pcanywhere.rs`, `pcnfs.rs`, `rtsp.rs`, `asterisk.rs`, `cisco_enable.rs`, `cisco_aaa.rs`, `cisco_auth.rs`, `icq.rs`, `teamspeak.rs`, `sap_r3.rs`, `firebird.rs`, `memcached.rs`, `s7_300.rs`, `adam6500.rs`, `socks5.rs`, `afp.rs`, `ncp.rs`, `rlogin.rs`, `rsh.rs`, `rexec.rs`, `radmin2.rs`, `cobaltstrike.rs`, `vmauthd.rs`, `sshkey.rs`, `rpcap.rs`, `sip.rs`, `time.rs`, `http_proxy.rs`, `http_proxy_urlenum.rs` — protocol-specific small modules, each ~200-500 LOC.

**How protocols plug in (registry pattern):**
1. Each protocol struct implements `Protocol` trait.
2. `protocols/mod.rs` has a `inventory::collect!(&'static dyn Protocol)` registry — every protocol module submits itself.
3. CLI resolves `proto://host:port` → looks up by name, instantiates singleton, calls `try_credential` from worker threads.
4. `ModuleOpts` (HashMap<String, String>) carries per-module config like the HTTP-form DSL string.

**Concurrency model.**
- One **`Engine`** per Hydra invocation, holds N **target workers** (one task per target) plus a **global rate limiter**.
- Each target worker spawns `-t` (default 16) **credential workers** in a `tokio::task::JoinSet`.
- Each credential worker:
  1. Pulls `(user, pass)` from the per-target credqueue.
  2. Calls `protocol.try_credential()` with retries on transient errors.
  3. Records result in the shared `Results`.
  4. If `AuthOutcome::Success` and `-f` set, signals the engine `CancellationToken` (everyone exits).
- Per-target connection pooling (where the protocol allows session re-use — e.g., FTP, SMB), or forced reconnect (SSH, RDP). Pool size capped at `-t`.

## Granular feature catalog

**CLI flags (mirroring upstream `hydra -h`):**

| Flag | Long | Description |
|---|---|---|
| `-l LOGIN` | | Single login name |
| `-L FILE` | | File with logins, one per line |
| `-p PASS` | | Single password |
| `-P FILE` | | File with passwords, one per line |
| `-C FILE` | | Colon-separated `login:pass` combo file |
| `-x MIN:MAX:CHARSET` | | Charset brute-force generator. Preset CHARSETs: `a` lower, `A` upper, `1` digits, `aA1` mix, custom letters. |
| `-y` | | Disable use of letters in `-x` charset (digits-only fast path). |
| `-e nsr` | | Extra modes: `n` null pass, `s` pass = login, `r` reversed login. |
| `-u` | | Loop around users first, then passwords (default loops passwords first). |
| `-t N` | | Parallel tasks per target (default 16). |
| `-T N` | | Total parallel tasks across all targets (overrides per-target sum). |
| `-w N` | | Wait time per response (default 32 sec). |
| `-W N` | | Wait time between connects per thread (default 0). |
| `-c N` | | Wait time before retry on connection error (default 0). |
| `-s PORT` | | Override default port. |
| `-S` | | Use SSL/TLS variant. |
| `-O` | | Use SSLv2 (legacy). |
| `-K` | | Do not abort on module-option-error (continue). |
| `-q` | | Quiet — no warnings on connection errors. |
| `-v` / `-V` | | Verbose / show login:pass per attempt. |
| `-d` | | Debug — protocol-level trace. |
| `-f` / `-F` | | Stop on first found globally / per target. |
| `-M FILE` | | Target file (one host per line, optional `:port`). |
| `-m OPT` | | Module-specific options string (e.g., HTTP-form DSL). |
| `-o FILE` | | Output file for hits. |
| `-b FORMAT` | | Output format: `text`, `json`, `jsonv1`. |
| `-I` | | Ignore existing restore file. |
| `-R` | | Resume from `hydra.restore`. |
| `-h` / `-help-format` | | Help (general / module-format). |
| `-U` | | Service module usage details (`-U ssh`, `-U http-form-post`). |
| `-x check` | | Verify charset specification. |
| `-4` / `-6` | | Force IPv4 / IPv6. |
| `-a ADDRESS` | | (HTTP) Authentication-type override (basic / ntlm / digest) — added in 9.0. |
| `2=NNN` | | (HTTP-form DSL extra) Treat HTTP status code NNN (e.g., `302`, `403`) as success — added in 9.4 / 9.6. |
| `-help-format` | | Print HTTP-form mini-DSL syntax help and exit. |
| `-y` (extended) | | Force digits-only fast path for `-x` charset (no a-z / A-Z). |
| `--proxy URL` | | Single SOCKS5 / HTTP-CONNECT proxy URL (alias for upstream `HYDRA_PROXY` env). |
| `--proxy-auth U:P` | | Proxy credentials (alias for upstream `HYDRA_PROXY_AUTH` env). |
| `-l FILE -P FILE -u` | | (Lancer extension) Stream both lists from the same combo file in pair-iter mode. |
| `-l1` / `-L1` (Lancer) | | Mark a credential list as "user-spray safe" (one attempt per account per N minutes). |

**Credential generation modes (`hydra-credlist`):**
- `-l user -P passwords.txt` — single user × many passes (most common).
- `-L users.txt -p pass` — password spray (one pass × many users — defeats lockout policies).
- `-L users.txt -P passwords.txt` — full cartesian product.
- `-C combo.txt` — pre-paired `user:pass\n` (best for credential-stuffing from leaked databases).
- `-x 4:8:aA1` — charset brute-force, every 4-8 char alphanumeric (~80B combos — use offline crackers for anything beyond 6 chars).
- `-x 1:8:a` — every lower-alpha 1-8 chars.
- `-e nsr` — for each (login, pass) tuple, also try `(login, "")`, `(login, login)`, `(login, reverse(login))`.

**Upstream environment variables** (must be honoured for parity):
- `HYDRA_PROXY` — single proxy URL (e.g., `socks5://1.2.3.4:1080` or `connect://proxy:8080`).
- `HYDRA_PROXY_AUTH` — `user:pass` for the above.
- `HYDRA_PROXY_HTTP` — alternate HTTP-CONNECT proxy specifically for HTTP modules.

**Upstream companion binary: `xhydra`** — vanhauser-thc ships a GTK GUI named `xhydra` (the "X-front-end-to-hydra"). Lancer-hydra's egui GUI MUST cover every panel `xhydra` has: Target tab (single / list / file), Passwords tab (user / list / generate), Tuning tab (`-t`, `-w`, `-W`, `-c`, retry, proxy), Specific tab (per-protocol module options), Start tab (live output / save / stop). PCRE2 / FreeRDP3 / libsmbclient / libsmb2 build flags must be reflected in `lancer-hydra --self-test` output.

**Per-module options (`-m` flag).**
- `http-get-form` / `http-post-form` mini-DSL:
  - `"/login.php:user=^USER^&pass=^PASS^:F=incorrect"`
  - `:` separator. Three or four parts: `path : body : failure-condition [: extras]`.
  - `^USER^` / `^PASS^` substitution tokens.
  - `F=<str>` failure string (response body contains this → failed).
  - `S=<str>` success string (response body contains this → success; opposite of F).
  - `H=Name:Value` extra header (repeatable).
  - `C=/cookies-path` GET this path first to harvest cookies before login (CSRF setup).
  - `^CSRF_TOKEN^` token-grab from harvested cookies — `^CSRF[regex]:^` style.
- `smtp` / `smtp-enum` — `-m LOGIN` / `-m PLAIN` / `-m CRAM-MD5` / `-m DIGEST-MD5` / `-m NTLM` selects mechanism. M365 OAuth2 (XOAUTH2) supported with `-m XOAUTH2` and bearer token.
- `imap` — `-m PLAIN` / `-m LOGIN` / `-m CRAM-MD5` / `-m NTLM` / `-m XOAUTH2`.
- `ldap` — `-m simple` / `-m DIGEST-MD5` / `-m NTLM` / `-m CRAM-MD5`. DN binding: `cn=^USER^,ou=people,dc=acme,dc=com`.
- `rdp` — `-m DOMAIN\\` to specify Windows domain.
- `smb` — `-m Local` / `-m Domain\\` / `-m Both`. `-S` to disable SMB signing requirement check (some old shares).
- `cisco-enable` — `-m PASS` requires a logged-in session — usually chained after `cisco`.
- `oracle-listener` — `-m SID` to test listener accept; `-m TNS` to test post-listener.
- `snmp` — `-m v1` / `-m v2c` / `-m v3:authproto:authpass:privproto:privpass`.
- `http-proxy-urlenum` — feeds the proxy a list of URLs, looking for auth on a back-end.
- `mysql` — protocol version auto-detect; `-m USE=dbname` to verify against a specific DB.
- `ssh` — `-m KEX=algo,algo`, `-m HOSTKEY=ssh-rsa,ssh-ed25519`, `-m CIPHER=aes128-ctr,chacha20-poly1305` (legacy cipher support added 9.6).
- `sshkey` — `-m KEYFILE=path/to/id_rsa` (test private-key acceptance, not password).
- `mongodb` — `-m v2` to force MongoDB protocol v2 (added 9.7); `-m authdb=admin` for auth-db override.
- `postgresql` — `-m PORT=5433` for custom port override (added 9.6); `-m DB=postgres` for db selection.
- `firebird` — `-m DB=path/to/db.fdb` required.
- `sap-r3` — `-m CLIENT=000` SAP client number.
- `mqtt` — `-m v3.1.1` / `-m v5`; `-m TLS=1` for MQTTS.
- `kerberos-preauth` (9.5+) — `-m REALM=ACME.LOCAL` realm string; `-m ENCTYPE=aes256-cts-hmac-sha1-96`.
- `redis` — `-m ACL=username` for Redis 6+ ACL user (default user is `default`).
- `cobaltstrike` — `-m HASH=<MD5>` of the team-server credential staging string (added 9.3).
- `radmin2` — `-m DH=1` Diffie-Hellman style handshake forced.
- `vmauthd` — `-m TLS=0` to disable STARTTLS for legacy ESXi 5.x.
- `s7-300` / `adam6500` — `-m SLOT=2 -m RACK=0` Siemens PLC chassis addressing.
- `socks5` — `-m AUTH=user-pass`/`-m AUTH=gssapi` SOCKS5 auth method selection.

**Restore file format** (`hydra.restore`, JSON):
```json
{
  "version": "9.5-lancer",
  "command": "hydra -L u.txt -P p.txt ssh://1.2.3.4",
  "targets": [{"host":"1.2.3.4","port":22,"protocol":"ssh"}],
  "creds_done": 23145,
  "hits": [{"login":"admin","pass":"P@ss123"}],
  "credqueue_cursor": {"user_index":3,"pass_index":7714}
}
```
On SIGINT, atomically replace `hydra.restore` (write to `.restore.tmp` + `rename(2)`). **Upstream also auto-saves every 5 minutes** during a long run (not just on signal); Lancer-hydra mirrors this via a `tokio::time::interval(Duration::from_secs(300))` ticker. **No platform portability** — upstream restore files are NOT portable across endianness / architectures; Lancer-hydra fixes this by using JSON (vs upstream's packed binary), so the same `hydra.restore` resumes on Linux x86_64 → Windows ARM64 unchanged.

**Output schema** (`-b json` and `-b jsonv1`):
```json
{
  "generator": {"version":"9.7-lancer","built":"2026-05-30T...","binary":"lancer-hydra","arguments":"..."},
  "errormessages": [{"error":"timeout","host":"1.2.3.4"}],
  "success": true,
  "quantityfound": 2,
  "results": [
    {"host":"1.2.3.4","port":22,"service":"ssh","login":"admin","password":"P@ss","time_ms":420}
  ]
}
```
The `jsonv1` variant pins this schema (upstream-compatible); `json` may bump versions. Both formats truncate the output file on open (upstream behavior — change documented in 9.0). A NEW `-b jsonl` variant (Lancer extension) emits one JSON object per line as hits arrive (stream-friendly for log shippers).

## Engineering hard parts

1. **Each protocol is its own iceberg.** SSH alone is weeks: KEX algorithm negotiation, host-key verification (or skip), password auth vs keyboard-interactive, server-side login banner timing, slow ciphers, dropped half-open connections. **And SSH is the easy one** — RDP NLA requires CredSSP (SPNEGO + Kerberos + NTLMSSP nested in TLS), SMB2 requires NTLMv2 challenge computation, Oracle TNS is undocumented binary.

2. **Parallelism without melting the target.** 16 SSH tasks against one host is fine; 16 tasks against an OpenSSH 8.x with `MaxStartups 10:30:100` will see most connections rejected after a few seconds. Solution: per-host adaptive throttling — count rejections, halve concurrency on N rejections, recover slowly. Hydra upstream doesn't do this; Lancer-hydra should.

3. **False-positive detection.** The hard part of being a generic brute-forcer. Failure modes:
   - SSH server returns auth-success then immediately disconnects (some honeypots, some appliance UIs that don't actually accept the password).
   - Account locked after N tries: subsequent valid creds appear to fail — surface as `Lockout` not `Failure`.
   - HTTP login forms that return 200 for both success and failure, distinguished only by a "Welcome" string or a redirect to `/dashboard`. The DSL `F=` / `S=` flags are an attempt; in practice users often misconfigure them. Lancer-hydra should auto-detect: compare a known-bad credential's response to known-good's, surface the diff to the user, suggest the `F=` / `S=` string.
   - HTTPS forms that present a CAPTCHA after N failures — every credential after that "succeeds" superficially (200 OK with CAPTCHA page).
   - Per-protocol lockout responses (LDAP returns specific errors codes for account-disabled vs account-locked vs bad-password; SMTP returns 535 for auth-fail but some MTAs return 421 for rate-limit).

4. **Session re-use vs forced-reconnect.** FTP allows session re-use (LOGIN, fail, USER again, fail, USER again …) — Hydra reuses. SSH forces reconnect every credential (it's part of the protocol). Reconnecting is slow; some Hydra modules (FTP, IMAP) take advantage of reuse for 5-10× throughput improvement. Lancer-hydra: per-protocol `supports_reuse()` flag in the trait.

5. **Proxy chains for OPSEC.** A scan from your single IP gets you blocked instantly. Hydra supports `socks5://proxy/` upstream proxy. Lancer extends: chains of SOCKS5 + HTTP CONNECT, configurable rotation (round-robin, random, sticky-per-target). Use `fast-socks5` + custom dispatcher.

6. **Restore-file safe interrupt.** Worker is mid-credential when SIGINT arrives. The naive "kill all workers, write restore" loses ~16 credentials (they were in-flight; restore says "done" but actually unsent). Hydra upstream's solution: each worker writes its "last successfully sent" credential into a shared mutex-protected struct *before* sending the next; restore uses the minimum across all workers. Lancer-hydra: same pattern, using `Arc<Mutex<HashMap<WorkerId, CredentialOffset>>>`.

7. **HTTP-form CSRF tokens.** Modern login forms have hidden CSRF tokens. Hydra upstream's `C=/path` flag does the GET first to harvest a cookie, but the token is usually in the *response body*, not a cookie. Lancer-hydra: extend DSL with `^CSRF[regex]^` to extract from response body via regex, substitute into the next POST.

8. **Per-protocol default port + SSL variant.** `ssh` → 22 plain. `ftp` → 21 plain, `ftps` → 21 with explicit AUTH TLS, alt `-S` flag implicit SSL on 990. Each protocol has its own quirks; the trait's `default_port()` + `supports_ssl()` + per-module options resolves it.

9. **OAuth2 / modern auth.** M365 / Google Workspace no longer accept simple `IMAP LOGIN user pass`. They require OAuth2 (XOAUTH2 SASL). Hydra 9.5 added this. Lancer-hydra needs flag for bearer token / refresh token flow.

10. **IPv6 / dual stack.** Some services bind only IPv6 (Cisco IOSv-XE listener) or have different behavior IPv4 vs IPv6 (LDAP on Windows AD). `-4` / `-6` flag forces address-family selection.

## Rust library mapping

| Need | Crate | Version | Notes |
|---|---|---|---|
| Async runtime | `tokio` | 1.40 | Multi-threaded scheduler. |
| CLI | `clap` (derive) | 4.5 | 9 flag groups (input/cred/parallelism/timing/output/restore/network/protocol/debug). |
| TLS | `rustls` + `tokio-rustls` | 0.23 / 0.26 | For all `*S` protocols (https, ftps, ldaps, etc.). |
| SSH | `russh` | 0.45 | Pure-Rust async SSH. Password + keyboard-interactive auth. |
| SFTP | `russh-sftp` | 2.x | Built on russh. |
| FTP / FTPS | `async-ftp` or hand-roll | — | `async-ftp` is dormant; consider hand-rolling 500 LOC. |
| Telnet | hand-roll over `tokio::net::TcpStream` | — | Just IAC negotiation + login prompt regex. |
| SMTP | `lettre` async | 0.11 | All SASL mechanisms. |
| IMAP | `async-imap` | 0.10 | Includes IDLE; we only need AUTHENTICATE. |
| POP3 | `async-pop3` or hand-roll | — | Trivial; 200 LOC. |
| HTTP-form | `reqwest` | 0.12 | + `regex` for `^CSRF^` token substitution. |
| RDP | `rdp-rs` | 0.1.x | Old crate, lightly maintained. May need fork for NLA. |
| VNC | hand-roll RFB | — | ~600 LOC for 3.3/3.7/3.8. DES for legacy auth. |
| SMB / SMB2 | hand-roll or `smb` crate | — | `smb` crate is incomplete; consider C FFI to libsmb2. |
| LDAP / LDAPS | `ldap3` | 0.11 | Battle-tested; supports all SASL mechs. |
| MySQL | `mysql_async` | 0.34 | Native + caching_sha2_password. |
| PostgreSQL | `tokio-postgres` | 0.7 | md5 + scram-sha-256. |
| MSSQL | `tiberius` | 0.12 | SQL Server auth + Windows Auth (NTLM). |
| Oracle | hand-roll TNS | — | No Rust driver. Implement minimal TNS handshake + auth. |
| MongoDB | `mongodb` | 3.x | SCRAM-SHA-256. |
| Redis | `redis` async | 0.27 | AUTH command + ACL multi-user. |
| SNMP | `snmp` (custom) | — | Hand-roll ASN.1 BER; v1/v2c trivial, v3 USM with HMAC. |
| MQTT | `rumqttc` | 0.24 | CONNECT with username/password. |
| XMPP | `tokio-xmpp` | 4.x | SASL PLAIN / DIGEST-MD5 / SCRAM-SHA-1. |
| NTLM | `ntlmclient` | 0.5 | Used by SMB, MSSQL, LDAP NTLM SASL. |
| Kerberos | `cross-krb5` | 0.4 | For AD-integrated SMB/LDAP/MSSQL. |
| SOCKS5 proxy | `fast-socks5` | 0.10 | Async dialer; chains via custom dispatcher. |
| DNS | `hickory-resolver` | 0.24 | One resolve per target. |
| Rate limiting | `governor` | 0.6 | Per-target + global. |
| Wordlist line iter | `tokio::io::BufReader` | std | Stream `-P` files line-by-line. |
| Cancellation | `tokio_util::sync::CancellationToken` | 0.7 | `-f` / `-F` stop-on-found. |
| Restore-file JSON | `serde_json` | 1.0 | Atomic write via rename(2). |
| Output | `serde_json` + Display | — | Mirrors `-b text|json|jsonv1`. |
| Logging | `tracing` + `tracing-subscriber` | 0.1 / 0.3 | `-d` debug = trace level. |
| Errors | `eyre` | 0.6 | Per-module errors via `thiserror`. |
| Inventory pattern | `inventory` | 0.3 | Compile-time protocol registry. |

## Bug bounty workflows

**Found exposed SSH on a recon scan.** Hydra against the leaked-credential corpus (collections #1-5, Compilation of Many Breaches, RockYou2024). `lancer-hydra ssh://1.2.3.4 -L common-users.txt -P top-10k.txt -t 4 -f -o ssh_hits.json`.

**Found RDP open on Internet-facing host.** Try defaults first (`Administrator:`, `admin:admin`, `admin:P@ssw0rd`), then leaked combos. Heads-up on lockout — RDP NLA's "after 5 wrong, lock 30 min" is common. Use `-t 1 -W 5` (one task, 5 sec between attempts) to dodge.

**Found SMB share open with NULL session enabled.** Enumerate users via `enum4linux-ng`, then `lancer-hydra smb://1.2.3.4 -L enum-users.txt -P common-pass.txt -t 4 -m Local` for local-auth attempt, then `-m Domain\\CORP` for domain.

**Found SMTP server (MX scan).** Test for OPEN auth — useful for spoofed phishing. `lancer-hydra smtp://mail.target.com -l postmaster@target.com -p P@ssw0rd123 -e nsr -t 1` to test typo-squat creds.

**Vuln-confirm a credential-harvest finding.** Found a creds dump in a leaked Slack channel. Replay across protocols: SSH (jump server), VPN (admin panel), Confluence (SSO), MySQL (dev DB) — same credentials, multiple endpoints. Use `-C creds_dump.txt` on each protocol.

**Brute SMB shares for misconfigured admin shares.** Found `\\target\C$` accessible? Try `lancer-hydra smb://1.2.3.4 -l Administrator -P top-1k.txt -m Local` — if a local admin uses a guessable password, full system access.

**SMTP auth bypass.** Some misconfigured Exchange / Postfix servers allow `AUTH LOGIN` to succeed with wrong creds (logging bug), then reject the MAIL FROM. Detect: `lancer-hydra smtp://mail.acme.com -l fakeuser -P known-fake-passwords.txt` — if everything succeeds, log a finding.

**Credential-stuffing simulation (red team).** Test the corporate password policy by trying `Spring2026!`, `Summer2026!`, `Fall2026!`, company name + year, etc., across all known company employees.

**API tokens via HTTP-form.** Found a `/api/v1/auth` endpoint accepting JSON body? `lancer-hydra https-post-form://api.acme.com -L employees.txt -P leaked.txt -m "/api/v1/auth:{\"user\":\"^USER^\",\"pass\":\"^PASS^\"}:F=\"error\":H=Content-Type:application/json"`.

## 2024-2026 state

- **Hydra 9.7 (May 2024 — current upstream HEAD).** GTK3 support for `xhydra` GUI, MongoDB v2 protocol support (`-m v2`), POP3 buffer overflow fix (CVE-pending), continued PCRE2 cleanup.
- **Hydra 9.6 (Sep 2023).** FreeRDP v2 → v3 upgrade (NLA now works again on Windows Server 2022), GCC-15 compile fixes, HTTP 403 status as success code (`2=403`), SSH legacy cipher support (3des-cbc / blowfish-cbc for legacy network gear), PostgreSQL custom port option.
- **Hydra 9.5 (Jun 2023).** `-W` (per-thread wait) added to many modules that previously ignored it, HTTP-form proxy bug fixed, SMB2 libsmb2 success-detection fix, SMTP early-exit on auth-rejection, RDP detection of disabled accounts and empty-password accounts. Kerberos pre-authentication brute-force (`-m kerberos-preauth`) tracked as a planned extension. NOTE: Earlier draft of this doc claimed M365 OAuth2 (XOAUTH2) shipped in 9.5 — actually a Lancer-hydra net-new feature, not upstream.
- **Hydra 9.4 (Sep 2022).** Migration from PCRE → PCRE2 (older pcre/pcre3 deprecated in Debian 12+), RTSP server-handling fixes, HTTP 302-as-success code support via `2=302` parameter, `wait3()` → `waitpid()` for portability. Memcached / Adam-6500 PLC were actually shipped earlier (Memcached 9.0, Adam-6500 9.x). SIP module is NOT removed — still present, but flagged as unreliable.
- **Hydra 9.3 (Feb 2022).** New **CobaltStrike** module for C2 framework testing, Xcode compilation support, SSH IP-range support in `-M`, RDP empty-password detection, IPv6 addresses in `-M` mass-target file, HTTP-form proxy support, VNC/Cisco password-only protocols skip after first hit.
- **Hydra 9.2 (Mar 2021).** Rain mode `-r` removed (deprecated, inefficient), IPv6 Host header support in HTTP modules, GTK3 prep work on `xhydra`, MSYS Windows compat.
- **Hydra 9.1 (Jul 2020).** New `smb2` module via `libsmbclient` (handles SMB2 + SMB3), FreeRDP3 update, HTTP `F=` / `S=` string matching condition flags, `-K` flag for disabling reconnect retries (mass scanning speed-up), MongoDB v2 protocol initial, Oracle success-condition refinement.
- **Hydra 9.0 (May 2020).** RDP module fully rewritten on FreeRDP library, HTTP `a=` authentication-type selector (basic/ntlm/digest), JSON output now truncates output file on open, SVN memory leak fixes, Memcached protocol module added, MongoDB protocol module added.
- **Hydra 9.8-dev (in-tree as of 2026).** Heavy security-hardening sprint: buffer-overflow audit, null-terminator audit, deserialization vulnerability fixes across 20+ protocol parsers. Lancer-hydra is unaffected (Rust eliminates this class of bugs at the type level), but parity-tests must still ingest 9.8-dev's hardened response parsers since some behavior changed (e.g., strict line-length enforcement on POP3, SMTP). **9.8-dev specifics from CHANGES walk (2026-05-31 deep dive):**
  - Buffer overflows fixed in: `icq`, `irc`, `rlogin`, `rsh`, `rexec`, `smb1`, `ncp`, `pcanywhere`, `afp`, `snmp`, `ldap`, `socks5`, `oracle-listener`. Our test corpus for these modules needs the new malformed-response cases to ensure parity behaviour (silently drop, not crash).
  - NULL-deref hardening for `hydra_receive_line` callers across `pop3`, `smtp`, `http`, etc. The callers now must check for NULL before accessing fields — our Rust parsers' `Option<&str>` semantics already enforce this.
  - **HTTP-form cross-host redirect hardening.** When a login form redirects to a different host, hydra now clears the cookie jar AND drops operator-supplied `-H "Authorization: ..."` headers. Critical security fix — previously you could leak Bearer tokens to a different domain. Our `http_form.rs` must enforce the same: on cross-host 3xx, blank the cookie jar and strip auth headers.
  - **NTLM challenge-offset bounds.** Server-controlled offset in NTLM challenge can no longer exceed 4096 bytes — was a remote-server-controlled OOB read. Our `ntlmclient` wrapper enforces the limit.
  - **SMB1 short-reply uninit-stack fix.** Minimum 42-byte response now enforced; below that, the response is rejected as malformed. Our SMB1 module mirrors.
  - **SSH libssh runtime warning.** If linked libssh is below 0.10.6, hydra emits a runtime warning at startup citing CVE-2025-4877. Our build-time check verifies the `russh` version satisfies the equivalent fix.
- **2025 community trends.** Most hunters now use Hydra for non-HTTP (SSH/RDP/SMB/SQL/LDAP) and prefer Burp/Lancer Intruder for HTTP-form. Hydra's HTTP-form DSL is famously brittle (every config has subtle `F=` / `S=` traps). Lancer-hydra inherits the DSL but adds a UI-driven wizard.
- **2026 dev focus.** Active issues: better TLS cipher negotiation (some appliances reject modern ciphers); HTTP/2 form support (some apps now `POST /login` over h2); WebSocket auth (long-poll login). LSP integration for credential-list editing (autocomplete leaked-dump filenames).
- **Detection / evasion.** Most enterprise IDS/IPS (Cisco Firepower, Palo Alto Threat Prevention) signature-match Hydra by TCP fingerprint (specific TLS Client Hello extension order, specific SSH KEXINIT order). Lancer-hydra: randomize TLS / SSH fingerprints from a corpus of legit-browser/legit-client recordings.
- **Cloud-hosted brute-force.** Modern attack pattern: AWS Lambda + 16k IPs to rotate source IPs. Lancer-hydra (eventually) ships a `--cloud-rotate=lambda://my-fn` flag to dispatch credential attempts via a serverless backend, each attempt from a fresh source IP.

> **Research note — 2026-05-30.** Deep-dived upstream vs this plan. Corrections applied above: upstream's actual release dates are 9.7 (May 2024), 9.6 (Sep 2023), 9.5 (Jun 2023), 9.4 (Sep 2022), 9.3 (Feb 2022); the earlier draft conflated some Lancer-hydra net-new features (Kerberos-preauth, OAuth2/XOAUTH2, SOCKS5 chains, `-b json` schema) with upstream 9.5. These remain on the Lancer roadmap, but are now correctly marked as net-new. Added to the catalog: missing protocol modules (`adam6500`, `radmin2`, `vmauthd`, `cobaltstrike`, `sshkey`, `ncp`, `pcnfs`, `rlogin`, `rsh`, `rexec`, `svn`, `sip`, `time`, `http-proxy-urlenum`, `rpcap`, `cisco-aaa`, `cisco-auth`, telnets, smtp-enum, ldap2/ldap3 dialects); missing CLI flags (`-a` HTTP auth-type, `2=NNN` HTTP success-status, `-help-format`, `-y` extended digits-only); upstream env vars (`HYDRA_PROXY`, `HYDRA_PROXY_AUTH`, `HYDRA_PROXY_HTTP`); restore-file 5-min auto-save; `xhydra` upstream GTK GUI parity panels (Target/Passwords/Tuning/Specific/Start); upstream output schema fields (`generator`, `errormessages`, `success`, `quantityfound`, `results`); per-module `-m` options for ssh-cipher/sshkey/mongodb-v2/postgres-port/firebird-db/sap-client/mqtt-version/kerberos-realm/redis-acl/cobaltstrike-hash/radmin-dh/vmware-tls/siemens-rack/socks5-auth; build dependencies (PCRE2, FreeRDP3, libsmbclient, libsmb2). Existing roadmap, library mapping, and engineering hard-parts sections kept intact.
- **2025 community trends.** Most hunters now use Hydra for non-HTTP (SSH/RDP/SMB/SQL/LDAP) and prefer Burp/Lancer Intruder for HTTP-form. Hydra's HTTP-form DSL is famously brittle (every config has subtle `F=` / `S=` traps). Lancer-hydra inherits the DSL but adds a UI-driven wizard.
- **2026 dev focus.** Active issues: better TLS cipher negotiation (some appliances reject modern ciphers); HTTP/2 form support (some apps now `POST /login` over h2); WebSocket auth (long-poll login). LSP integration for credential-list editing (autocomplete leaked-dump filenames).
- **Detection / evasion.** Most enterprise IDS/IPS (Cisco Firepower, Palo Alto Threat Prevention) signature-match Hydra by TCP fingerprint (specific TLS Client Hello extension order, specific SSH KEXINIT order). Lancer-hydra: randomize TLS / SSH fingerprints from a corpus of legit-browser/legit-client recordings.
- **Cloud-hosted brute-force.** Modern attack pattern: AWS Lambda + 16k IPs to rotate source IPs. Lancer-hydra (eventually) ships a `--cloud-rotate=lambda://my-fn` flag to dispatch credential attempts via a serverless backend, each attempt from a fresh source IP.

## AI augmentation ideas

1. **Target-tailored wordlist generation.** Given target context (company name, CEO, founding year, locale), LLM generates a custom 5k-line wordlist mixing seasonal patterns (`Spring2026!`), company-derived (`AcmeCorp2026!`), keyboard-walks (`qwerty123`), and locale-specific (German umlauts for `.de` targets).
2. **Credential combination strategy.** "It's an SSO server bound to Active Directory" → prioritize email-format usernames (`first.last@acme.com`), domain-prefixed (`ACME\jdoe`), short usernames (`jdoe`). LLM picks the right order to minimize lockout risk.
3. **False-positive auto-detection.** After 100 attempts with 70 "successes," LLM compares response patterns and surfaces "the server is returning success on everything — probably a CAPTCHA wall after attempt 50; reset rate."
4. **Lockout-policy inference.** LLM reads first 10 failure responses, predicts lockout threshold ("seeing 'too many attempts' at #5 — set `-t 1 -W 600` to stay under"). Auto-recalibrates.
5. **Post-success guidance.** Got SSH? LLM suggests next steps: "you're on a Debian 11 — try LinPEAS for privesc, check `/etc/passwd` for other users, dump `~/.ssh/known_hosts` for lateral movement targets." Then suggests tools (Lancer's privesc helper).
6. **HTTP-form DSL synthesis.** User points at a login URL — Lancer fetches the form, identifies the username/password fields, hidden CSRF token, success/failure indicators by submitting one known-bad credential, and constructs the `-m` string automatically.
7. **Credential rotation strategy.** Given a 10M-line wordlist, LLM clusters into "likely common" (top 1k), "demographic-likely" (next 50k), "long-tail" (remainder). Try in tiers, abort tier if no hits in N attempts.
8. **Leaked-credential corpus search.** Have a list of target emails? Lancer indexes HaveIBeenPwned / leaked-dump corpora locally, surfaces "this email appears in dump X with hash Y; if it's plaintext, here's the password." Skip brute, go straight to credential.
9. **Honeypot detection.** "Every credential succeeds, even random base64 — this is a honeypot. Stop scanning." LLM scores response patterns for honeypot likelihood.
10. **Per-protocol guidance.** "Hit a Redis on port 6379 with no auth — there's no brute needed; here's `CONFIG SET dir /var/spool/cron/ + CONFIG SET dbfilename root + SET payload + SAVE` for RCE."

## Implementation phases (16-week roadmap)

### Phase 0 — Workspace skeleton + core (Week 1)
- `cargo new --bin lancer-hydra`, set up workspace with `hydra-core`, `hydra-protocols`, `hydra-credlist`, `hydra-output`.
- `Protocol` trait, `AuthOutcome` enum.
- `Engine` with target + cred queue + `tokio::task::JoinSet` worker pool.
- CLI: `lancer-hydra <proto>://<host> -l user -p pass` does one attempt, prints result.

### Phase 1 — Credential generation (Week 2)
- `hydra-credlist`: file readers (`-L`, `-P`), single (`-l`, `-p`), combo (`-C`).
- Charset generator `-x MIN:MAX:CHARSET`.
- Extra modes `-e nsr`.
- Loop order `-u`.
- Lazy stream backed by `tokio::sync::mpsc` (bounded 1024 entries).

### Phase 2 — First 4 protocols: SSH, FTP, HTTP-basic, SMTP (Week 3-4)
- `ssh.rs` via `russh` — password auth; handle host-key skip; keyboard-interactive fallback.
- `ftp.rs` — hand-rolled minimal client (USER/PASS); session reuse for throughput.
- `http_basic.rs` / `https_basic.rs` via `reqwest`.
- `smtp.rs` — `lettre` async; LOGIN + PLAIN mechs.
- Regression tests against Docker images (`linuxserver/openssh-server`, `bytemark/vsftpd`, `mailcatcher`).

### Phase 3 — 6 more protocols: IMAP, POP3, MySQL, PostgreSQL, RDP, Telnet (Week 5-7)
- `imap.rs` / `pop3.rs` — async-imap, async-pop3.
- `mysql.rs` / `postgresql.rs` — auth handshake only (don't run query post-auth).
- `rdp.rs` — `rdp-rs`; NLA toggle.
- `telnet.rs` — IAC negotiate, login-prompt match.
- Reaches "10 core protocols" milestone; covers ~80% of pentest usage.

### Phase 4 — HTTP-form DSL + CSRF (Week 8)
- `http_form.rs` / `https_form.rs`: parse `-m "path:body:F=fail:S=success:C=cookie-path:H=header"`.
- `^USER^` / `^PASS^` substitution.
- `C=` cookie harvest GET.
- `^CSRF[regex]^` body extraction.
- Tests: WordPress login, Joomla admin, DVWA brute-page.

### Phase 5 — Parallelism + rate + restore (Week 9)
- `-t` per-target, `-T` global; `governor` rate limiting.
- Restore-file write on SIGINT (atomic rename).
- `-R` resume.
- `-f` / `-F` stop-on-found via `CancellationToken`.
- Per-target adaptive throttling (auto-detect lockout/rejection patterns).

### Phase 6 — SMB / LDAP / VNC / SNMP (Week 10-11)
- `smb.rs` — vendor `libsmb2` C binding via `bindgen`; NTLMv2 + Kerberos auth.
- `ldap.rs` — `ldap3` simple bind + SASL bind.
- `vnc.rs` — hand-roll RFB 3.3-3.8; DES challenge for legacy.
- `snmp.rs` — hand-roll v1/v2c community; v3 USM with HMAC.

### Phase 7 — 10 more protocols (Week 12-13)
- MSSQL (`tiberius`), Oracle (TNS hand-roll), MongoDB (`mongodb`), Redis (`redis`), MQTT (`rumqttc`), XMPP (`tokio-xmpp`), Cisco enable, NNTP, IRC, CVS.

### Phase 8 — OPSEC: proxies + fingerprint randomization (Week 14)
- SOCKS5 single + chain (`fast-socks5` + custom dispatcher).
- HTTP CONNECT proxy.
- TLS/SSH fingerprint randomization (corpus of real client fingerprints, rotate per connection).
- Per-target source-IP binding (for multi-IP boxes).

### Phase 9 — Output + JSON + observability (Week 15)
- Text output `<protocol>:<host>:<port>:<login>:<password>`.
- JSON output `-b json` (newline-delimited per hit) + `-b jsonv1` (compatible with upstream jsonv1 schema).
- Progress bar via `indicatif`.
- `tracing-subscriber` JSON logging for `-d` debug.

### Phase 10 — 10 long-tail protocols + AI panel (Week 16)
- SFTP, FTPS, IMAPS, POP3S, LDAPS, SMTPS (just `-S` flag wrappers).
- Asterisk, Teamspeak, SAP/R3, Firebird, Memcached, S7-300 (stub modules — testable but rarely used).
- AI panel: paste a leaked-creds dump filename + target context, AI generates a tailored shortlist of credentials to try first.
- Hits "50+ protocol" milestone.

---

## GUI (Lancer-standard pattern)

`lancer-hydra` ships as a **native GUI application** by default. The CLI surface listed in `## Granular feature catalog` is still available behind a `--cli` flag (or via the `lancer-hydra-cli` companion binary), but the **plain `lancer-hydra` invocation opens a native desktop window**, matching every other tool in the Lancer ecosystem. No terminal-only mode.

### Framework

Pure-Rust GUI stack — no JavaScript, no Node, single static binary:

| Crate | Role |
|-------|------|
| `eframe` | Cross-platform window + event loop wrapper around `egui` |
| `egui` | Immediate-mode UI widgets (panels, tables, forms, menus, drag-and-drop) |
| `egui_extras` | Sortable tables, image loaders, syntax highlighting, date pickers |
| `egui_plot` | Charts, graphs, timelines (histograms, activity meters, progress) |
| `rfd` | Native file/folder pickers (open file, save dialog) |
| `directories` | Per-OS config dir (`~/.config/lancer-hydra/`, `%APPDATA%\lancer-hydra\`, etc.) |
| `image` | Screenshot / preview rendering inside egui |
| `arboard` | Clipboard read/write for "copy result" actions |
| `muda` | Native menu bar (Linux / macOS / Windows) |
| `egui-notify` | Toast notifications |

Optional dark/light theme persisted to `lancer-hydra-config.json` via `serde_json`.

### Window layout

Three-pane layout matching the Lancer mothership GUI:

```
┌─────────────────────────────────────────────────────────────────────┐
│  File   Tools   Settings   Help                              [≡]    │
├──────────┬────────────────────────────────────────┬─────────────────┤
│          │                                        │                 │
│  Inputs  │           Main view                    │  Detail pane    │
│  / jobs  │  (table of results / source tree /     │  (full record / │
│  / scope │   findings list / packet list / etc.)  │   bytes / src / │
│          │                                        │   remediation)  │
│          │                                        │                 │
├──────────┴────────────────────────────────────────┴─────────────────┤
│  Status: idle           Items: 0          [Open]  [Run]  [Export]   │
└─────────────────────────────────────────────────────────────────────┘
```

- **Left sidebar (200-300px)** — inputs / queued jobs / scope / target list. Drag-and-drop accepted.
- **Center pane (flexible)** — primary result view appropriate to the tool (table for findings, tree for hierarchical data, code editor for source).
- **Right pane (300-400px, collapsible)** — full detail of the currently-selected item.
- **Top menu bar** — File (Open / Save / Export / Recent / Quit), Tools (per-tool actions), Settings (theme, fonts, integrations), Help (About / Docs).
- **Bottom status bar** — current activity, item counts, primary action buttons.

### Cross-tool integration with Lancer + the other 29 clones

Every Lancer-clone GUI exposes a small local HTTP server on a port auto-allocated at launch (`127.0.0.1:<port>`, written to `%TEMP%/lancer-hydra.port`):

- The main Lancer GUI discovers running tools by scanning `%TEMP%/lancer-*.port` and lists them in its sidebar.
- Right-clicking any item in any tool can "Send to <other Lancer tool>" — the receiving tool fetches the payload via its own HTTP endpoint.
- A future "Lancer Hub" tray shell can launch / focus any of the 30 GUIs from one menu.
- HTTP endpoints exposed:
  - `GET  /v1/state` — current jobs / progress
  - `POST /v1/import` — accept a target / file / record from another Lancer tool
  - `GET  /v1/export?format=json|csv|sarif|markdown` — pull the current result set in a portable format

### Async work + responsiveness

- Long-running scans run on a Tokio task pool; the GUI thread only renders.
- Progress propagates via `crossbeam::channel` from worker → UI.
- A `Stop` button cancels in-flight work via a `CancellationToken`.
- All file I/O / network I/O / subprocess work goes through async channels — the egui thread never blocks.

### Build output

The existing `build.bat` / `build-windows.bat` / `build-linux.sh` already produce a single binary. With `eframe` linked, the same binary is the GUI app.

- Windows: `build\lancer-hydra.exe` (double-click opens the GUI window).
- Linux: `build/lancer-hydra` (also installable as a `.desktop` entry via `build-linux.sh --install`).
- macOS: `build/lancer-hydra` (bundled into `lancer-hydra.app` via `cargo-bundle` in the `build-mac.sh` companion).

For CI / headless / scripting, pass `--cli` to fall through to the CLI surface from `## Granular feature catalog`.

## Build Setup (Lancer-standard pattern)

This clone follows the same build pattern as the main Lancer project — single `.exe` output via `build.bat` on Windows, `.so/elf` via `build-linux.sh` on Linux.

### Project layout

```
lancer-hydra/
├── Cargo.toml              # single-crate Rust project
├── Cargo.lock              # committed (binary, not library)
├── src/
│   └── main.rs             # entry point (scaffold)
├── build.bat               # Windows build → build/lancer-hydra.exe
├── build-windows.bat       # Windows packaged dist build → dist/lancer-hydra-windows-x86_64/
├── build-linux.sh          # Linux build → build/lancer-hydra
├── .gitignore              # plan.md (local-only) + target/ + build/ + dist/
├── README.md               # public-facing (pushed to GitHub)
└── plan.md                 # this file (gitignored — local blueprint, never pushed)
```

### Build commands

**Windows (double-click `build.bat`):**
```
build.bat
```
Produces `build\lancer-hydra.exe`. Pauses at end so the window stays open.

**Windows (packaged dist):**
```
build-windows.bat
```
Produces `dist\lancer-hydra-windows-x86_64\bin\lancer-hydra.exe` plus LICENSE/README — ready to zip.

**Linux / macOS:**
```bash
./build-linux.sh
```
Produces `build/lancer-hydra`.

### Requirements
- Rust toolchain (https://rustup.rs)
- Windows: Visual C++ Build Tools 2019/2022 (needed by some crates)

### CI

The build pattern is intentionally identical across Lancer and all 19 clones, so a single Jenkins/GitHub Actions matrix can build everything by calling `build-windows.bat` or `build-linux.sh` per repo.
