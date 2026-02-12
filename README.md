# lancer-hydra

A Rust clone of [THC-Hydra](https://github.com/vanhauser-thc/thc-hydra) — a
parallelized, multi-protocol network login brute-forcer — with a native desktop
GUI on top. Part of the Lancer ecosystem.

> ⚠️ For **authorized** security testing only (your own systems, pentest
> engagements with written permission, CTFs, and research). Online credential
> testing against systems you do not own is illegal in most jurisdictions.

## What it does

Given a target, a service, and a credential corpus, `lancer-hydra` spawns
concurrent workers that speak the live protocol and observe the real
success/failure signal — across **50+ protocols**: SSH, FTP/FTPS/SFTP,
Telnet, SMTP/IMAP/POP3 (+ TLS), HTTP(S) basic & form, RDP, VNC, SMB/SMB2,
LDAP(S), MySQL, PostgreSQL, MSSQL, Oracle, MongoDB, Redis, SNMP, MQTT, XMPP,
NNTP, IRC, SOCKS5, SIP, Cisco, and many more.

A bare `lancer-hydra` opens the **GUI**; `--cli` (or the `lancer-hydra-cli`
companion binary) exposes the full command-line surface for headless/CI use.

## Workspace

| Crate | Role |
|-------|------|
| `lancer-hydra` | CLI + native egui GUI binary |
| `hydra-core` | Orchestration engine: worker pools, queues, rate limiting, stop-on-found, restore |
| `hydra-protocols` | Per-protocol auth modules on a shared `Protocol` trait |
| `hydra-credlist` | Credential generation (`-l/-L/-p/-P/-C/-x/-e/-u`), lazy streaming |
| `hydra-output` | Text / JSON / jsonv1 / jsonl output, progress bar, restore-file IO |

Pure-Rust throughout: TLS via `native-tls` (SChannel on Windows), SSH via a
hand-rolled curve25519 + AES-CTR transport, crypto via RustCrypto. No C toolchain
or system libraries required.

## Build

### Windows
```
build.bat              :: -> build\lancer-hydra.exe
build-windows.bat      :: -> dist\lancer-hydra-windows-x86_64\bin\lancer-hydra.exe
```

### Linux / macOS
```bash
./build-linux.sh       # -> build/lancer-hydra   (--install adds a .desktop entry)
./build-mac.sh         # -> build/lancer-hydra   (+ .app via cargo-bundle if present)
```

### Requirements
- [Rust / Cargo](https://rustup.rs)
- (Windows) Visual C++ Build Tools 2019/2022

## Usage (CLI)

```bash
# single user, password list, stop on first hit
lancer-hydra --cli ssh://10.0.0.5 -l admin -P rockyou.txt -t 4 -f

# password spray across a user list
lancer-hydra --cli -L users.txt -p 'Spring2026!' -u smb://10.0.0.0

# HTTP POST form with a failure string
lancer-hydra --cli https-post-form://app.example.com \
  -L users.txt -P pass.txt \
  -m "/login:user=^USER^&pass=^PASS^:F=incorrect"

# JSON output
lancer-hydra --cli ftp://10.0.0.5 -l root -P pass.txt -b jsonv1 -o hits.json

# list a module's options, or run the parity self-test
lancer-hydra --cli -U ssh
lancer-hydra --cli --self-test
```

Run `lancer-hydra --cli --help` for the full flag list and `--help-format` for
the HTTP-form DSL.

## Tests

```bash
cargo test -p hydra-core --test upstream_parity
```

## License

MIT.
