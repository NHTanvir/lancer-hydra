//! Built-in default credential corpus, consulted only when the user supplies no
//! `-l/-L/-p/-P/-C/-x` source. Mirrors the plan's "default credential corpus per
//! protocol" (e.g. `admin:admin`, `root:root`, `cisco:cisco`).

/// Well-known default `(login, password)` pairs to try for `scheme` when no
/// explicit credential source was given. Returns owned strings so the caller can
/// store them in [`crate::CredConfig`].
pub fn default_creds(scheme: &str) -> Vec<(String, String)> {
    let s = scheme.to_ascii_lowercase();
    let specific: &[(&str, &str)] = match s.as_str() {
        "ssh" | "ssh2" | "sftp" => &[
            ("root", "root"),
            ("root", "toor"),
            ("root", "admin"),
            ("admin", "admin"),
            ("pi", "raspberry"),
        ],
        "ftp" | "ftps" => &[
            ("anonymous", "anonymous"),
            ("anonymous", ""),
            ("ftp", "ftp"),
            ("admin", "admin"),
        ],
        "mysql" => &[("root", ""), ("root", "root"), ("root", "mysql")],
        "postgres" | "postgresql" => &[("postgres", "postgres"), ("postgres", "")],
        "mssql" => &[("sa", ""), ("sa", "sa"), ("sa", "password")],
        "mongodb" | "mongo" => &[("admin", "admin"), ("root", "root")],
        "redis" => &[("default", ""), ("default", "redis")],
        "cisco" | "cisco-enable" | "cisco-aaa" => &[
            ("cisco", "cisco"),
            ("admin", "admin"),
            ("admin", "cisco"),
        ],
        "vnc" => &[("", "password"), ("", "admin")],
        "snmp" => &[("", "public"), ("", "private")],
        "rdp" | "smb" | "smb2" => &[
            ("administrator", ""),
            ("administrator", "admin"),
            ("administrator", "password"),
        ],
        "telnet" | "telnets" => &[("root", "root"), ("admin", "admin")],
        _ => &[],
    };
    let generic: &[(&str, &str)] = &[
        ("admin", "admin"),
        ("admin", "password"),
        ("root", "root"),
        ("administrator", "administrator"),
    ];

    let mut out: Vec<(String, String)> = Vec::new();
    for (u, p) in specific.iter().chain(generic.iter()) {
        let pair = (u.to_string(), p.to_string());
        if !out.contains(&pair) {
            out.push(pair);
        }
    }
    out
}
