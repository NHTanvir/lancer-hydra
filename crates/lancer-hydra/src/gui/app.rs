//! The egui application: a three-pane Lancer layout whose left sidebar carries
//! the xhydra-parity tabs (Target / Passwords / Tuning / Specific / Start).

use std::time::Duration;

use eframe::egui;
use tokio_util::sync::CancellationToken;

use hydra_core::{
    build_target, load_target_file, parse_target, registry, CharsetSpec, CredConfig, EngineOptions,
    ExtraModes, IpPref, LoginSource, ModuleOpts, OutputFormat, PassSource,
};
use hydra_output::Hit;

use super::server::{self, Shared};

#[derive(PartialEq, Eq, Clone, Copy)]
enum Tab {
    Target,
    Passwords,
    Tuning,
    Specific,
    Start,
}

pub struct HydraApp {
    tab: Tab,
    // Target tab
    target: String,
    service: String,
    target_file: String,
    use_target_file: bool,
    port: String,
    ssl: bool,
    ipv4: bool,
    ipv6: bool,
    // Passwords tab
    login: String,
    login_file: String,
    use_login_file: bool,
    pass: String,
    pass_file: String,
    use_pass_file: bool,
    combo: String,
    use_combo: bool,
    charset: String,
    use_charset: bool,
    digits_only: bool,
    e_null: bool,
    e_same: bool,
    e_rev: bool,
    users_first: bool,
    // Tuning tab
    tasks: String,
    total_tasks: String,
    wait_response: String,
    wait_connect: String,
    retry_wait: String,
    rate: String,
    stop_global: bool,
    stop_target: bool,
    // Specific tab
    module_opts: String,
    http_auth: String,
    proxy: String,
    proxy_auth: String,
    sslv2: bool,
    show_attempts: bool,
    verbose: bool,
    quiet: bool,
    debug: bool,
    // Start tab / output
    output: String,
    format: String,
    resume: bool,
    ignore_restore: bool,
    restore_file: String,
    // runtime
    services: Vec<String>,
    selected: Option<usize>,
    shared: Shared,
    cancel: Option<CancellationToken>,
    last_error: String,
}

impl HydraApp {
    pub fn new(cc: &eframe::CreationContext<'_>, shared: Shared) -> Self {
        cc.egui_ctx.set_visuals(egui::Visuals::dark());
        let mut services: Vec<String> = registry::names().iter().map(|s| s.to_string()).collect();
        services.sort();
        Self {
            tab: Tab::Target,
            target: String::new(),
            service: "ssh".to_string(),
            target_file: String::new(),
            use_target_file: false,
            port: String::new(),
            ssl: false,
            ipv4: false,
            ipv6: false,
            login: String::new(),
            login_file: String::new(),
            use_login_file: false,
            pass: String::new(),
            pass_file: String::new(),
            use_pass_file: false,
            combo: String::new(),
            use_combo: false,
            charset: "1:4:a".to_string(),
            use_charset: false,
            digits_only: false,
            e_null: false,
            e_same: false,
            e_rev: false,
            users_first: false,
            tasks: "16".to_string(),
            total_tasks: String::new(),
            wait_response: "32".to_string(),
            wait_connect: "0".to_string(),
            retry_wait: "0".to_string(),
            rate: String::new(),
            stop_global: false,
            stop_target: false,
            module_opts: String::new(),
            http_auth: String::new(),
            proxy: String::new(),
            proxy_auth: String::new(),
            sslv2: false,
            show_attempts: false,
            verbose: false,
            quiet: false,
            debug: false,
            output: String::new(),
            format: "text".to_string(),
            resume: false,
            ignore_restore: false,
            restore_file: "hydra.restore".to_string(),
            services,
            selected: None,
            shared,
            cancel: None,
            last_error: String::new(),
        }
    }

    fn build_options(&self) -> Result<EngineOptions, String> {
        let scheme = self.service.trim().to_string();
        if scheme.is_empty() {
            return Err("select a service".into());
        }
        let proto = registry::resolve(&scheme).ok_or_else(|| format!("unknown service: {scheme}"))?;
        let default_port = proto.default_port();
        let port_override = self.port.trim().parse::<u16>().ok();
        let ip_pref = if self.ipv6 {
            IpPref::V6
        } else if self.ipv4 {
            IpPref::V4
        } else {
            IpPref::Any
        };

        let raw_hosts: Vec<String> = if self.use_target_file && !self.target_file.trim().is_empty() {
            load_target_file(std::path::Path::new(self.target_file.trim()))
                .map_err(|e| format!("target file: {e}"))?
        } else if !self.target.trim().is_empty() {
            vec![self.target.trim().to_string()]
        } else {
            return Err("enter a target host or a target file".into());
        };
        let targets: Vec<_> = raw_hosts
            .iter()
            .map(|h| {
                let parsed = parse_target(h);
                build_target(&parsed, &scheme, default_port, port_override, self.ssl, ip_pref)
            })
            .collect();

        let logins = if self.use_login_file && !self.login_file.trim().is_empty() {
            LoginSource::File(self.login_file.trim().into())
        } else if !self.login.trim().is_empty() {
            LoginSource::Single(self.login.trim().to_string())
        } else {
            LoginSource::None
        };
        let passwords = if self.use_pass_file && !self.pass_file.trim().is_empty() {
            PassSource::File(self.pass_file.trim().into())
        } else if self.use_charset {
            let mut spec = CharsetSpec::parse(self.charset.trim()).map_err(|e| format!("charset: {e}"))?;
            if self.digits_only {
                spec.charset = ('0'..='9').collect();
            }
            PassSource::Charset(spec)
        } else if !self.pass.is_empty() {
            PassSource::Single(self.pass.clone())
        } else {
            PassSource::None
        };
        let mut cred = CredConfig {
            logins,
            passwords,
            combo: if self.use_combo && !self.combo.trim().is_empty() {
                Some(self.combo.trim().into())
            } else {
                None
            },
            extra: ExtraModes {
                null: self.e_null,
                same: self.e_same,
                reversed: self.e_rev,
            },
            users_first: self.users_first,
            defaults: Vec::new(),
        };
        // No explicit credential source → fall back to the per-protocol defaults.
        if !cred.has_explicit_creds() {
            cred.defaults = hydra_core::default_creds(&scheme);
        }

        let mut module_opts = ModuleOpts::from_raw(if self.module_opts.trim().is_empty() {
            None
        } else {
            Some(self.module_opts.trim().to_string())
        });
        module_opts.wait_response = Duration::from_secs(self.wait_response.parse().unwrap_or(32));
        module_opts.wait_connect = Duration::from_secs(self.wait_connect.parse().unwrap_or(0));
        module_opts.retry_wait = Duration::from_secs(self.retry_wait.parse().unwrap_or(0));
        module_opts.ssl = self.ssl;
        module_opts.sslv2 = self.sslv2;
        module_opts.verbose = self.verbose;
        module_opts.quiet = self.quiet;
        module_opts.debug = self.debug;
        if !self.http_auth.trim().is_empty() {
            module_opts.http_auth = Some(self.http_auth.trim().to_string());
        }
        if !self.proxy.trim().is_empty() {
            module_opts.proxy = Some(self.proxy.trim().to_string());
        }
        if !self.proxy_auth.trim().is_empty() {
            module_opts.proxy_auth = Some(self.proxy_auth.trim().to_string());
        }

        let output_format = OutputFormat::parse(&self.format).unwrap_or(OutputFormat::Text);
        let restore_path = if self.restore_file.trim().is_empty() {
            std::path::PathBuf::from("hydra.restore")
        } else {
            std::path::PathBuf::from(self.restore_file.trim())
        };

        Ok(EngineOptions {
            scheme,
            targets,
            cred,
            module_opts,
            tasks_per_target: self.tasks.parse().unwrap_or(16),
            total_tasks: self.total_tasks.trim().parse().ok(),
            stop_on_first_global: self.stop_global,
            stop_on_first_target: self.stop_target,
            rate_per_sec: self.rate.trim().parse().ok(),
            output_file: if self.output.trim().is_empty() {
                None
            } else {
                Some(self.output.trim().into())
            },
            output_format,
            restore_path,
            ignore_restore: self.ignore_restore,
            resume: self.resume,
            quiet: self.quiet,
            verbose: self.verbose,
            show_attempts: self.show_attempts,
            command_line: format!("lancer-hydra (gui) {}://{}", self.service, self.target),
            queue_buffer: 1024,
            external_cancel: None,
        })
    }

    fn start_run(&mut self) {
        match self.build_options() {
            Ok(mut opts) => {
                self.last_error.clear();
                let token = CancellationToken::new();
                opts.external_cancel = Some(token.clone());
                self.cancel = Some(token);
                if let Ok(mut s) = self.shared.lock() {
                    s.running = true;
                    s.status = "running…".into();
                    s.hits.clear();
                }
                self.selected = None;
                let shared = self.shared.clone();
                std::thread::spawn(move || {
                    let rt = match tokio::runtime::Runtime::new() {
                        Ok(r) => r,
                        Err(e) => {
                            if let Ok(mut s) = shared.lock() {
                                s.running = false;
                                s.status = format!("runtime error: {e}");
                            }
                            return;
                        }
                    };
                    let result = rt.block_on(hydra_core::Engine::run(opts));
                    if let Ok(mut s) = shared.lock() {
                        match result {
                            Ok(hits) => {
                                s.status = format!("done — {} found", hits.len());
                                s.hits = hits;
                            }
                            Err(e) => s.status = format!("error: {e}"),
                        }
                        s.running = false;
                    }
                });
            }
            Err(e) => self.last_error = e,
        }
    }

    fn stop_run(&mut self) {
        if let Some(t) = &self.cancel {
            t.cancel();
        }
    }
}

impl eframe::App for HydraApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Snapshot shared state once per frame.
        let (running, hits, status) = match self.shared.lock() {
            Ok(s) => (s.running, s.hits.clone(), s.status.clone()),
            Err(_) => (false, Vec::new(), String::new()),
        };

        egui::TopBottomPanel::top("menubar").show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                ui.menu_button("File", |ui| {
                    if ui.button("Export results…").clicked() {
                        export_hits(&hits);
                        ui.close_menu();
                    }
                    if ui.button("Quit").clicked() {
                        std::process::exit(0);
                    }
                });
                ui.menu_button("Tools", |ui| {
                    if ui.button("Run").clicked() {
                        self.start_run();
                        ui.close_menu();
                    }
                    if ui.button("Stop").clicked() {
                        self.stop_run();
                        ui.close_menu();
                    }
                });
                ui.menu_button("Settings", |ui| {
                    if ui.button("Light theme").clicked() {
                        ctx.set_visuals(egui::Visuals::light());
                        ui.close_menu();
                    }
                    if ui.button("Dark theme").clicked() {
                        ctx.set_visuals(egui::Visuals::dark());
                        ui.close_menu();
                    }
                });
                ui.menu_button("Help", |ui| {
                    ui.label(format!("lancer-hydra {}-lancer", env!("CARGO_PKG_VERSION")));
                    ui.label(format!("{} protocol modules", hydra_protocols_count()));
                    ui.label(format!("{} schemes (incl. aliases)", registry::names().len()));
                    ui.label("Rust THC-Hydra clone — Lancer ecosystem");
                    ui.label("Authorized security testing only.");
                });
            });
        });

        egui::SidePanel::left("inputs").default_width(330.0).show(ctx, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.selectable_value(&mut self.tab, Tab::Target, "Target");
                ui.selectable_value(&mut self.tab, Tab::Passwords, "Passwords");
                ui.selectable_value(&mut self.tab, Tab::Tuning, "Tuning");
                ui.selectable_value(&mut self.tab, Tab::Specific, "Specific");
                ui.selectable_value(&mut self.tab, Tab::Start, "Start");
            });
            ui.separator();
            egui::ScrollArea::vertical().show(ui, |ui| match self.tab {
                Tab::Target => self.tab_target(ui),
                Tab::Passwords => self.tab_passwords(ui),
                Tab::Tuning => self.tab_tuning(ui),
                Tab::Specific => self.tab_specific(ui),
                Tab::Start => self.tab_start(ui),
            });
        });

        egui::SidePanel::right("detail").default_width(340.0).show(ctx, |ui| {
            ui.heading("Detail");
            ui.separator();
            match self.selected.and_then(|i| hits.get(i)) {
                Some(h) => {
                    ui.label(format!("Host:     {}", h.host));
                    ui.label(format!("Port:     {}", h.port));
                    ui.label(format!("Service:  {}", h.service));
                    ui.label(format!("Login:    {}", h.login));
                    ui.label(format!("Password: {}", h.password));
                    ui.label(format!("Time:     {} ms", h.time_ms));
                }
                None => {
                    ui.label("Select a result to see details.");
                }
            }
        });

        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(if running { "Status: running" } else { "Status: idle" });
                ui.separator();
                ui.label(format!("Items: {}", hits.len()));
                ui.separator();
                ui.label(status.as_str());
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if running {
                        if ui.button("Stop").clicked() {
                            self.stop_run();
                        }
                    } else if ui.button("Run").clicked() {
                        self.start_run();
                    }
                    if ui.button("Export").clicked() {
                        export_hits(&hits);
                    }
                });
            });
            if !self.last_error.is_empty() {
                ui.colored_label(egui::Color32::LIGHT_RED, self.last_error.as_str());
            }
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Results");
            ui.separator();
            self.results_table(ui, &hits);
        });

        if running {
            ctx.request_repaint_after(Duration::from_millis(250));
        }
    }
}

impl HydraApp {
    fn tab_target(&mut self, ui: &mut egui::Ui) {
        ui.label("Single Target (host, host:port, or proto://host)");
        ui.text_edit_singleline(&mut self.target);
        ui.checkbox(&mut self.use_target_file, "Target list (-M file)");
        ui.horizontal(|ui| {
            ui.text_edit_singleline(&mut self.target_file);
            if ui.button("…").clicked() {
                if let Some(p) = rfd::FileDialog::new().pick_file() {
                    self.target_file = p.display().to_string();
                    self.use_target_file = true;
                }
            }
        });
        ui.separator();
        ui.label("Service / protocol");
        egui::ComboBox::from_label("service")
            .selected_text(self.service.clone())
            .show_ui(ui, |ui| {
                for s in &self.services {
                    ui.selectable_value(&mut self.service, s.clone(), s.as_str());
                }
            });
        ui.horizontal(|ui| {
            ui.label("Port (-s)");
            ui.text_edit_singleline(&mut self.port);
        });
        ui.checkbox(&mut self.ssl, "Use SSL/TLS (-S)");
        ui.horizontal(|ui| {
            ui.checkbox(&mut self.ipv4, "IPv4 (-4)");
            ui.checkbox(&mut self.ipv6, "IPv6 (-6)");
        });
    }

    fn tab_passwords(&mut self, ui: &mut egui::Ui) {
        ui.label("Login (-l)");
        ui.text_edit_singleline(&mut self.login);
        ui.checkbox(&mut self.use_login_file, "Login list (-L)");
        ui.horizontal(|ui| {
            ui.text_edit_singleline(&mut self.login_file);
            if ui.button("…").clicked() {
                if let Some(p) = rfd::FileDialog::new().pick_file() {
                    self.login_file = p.display().to_string();
                    self.use_login_file = true;
                }
            }
        });
        ui.separator();
        ui.label("Password (-p)");
        ui.text_edit_singleline(&mut self.pass);
        ui.checkbox(&mut self.use_pass_file, "Password list (-P)");
        ui.horizontal(|ui| {
            ui.text_edit_singleline(&mut self.pass_file);
            if ui.button("…").clicked() {
                if let Some(p) = rfd::FileDialog::new().pick_file() {
                    self.pass_file = p.display().to_string();
                    self.use_pass_file = true;
                }
            }
        });
        ui.separator();
        ui.checkbox(&mut self.use_combo, "Combo file (-C login:pass)");
        ui.horizontal(|ui| {
            ui.text_edit_singleline(&mut self.combo);
            if ui.button("…").clicked() {
                if let Some(p) = rfd::FileDialog::new().pick_file() {
                    self.combo = p.display().to_string();
                    self.use_combo = true;
                }
            }
        });
        ui.separator();
        ui.checkbox(&mut self.use_charset, "Brute-force charset (-x MIN:MAX:CHARSET)");
        ui.text_edit_singleline(&mut self.charset);
        ui.checkbox(&mut self.digits_only, "Digits only (-y)");
        ui.separator();
        ui.label("Extra modes (-e)");
        ui.horizontal(|ui| {
            ui.checkbox(&mut self.e_null, "null (n)");
            ui.checkbox(&mut self.e_same, "=login (s)");
            ui.checkbox(&mut self.e_rev, "reversed (r)");
        });
        ui.checkbox(&mut self.users_first, "Loop users first / spray (-u)");
    }

    fn tab_tuning(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("Tasks per target (-t)");
            ui.text_edit_singleline(&mut self.tasks);
        });
        ui.horizontal(|ui| {
            ui.label("Total tasks (-T)");
            ui.text_edit_singleline(&mut self.total_tasks);
        });
        ui.horizontal(|ui| {
            ui.label("Response wait (-w, s)");
            ui.text_edit_singleline(&mut self.wait_response);
        });
        ui.horizontal(|ui| {
            ui.label("Connect wait (-W, s)");
            ui.text_edit_singleline(&mut self.wait_connect);
        });
        ui.horizontal(|ui| {
            ui.label("Retry wait (-c, s)");
            ui.text_edit_singleline(&mut self.retry_wait);
        });
        ui.horizontal(|ui| {
            ui.label("Rate cap (/s)");
            ui.text_edit_singleline(&mut self.rate);
        });
        ui.separator();
        ui.checkbox(&mut self.stop_global, "Stop on first found, global (-f)");
        ui.checkbox(&mut self.stop_target, "Stop on first found, per target (-F)");
    }

    fn tab_specific(&mut self, ui: &mut egui::Ui) {
        ui.label("Module options (-m) — e.g. the HTTP-form DSL");
        ui.text_edit_multiline(&mut self.module_opts);
        ui.separator();
        ui.horizontal(|ui| {
            ui.label("HTTP auth type (-a)");
            ui.text_edit_singleline(&mut self.http_auth);
        });
        ui.separator();
        ui.label("Proxy (OPSEC)");
        ui.horizontal(|ui| {
            ui.label("Proxy URL (--proxy)");
            ui.text_edit_singleline(&mut self.proxy);
        });
        ui.horizontal(|ui| {
            ui.label("Proxy auth user:pass");
            ui.text_edit_singleline(&mut self.proxy_auth);
        });
        ui.small("e.g. socks5://127.0.0.1:1080 or connect://proxy:8080");
        ui.separator();
        ui.label("Flags");
        ui.checkbox(&mut self.sslv2, "SSLv2 legacy (-O)");
        ui.checkbox(&mut self.show_attempts, "Show login:pass per attempt (-V)");
        ui.checkbox(&mut self.verbose, "Verbose (-v)");
        ui.checkbox(&mut self.quiet, "Quiet (-q)");
        ui.checkbox(&mut self.debug, "Debug — wire trace (-d)");
        ui.separator();
        if let Some(p) = registry::resolve(&self.service) {
            ui.label(format!("{} (port {})", p.name(), p.default_port()));
            ui.label(p.usage());
        }
    }

    fn tab_start(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("Output file (-o)");
            ui.text_edit_singleline(&mut self.output);
            if ui.button("…").clicked() {
                if let Some(p) = rfd::FileDialog::new().save_file() {
                    self.output = p.display().to_string();
                }
            }
        });
        ui.label("Output format (-b)");
        egui::ComboBox::from_label("format")
            .selected_text(self.format.clone())
            .show_ui(ui, |ui| {
                for f in ["text", "json", "jsonv1", "jsonl"] {
                    ui.selectable_value(&mut self.format, f.to_string(), f);
                }
            });
        ui.separator();
        ui.label("Restore / resume");
        ui.horizontal(|ui| {
            ui.label("Restore file (--restore-file)");
            ui.text_edit_singleline(&mut self.restore_file);
        });
        ui.checkbox(&mut self.resume, "Resume from restore file (-R)");
        ui.checkbox(&mut self.ignore_restore, "Ignore existing restore file (-I)");
        ui.separator();
        ui.horizontal(|ui| {
            if ui.button("▶ Run").clicked() {
                self.start_run();
            }
            if ui.button("■ Stop").clicked() {
                self.stop_run();
            }
        });
    }

    fn results_table(&mut self, ui: &mut egui::Ui, hits: &[Hit]) {
        egui::ScrollArea::vertical().show(ui, |ui| {
            egui::Grid::new("results")
                .striped(true)
                .num_columns(6)
                .show(ui, |ui| {
                    ui.strong("Host");
                    ui.strong("Port");
                    ui.strong("Service");
                    ui.strong("Login");
                    ui.strong("Password");
                    ui.strong("ms");
                    ui.end_row();
                    for (i, h) in hits.iter().enumerate() {
                        if ui
                            .selectable_label(self.selected == Some(i), h.host.as_str())
                            .clicked()
                        {
                            self.selected = Some(i);
                        }
                        ui.label(h.port.to_string());
                        ui.label(h.service.as_str());
                        ui.label(h.login.as_str());
                        ui.label(h.password.as_str());
                        ui.label(h.time_ms.to_string());
                        ui.end_row();
                    }
                });
        });
    }
}

fn export_hits(hits: &[Hit]) {
    if let Some(path) = rfd::FileDialog::new()
        .set_file_name("lancer-hydra-results.json")
        .save_file()
    {
        let json = serde_json::to_string_pretty(hits).unwrap_or_else(|_| "[]".into());
        let _ = std::fs::write(path, json);
    }
}

fn hydra_protocols_count() -> usize {
    registry::names().len()
}

// Re-export the launcher used by `mod.rs`.
pub fn launch() {
    let shared: Shared = std::sync::Arc::new(std::sync::Mutex::new(server::ServerState::default()));
    server::spawn(shared.clone());
    let options = eframe::NativeOptions::default();
    let _ = eframe::run_native(
        "lancer-hydra",
        options,
        Box::new(move |cc| Ok(Box::new(HydraApp::new(cc, shared.clone())) as Box<dyn eframe::App>)),
    );
}
