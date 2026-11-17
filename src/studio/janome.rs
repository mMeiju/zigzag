//! The Janome window: sending the design to a Janome machine (the
//! IJ521 and other dotCustomizer models) over Wi-Fi. A worker thread
//! does the talking so the UI never waits on the network: it finds
//! machines, reads one's status, and uploads the design as JEF, the
//! way the app does. The Skitch window's smaller cousin — a Janome
//! takes a file and sews it, with none of the Skitch's conversation.

use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::app::Studio;
use crate::theme::{pal_ui, space};
use eframe::egui::{self, RichText};
use zigzag::machine::janome as wire;

/// What the worker last learned, and what it's doing.
#[derive(Clone, Default)]
pub struct Shared {
    /// The command in flight ("Finding machines", "Sending"…).
    pub doing: Option<&'static str>,
    /// The machines discovery found.
    pub found: Vec<wire::Machine>,
    /// The status last read, and the address it came from.
    pub status: Option<(String, wire::Status)>,
    /// What happened, in order.
    pub log: Vec<String>,
    /// The last command that didn't work.
    pub problem: Option<String>,
}

enum Cmd {
    Discover,
    Status(String),
    Send(String, Vec<u8>),
}

/// The Janome window's state.
pub struct JanomePanel {
    /// The window is showing.
    pub open: bool,
    /// The machine's address: typed, or picked from discovery.
    pub host: String,
    tx: Option<Sender<Cmd>>,
    pub shared: Arc<Mutex<Shared>>,
}

impl Default for JanomePanel {
    fn default() -> Self {
        JanomePanel {
            open: false,
            host: String::new(),
            tx: None,
            shared: Default::default(),
        }
    }
}

impl JanomePanel {
    pub fn snapshot(&self) -> Shared {
        self.shared.lock().unwrap().clone()
    }

    /// Hand the worker a command (starting it the first time).
    fn ask(&mut self, cmd: Cmd, ctx: &egui::Context) {
        if self.tx.is_none() {
            let (tx, rx) = mpsc::channel();
            let shared = self.shared.clone();
            let ctx = ctx.clone();
            let _ = std::thread::Builder::new()
                .name("janome".into())
                .spawn(move || worker(rx, shared, ctx));
            self.tx = Some(tx);
        }
        if let Some(tx) = &self.tx {
            let _ = tx.send(cmd);
        }
    }

    pub fn discover(&mut self, ctx: &egui::Context) {
        self.begin("Finding machines");
        self.ask(Cmd::Discover, ctx);
    }

    pub fn check_status(&mut self, ctx: &egui::Context) {
        if self.host.trim().is_empty() {
            return;
        }
        self.begin("Reading the status");
        self.ask(Cmd::Status(self.host.trim().to_string()), ctx);
    }

    /// Upload JEF bytes to the machine at the panel's address.
    pub fn send(&mut self, jef: Vec<u8>, ctx: &egui::Context) {
        if self.host.trim().is_empty() {
            return;
        }
        self.begin("Sending");
        self.ask(Cmd::Send(self.host.trim().to_string(), jef), ctx);
    }

    fn begin(&mut self, doing: &'static str) {
        let mut s = self.shared.lock().unwrap();
        s.doing = Some(doing);
        s.problem = None;
    }
}

fn worker(rx: Receiver<Cmd>, shared: Arc<Mutex<Shared>>, ctx: egui::Context) {
    while let Ok(cmd) = rx.recv() {
        {
            let mut s = shared.lock().unwrap();
            s.doing = None;
            match cmd {
                Cmd::Discover => match wire::discover(Duration::from_secs(2)) {
                    Ok(machines) => {
                        if machines.is_empty() {
                            s.log.push("No machines answered.".into());
                        }
                        for m in &machines {
                            s.log.push(format!("Found {} at {}", m.name, m.ip));
                        }
                        s.found = machines;
                    }
                    Err(e) => {
                        s.problem = Some(format!("Finding machines didn't work: {e:#}"));
                    }
                },
                Cmd::Status(host) => match wire::status(&host, Duration::from_secs(3)) {
                    Ok(st) => s.status = Some((host, st)),
                    Err(e) => {
                        s.problem = Some(format!("Reading the status didn't work: {e:#}"));
                    }
                },
                Cmd::Send(host, jef) => {
                    match wire::send_jef(&host, &jef, Duration::from_secs(15)) {
                        Ok(lines) => {
                            for line in lines {
                                s.log.push(line);
                            }
                            s.log.push(format!("Sent {} bytes to {host}.", jef.len()));
                        }
                        Err(e) => {
                            s.problem = Some(format!("Sending didn't work: {e:#}"));
                        }
                    }
                }
            }
        }
        ctx.request_repaint();
    }
}

impl Studio {
    /// The Janome window, when the Send action opened it.
    pub fn janome_window(&mut self, ctx: &egui::Context) {
        if !self.janome.open {
            return;
        }
        let s = self.janome.snapshot();
        let busy = s.doing.is_some();
        let title = self
            .machine_label()
            .filter(|_| self.janome_target())
            .unwrap_or_else(|| "Janome".to_string());
        let mut open = true;
        let screen = ctx.content_rect();
        egui::Window::new(format!("{title} — Wi-Fi"))
            .id(egui::Id::unique("janome-window"))
            .title_frame(crate::theme::title_frame(ctx))
            .open(&mut open)
            .collapsible(false)
            .resizable(true)
            .default_size([430.0, 430.0])
            .min_width(360.0)
            .default_pos(egui::Pos2::new(screen.right() - 450.0, 70.0))
            .show(ctx, |ui| {
                let p = pal_ui(ui);
                ui.spacing_mut().item_spacing.y = space::S;

                // The machine: an address, typed or found.
                ui.label(RichText::new("Machine").size(12.5));
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.janome.host)
                            .hint_text("192.168.1.50")
                            .desired_width(170.0),
                    );
                    if ui
                        .add_enabled(!busy, egui::Button::new("Find"))
                        .on_hover_text("Look for Janome machines on the local network")
                        .clicked()
                    {
                        self.janome.discover(ctx);
                    }
                    if busy {
                        ui.add(egui::Spinner::new().size(12.0));
                        ui.label(s.doing.unwrap_or(""));
                    }
                });
                for m in &s.found {
                    let picked = self.janome.host.trim() == m.ip;
                    if ui
                        .selectable_label(picked, format!("{} — {}", m.name, m.ip))
                        .clicked()
                    {
                        self.janome.host = m.ip.clone();
                    }
                }

                crate::theme::hline(ui);

                // How it's doing.
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(
                            !busy && !self.janome.host.trim().is_empty(),
                            egui::Button::new("Check status"),
                        )
                        .clicked()
                    {
                        self.janome.check_status(ctx);
                    }
                    if let Some((host, st)) = &s.status
                        && host == self.janome.host.trim()
                    {
                        ui.label(format!(
                            "{} ({}), stitch {}, needle {:.1} × {:.1} mm",
                            st.name(),
                            st.code,
                            st.stitch_position,
                            st.x as f64 / 10.0,
                            st.y as f64 / 10.0
                        ));
                    }
                });

                crate::theme::hline(ui);

                // The design, and sending it.
                let b = self.design.bounds();
                let (w_mm, h_mm) = (b.width() / 10.0, b.height() / 10.0);
                let hoop = self
                    .machine()
                    .filter(|_| self.janome_target())
                    .map(|p| p.default_hoop);
                let too_big = hoop.is_some_and(|(hw, hh)| w_mm > hw || h_mm > hh);
                ui.label(format!(
                    "Design: {:.1} × {:.1} mm, {} stitches",
                    w_mm,
                    h_mm,
                    self.design.stitch_count()
                ));
                if too_big && let Some((hw, hh)) = hoop {
                    ui.label(
                        RichText::new(format!(
                            "Too big for the {:.0} × {:.0} mm hoop.",
                            hw, hh
                        ))
                        .color(p.error),
                    );
                }
                let can_send = !busy
                    && !self.janome.host.trim().is_empty()
                    && !self.design.blocks.is_empty()
                    && !too_big;
                if ui
                    .add_enabled(can_send, egui::Button::new("Send to machine"))
                    .on_hover_text("Upload the design as JEF, the way the dotCustomizer app does")
                    .clicked()
                {
                    match zigzag::formats::write_format_with(
                        &self.design,
                        "jef",
                        &self.doc.settings.export_options(),
                    ) {
                        Ok(bytes) => self.janome.send(bytes, ctx),
                        Err(_) => {
                            self.janome.shared.lock().unwrap().problem =
                                Some("The design could not be written as JEF.".into());
                        }
                    }
                }
                if let Some(problem) = &s.problem {
                    ui.label(RichText::new(problem).color(p.error));
                }

                if !s.log.is_empty() {
                    crate::theme::hline(ui);
                    egui::ScrollArea::vertical()
                        .id_salt("janome-log")
                        .auto_shrink([false, true])
                        .max_height(130.0)
                        .show(ui, |ui| {
                            for line in &s.log {
                                ui.label(RichText::new(line).size(12.0).color(p.secondary));
                            }
                        });
                }
            });
        if !open {
            self.janome.open = false;
        }
    }
}
