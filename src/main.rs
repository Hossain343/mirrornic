#![windows_subsystem = "windows"]
mod engine;

use eframe::egui::{self, Color32, RichText};
use std::sync::mpsc::{self, TryRecvError};
use std::sync::{Arc, Mutex};
use std::time::Duration;

type Starting = mpsc::Receiver<Result<engine::Engine, String>>;

#[derive(Clone, PartialEq)]
struct Cfg {
    name: String,
    route: String,
    exit: Option<u32>,
}

struct App {
    name: String,
    route: String,
    ifaces: Vec<(u32, String)>,
    exit_sel: Option<u32>,
    applied: Cfg,
    engine: Option<engine::Engine>,
    starting: Option<Starting>,
    result: Arc<Mutex<String>>,
    note: String,
}

fn clean_name(s: &str) -> String {
    let c: String = s
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect();
    if c.is_empty() { "MirrorNIC".into() } else { c }
}

fn clean_route(s: &str) -> String {
    let c: String = s.chars().filter(|c| c.is_ascii_digit() || *c == '.' || *c == '/' || *c == ',').collect();
    if c.is_empty() { "0.0.0.0/0".into() } else { c }
}

impl App {
    fn cfg(&self) -> Cfg {
        Cfg { name: clean_name(&self.name), route: clean_route(&self.route), exit: self.exit_sel }
    }
    fn start(&mut self) {
        let c = self.applied.clone();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(engine::start(&c.name, &c.route, c.exit));
        });
        self.starting = Some(rx);
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _f: &mut eframe::Frame) {
        let polled = self.starting.as_ref().map(|rx| rx.try_recv());
        match polled {
            Some(Ok(Ok(e))) => {
                self.note = e.note.clone();
                self.engine = Some(e);
                self.starting = None;
            }
            Some(Ok(Err(m))) => {
                *self.result.lock().unwrap() = m;
                self.starting = None;
            }
            Some(Err(TryRecvError::Empty)) => ctx.request_repaint_after(Duration::from_millis(100)),
            Some(Err(_)) => self.starting = None,
            None => {}
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(8.0);
                let busy = self.starting.is_some();
                let on = self.engine.is_some();
                let (txt, col) = if busy {
                    ("...", Color32::from_rgb(200, 150, 0))
                } else if on {
                    ("ON", Color32::from_rgb(30, 160, 60))
                } else {
                    ("OFF", Color32::from_rgb(120, 120, 120))
                };
                let b = egui::Button::new(RichText::new(txt).size(30.0).color(Color32::WHITE))
                    .fill(col)
                    .min_size(egui::vec2(200.0, 60.0));
                if ui.add(b).clicked() && !busy {
                    if on {
                        self.engine = None;
                        self.note.clear();
                    } else {
                        self.applied = self.cfg();
                        self.start();
                    }
                }
                ui.add_space(12.0);
                ui.label("Adapter name");
                ui.text_edit_singleline(&mut self.name);
                ui.add_space(6.0);
                ui.label("Route (comma separated)");
                ui.text_edit_singleline(&mut self.route);
                ui.add_space(6.0);
                ui.label("Exit interface");
                let cur = match self.exit_sel {
                    None => "Auto".to_string(),
                    Some(i) => self
                        .ifaces
                        .iter()
                        .find(|x| x.0 == i)
                        .map(|x| format!("{} ({})", x.1, x.0))
                        .unwrap_or_else(|| format!("#{}", i)),
                };
                ui.horizontal(|ui| {
                    egui::ComboBox::from_id_salt("exit").selected_text(cur).width(190.0).show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.exit_sel, None, "Auto");
                        for (i, n) in self.ifaces.clone() {
                            ui.selectable_value(&mut self.exit_sel, Some(i), format!("{} ({})", n, i));
                        }
                    });
                    if ui.button("Refresh").clicked() {
                        self.ifaces = engine::list_ifaces();
                    }
                });
                ui.add_space(10.0);
                if ui.button(RichText::new("Apply").size(18.0)).clicked() && !busy {
                    let c = self.cfg();
                    self.name = c.name.clone();
                    self.route = c.route.clone();
                    if c != self.applied {
                        let was_on = self.engine.take().is_some();
                        self.applied = c;
                        if was_on {
                            self.start();
                        }
                    }
                }
                ui.add_space(10.0);
                if on && !self.note.is_empty() {
                    ui.label(
                        RichText::new(format!("exit \u{2192} {}", self.note))
                            .size(13.0)
                            .color(Color32::from_rgb(90, 150, 230)),
                    );
                    ui.add_space(4.0);
                }
                if ui.button("Test").clicked() {
                    let r = self.result.clone();
                    let c = ctx.clone();
                    let sel = self.cfg().exit;
                    *r.lock().unwrap() = "...".into();
                    std::thread::spawn(move || {
                        let ip = engine::probe_report(sel);
                        *r.lock().unwrap() = ip;
                        c.request_repaint();
                    });
                }
                ui.add_space(6.0);
                let t = self.result.lock().unwrap().clone();
                ui.label(RichText::new(t).size(15.0));
            });
        });
    }
}

fn main() -> eframe::Result {
    let opts = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([330.0, 520.0])
            .with_resizable(false),
        ..Default::default()
    };
    eframe::run_native(
        "Mirror NIC",
        opts,
        Box::new(|_cc| {
            let c = Cfg { name: "MirrorNIC".into(), route: "0.0.0.0/0".into(), exit: None };
            Ok(Box::new(App {
                name: c.name.clone(),
                route: c.route.clone(),
                ifaces: engine::list_ifaces(),
                exit_sel: None,
                applied: c,
                engine: None,
                starting: None,
                result: Arc::new(Mutex::new(String::new())),
                note: String::new(),
            }))
        }),
    )
}
