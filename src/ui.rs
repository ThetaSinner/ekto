use eframe::egui;
use std::sync::{Arc, RwLock};

#[derive(Default, Debug, Clone, PartialEq)]
pub struct KeyForApproval {
    pub key: String,
    pub for_app_id: String,
}

#[derive(Debug)]
pub enum UiEvent {
    KeyApproved(KeyForApproval),
}

#[derive(Clone)]
pub struct MyApp {
    pub keys_for_approval: Arc<RwLock<Vec<KeyForApproval>>>,
    pub send_ui_event: tokio::sync::mpsc::Sender<UiEvent>,
}

impl MyApp {
    pub fn new(send_ui_event: tokio::sync::mpsc::Sender<UiEvent>) -> Self {
        Self {
            send_ui_event,
            keys_for_approval: Arc::new(RwLock::new(Vec::new())),
        }
    }
}

impl eframe::App for MyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Keys for approval");
            ui.vertical(|ui| {
                let keys = { self.keys_for_approval.read().unwrap().clone() };

                if keys.is_empty() {
                    ui.label("No keys awaiting approval at the moment");
                }
                for key in keys {
                    ui.horizontal(|ui| {
                        ui.label(format!(
                            "For app [{}], key is [{}]",
                            key.for_app_id, key.key
                        ));
                        if ui.button("Reject").clicked() {
                            if let Ok(mut keys) = self.keys_for_approval.try_write() {
                                keys.retain(|k| k != &key);
                                tracing::info!("Rejected key: {:?}", key);
                            }
                        }
                        if ui.button("Approve").clicked() {
                            if let Err(e) = self.send_ui_event.try_send(UiEvent::KeyApproved(key)) {
                                tracing::error!("Failed to send UI event: {}", e);
                            }
                        }
                    });
                }
            });
            // ui.horizontal(|ui| {
            //     let name_label = ui.label("Your name: ");
            //     ui.text_edit_singleline(&mut self.name)
            //         .labelled_by(name_label.id);
            // });
            // ui.add(egui::Slider::new(&mut self.age, 0..=120).text("age"));
            // if ui.button("Increment").clicked() {
            //     self.age += 1;
            // }
            // ui.label(format!("Hello '{}', age {}", self.name, self.age));
        });
    }
}

pub async fn run_ui(app: MyApp, mut require_ui: tokio::sync::mpsc::Receiver<String>) {
    while let Some(reason) = require_ui.recv().await {
        tracing::info!("Opening UI for event: {}", reason);

        let options = eframe::NativeOptions {
            viewport: eframe::egui::ViewportBuilder::default().with_inner_size([800.0, 600.0]),
            centered: true,
            ..Default::default()
        };
        eframe::run_native(
            "Ekto control panel",
            options,
            Box::new(|_cc| Ok(Box::new(app.clone()))),
        )
        .expect("Failed to start UI");

        // Clear if any events were sent while the UI was open. The user can do multiple tasks
        // while the UI is open, so no need to re-open the UI if it just closed.
        require_ui.try_recv().ok();
    }
}
