use eframe::egui;
use egui::{Button, Color32, Grid, Label, RichText, TextStyle, Ui, Vec2};
use serde::{Deserialize, Serialize};
use wasm_bindgen::{JsCast, JsValue};
use crate::node::EchoNode;
use iroh::NodeId;
use anyhow::Result;

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct TorrentInfo{
    magnet_uri : Option<String>,
    download_progress: f32,
    peers_count: usize,
    is_download: bool,
    is_seeding: bool,
    download_complete: bool
}

#[derive(Deserialize, Serialize)]
#[serde(default)]
pub struct P2PTransfer {
    #[serde(skip)]
    value: f32,
    #[cfg(target_arch = "wasm32")]
    #[serde(skip)]
    file_input_closure: Option<wasm_bindgen::closure::Closure<dyn FnMut(web_sys::Event)>>,
    #[serde(skip)]
    picked_file_name: std::sync::Arc<std::sync::Mutex<Option<String>>>,
    #[serde(skip)]
    picked_file_path: std::sync::Arc<std::sync::Mutex<Option<String>>>,
    #[serde(skip)]
    picked_file_size: std::sync::Arc<std::sync::Mutex<Option<u64>>>,
    #[serde(skip)]
    torrent_info: std::sync::Arc<std::sync::Mutex<TorrentInfo>>,
    #[serde(skip)]
    magnet_input: String,
    #[serde(skip)]
    node: std::sync::Arc<std::sync::Mutex<Option<EchoNode>>>,
    #[serde(skip)]
    node_id: Option<NodeId>,
    #[serde(skip)]
    is_accepting: bool,
    #[serde(skip)]
    connect_command: String,
    #[serde(skip)]
    shared_node_id: std::sync::Arc<std::sync::Mutex<Option<NodeId>>>,
    #[serde(skip)]
    is_receiving: bool,
    #[serde(skip)]
    show_receive_dialog: bool,
    #[serde(skip)]
    receive_hash_input: String,
    #[serde(skip)]
    receive_status: std::sync::Arc<std::sync::Mutex<String>>,
    #[serde(skip)]
    terminal_logs: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    #[serde(skip)]
    show_terminal_view: bool

}

impl Default for P2PTransfer {
    fn default() -> Self {
        Self {
            value: 0.0,
            #[cfg(target_arch = "wasm32")]
            file_input_closure: None,
            picked_file_name: std::sync::Arc::new(std::sync::Mutex::new(None)),
            picked_file_path: std::sync::Arc::new(std::sync::Mutex::new(None)),
            picked_file_size: std::sync::Arc::new(std::sync::Mutex::new(None)),
            torrent_info: std::sync::Arc::new(std::sync::Mutex::new(TorrentInfo::default())),
            magnet_input: String::new(),
            node: std::sync::Arc::new(std::sync::Mutex::new(None)),
            node_id: None,
            is_accepting: false,
            connect_command: String::new(),
            shared_node_id: std::sync::Arc::new(std::sync::Mutex::new(None)),
            is_receiving: false,
            show_receive_dialog: false,
            receive_hash_input: String::new(),
            receive_status: std::sync::Arc::new(std::sync::Mutex::new(String::new())),
            terminal_logs: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            show_terminal_view: false,
        }
    }
}

impl P2PTransfer {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        // Load previous app state (if any)
        if let Some(storage) = cc.storage {
            return eframe::get_value(storage, eframe::APP_KEY).unwrap_or_default();
        }
        Default::default()
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn pick_file(&mut self) {
        if let Some(path) = rfd::FileDialog::new().pick_file() {
            let file_name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
            let file_path = path.display().to_string();
            let file_size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);

            if let Ok(mut filename) = self.picked_file_name.lock() {
                *filename = Some(file_name);
            }
            if let Ok(mut filepath) = self.picked_file_path.lock() {
                *filepath = Some(file_path);
            }
            if let Ok(mut filesize) = self.picked_file_size.lock() {
                *filesize = Some(file_size);
            }
        }
    }

    #[cfg(target_arch = "wasm32")]
    fn pick_file(&mut self, ctx: &egui::Context) {
        use wasm_bindgen::JsCast;
        use web_sys::{Event, HtmlInputElement};

        self.file_input_closure = None;

        let document = web_sys::window().unwrap().document().unwrap();

        let input = document.create_element("input").unwrap().dyn_into::<HtmlInputElement>().unwrap();
        input.set_attribute("type", "file").unwrap();

        let ctx_clone = ctx.clone();
        let shared_filename = self.picked_file_name.clone();
        let shared_filepath = self.picked_file_path.clone();
        let shared_filesize = self.picked_file_size.clone();

        let closure = wasm_bindgen::closure::Closure::wrap(Box::new(move |event: Event| {
            let input = event.target().unwrap().dyn_into::<HtmlInputElement>().unwrap();

            if let Some(files) = input.files() {
                if let Some(file) = files.get(0) {
                    let name = file.name();
                    let size = file.size() as u64;
                    // In web, path is not fully accessible for security reasons, but we can use the name
                    let path = name.clone();

                    web_sys::console::log_1(&format!("Picked file: {}", name).into());

                    if let Some(window) = web_sys::window() {
                        if let Some(local_storage) = window.local_storage().ok().flatten() {
                            let _ = local_storage.set_item("picked", name.as_str());

                            // Update the shared states
                            if let Ok(mut filename) = shared_filename.lock() {
                                *filename = Some(name);
                            }
                            if let Ok(mut filepath) = shared_filepath.lock() {
                                *filepath = Some(path);
                            }
                            if let Ok(mut filesize) = shared_filesize.lock() {
                                *filesize = Some(size);
                            }
                        }
                    }

                    ctx_clone.request_repaint();
                }
            }
        }) as Box<dyn FnMut(_)>);

        input.set_onchange(Some(closure.as_ref().unchecked_ref()));
        self.file_input_closure = Some(closure);
        input.click();
    }

    fn format_size(&self, size_bytes: u64) -> String {
        const KB: u64 = 1024;
        const MB: u64 = 1024 * KB;
        const GB: u64 = 1024 * MB;

        if size_bytes < KB {
            format!("{} bytes", size_bytes)
        } else if size_bytes < MB {
            format!("{:.2} KB", size_bytes as f64 / KB as f64)
        } else if size_bytes < GB {
            format!("{:.2} MB", size_bytes as f64 / MB as f64)
        } else {
            format!("{:.2} GB", size_bytes as f64 / GB as f64)
        }
    }

    fn start_accepting(&mut self, ctx: &egui::Context) {
        if self.is_accepting {
            return;
        }

        self.is_accepting = true;

        #[cfg(target_arch = "wasm32")]
        {
            use wasm_bindgen_futures::spawn_local;

            let ctx_clone = ctx.clone();
            let node_id_shared = self.shared_node_id.clone();
            let node_shared = self.node.clone();

            spawn_local(async move {
                match EchoNode::spawn().await {
                    Ok(node) => {
                        let node_id = node.endpoint().node_id();
                        web_sys::console::log_1(&format!("Node spawned with ID: {}", node_id).into());

                        if let Ok(mut nid) = node_id_shared.lock() {
                            *nid = Some(node_id);
                        }

                        // Store the node to keep it alive
                        if let Ok(mut n) = node_shared.lock() {
                            *n = Some(node);
                        }

                        ctx_clone.request_repaint();
                    }
                    Err(e) => {
                        web_sys::console::log_1(&format!("Failed to spawn node: {}", e).into());
                    }
                }
            });
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let ctx_clone = ctx.clone();
            let node_id_shared = self.shared_node_id.clone();
            let node_shared = self.node.clone();
            let logs_shared = self.terminal_logs.clone();

            tokio::spawn(async move {
                match EchoNode::spawn().await {
                    Ok(node) => {
                        let node_id = node.endpoint().node_id();
                        let log_msg = format!("Node spawned with ID: {}", node_id);
                        println!("{}", log_msg);

                        if let Ok(mut logs) = logs_shared.lock() {
                            logs.push(log_msg);
                        }

                        if let Ok(mut nid) = node_id_shared.lock() {
                            *nid = Some(node_id);
                        }

                        // Store the node to keep it alive
                        if let Ok(mut n) = node_shared.lock() {
                            *n = Some(node);
                        }

                        ctx_clone.request_repaint();
                    }
                    Err(e) => {
                        let log_msg = format!("Failed to spawn node: {}", e);
                        println!("{}", log_msg);

                        if let Ok(mut logs) = logs_shared.lock() {
                            logs.push(log_msg);
                        }
                    }
                }
            });
        }
    }

    fn stop_accepting(&mut self) {
        self.is_accepting = false;

        // Clear the node (this will drop it and close connections)
        if let Ok(mut node) = self.node.lock() {
            *node = None;
        }

        // Clear the node_id
        if let Ok(mut nid) = self.shared_node_id.lock() {
            *nid = None;
        }

        #[cfg(target_arch = "wasm32")]
        web_sys::console::log_1(&"Stopped accepting connections".into());

        #[cfg(not(target_arch = "wasm32"))]
        {
            let log_msg = "⏹ Stopped accepting connections".to_string();
            println!("{}", log_msg);

            if let Ok(mut logs) = self.terminal_logs.lock() {
                logs.push(log_msg);
            }
        }
    }

    fn start_receiving(&mut self, ctx: &egui::Context, target_node_id: NodeId) {
        if self.is_receiving {
            return;
        }

        self.is_receiving = true;
        if let Ok(mut status) = self.receive_status.lock() {
            *status = "Connecting...".to_string();
        }

        #[cfg(target_arch = "wasm32")]
        {
            use wasm_bindgen_futures::spawn_local;

            let ctx_clone = ctx.clone();
            let node_shared = self.node.clone();
            let status_shared = self.receive_status.clone();

            spawn_local(async move {
                match EchoNode::spawn().await {
                    Ok(node) => {
                        web_sys::console::log_1(&format!("Connecting to node: {}", target_node_id).into());

                        // Store the node
                        if let Ok(mut n) = node_shared.lock() {
                            *n = Some(node);
                        }

                        // Update status
                        if let Ok(mut status) = status_shared.lock() {
                            *status = "Connected! Waiting for files...".to_string();
                        }

                        web_sys::console::log_1(&"Connected! Waiting for files...".into());

                        ctx_clone.request_repaint();
                    }
                    Err(e) => {
                        web_sys::console::log_1(&format!("Failed to connect: {}", e).into());
                        if let Ok(mut status) = status_shared.lock() {
                            *status = format!("Connection failed: {}", e);
                        }
                    }
                }
            });
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let ctx_clone = ctx.clone();
            let node_shared = self.node.clone();
            let status_shared = self.receive_status.clone();
            let logs_shared = self.terminal_logs.clone();

            tokio::spawn(async move {
                match EchoNode::spawn().await {
                    Ok(node) => {
                        let log_msg = format!("Connecting to node: {}", target_node_id);
                        println!("{}", log_msg);

                        if let Ok(mut logs) = logs_shared.lock() {
                            logs.push(log_msg);
                        }

                        // Get events from connecting
                        let mut events = node.connect(target_node_id, "hello-please-echo-back".to_string());

                        // Store the node
                        if let Ok(mut n) = node_shared.lock() {
                            *n = Some(node);
                        }

                        // Process connection events
                        use n0_future::StreamExt;
                        while let Some(event) = events.next().await {
                            match event {
                                crate::node::ConnectEvent::Connected => {
                                    let log_msg = "✓ Connected! Waiting for files...".to_string();
                                    println!("{}", log_msg);

                                    if let Ok(mut logs) = logs_shared.lock() {
                                        logs.push(log_msg);
                                    }
                                    if let Ok(mut status) = status_shared.lock() {
                                        *status = "Connected! Waiting for files...".to_string();
                                    }
                                    ctx_clone.request_repaint();
                                }
                                crate::node::ConnectEvent::Sent { bytes_sent } => {
                                    let log_msg = format!("→ Sent {} bytes", bytes_sent);
                                    println!("{}", log_msg);

                                    if let Ok(mut logs) = logs_shared.lock() {
                                        logs.push(log_msg);
                                    }
                                }
                                crate::node::ConnectEvent::Received { bytes_received } => {
                                    let log_msg = format!("← Received {} bytes", bytes_received);
                                    println!("{}", log_msg);

                                    if let Ok(mut logs) = logs_shared.lock() {
                                        logs.push(log_msg);
                                    }
                                    if let Ok(mut status) = status_shared.lock() {
                                        *status = format!("Receiving... {} bytes", bytes_received);
                                    }
                                    ctx_clone.request_repaint();
                                }
                                crate::node::ConnectEvent::Closed { error } => {
                                    let log_msg = if let Some(err) = &error {
                                        format!("✗ Connection closed with error: {}", err)
                                    } else {
                                        "✓ Connection closed successfully".to_string()
                                    };
                                    println!("{}", log_msg);

                                    if let Ok(mut logs) = logs_shared.lock() {
                                        logs.push(log_msg);
                                    }
                                    if let Some(err) = error {
                                        if let Ok(mut status) = status_shared.lock() {
                                            *status = format!("Error: {}", err);
                                        }
                                    } else {
                                        if let Ok(mut status) = status_shared.lock() {
                                            *status = "Transfer complete!".to_string();
                                        }
                                    }
                                    ctx_clone.request_repaint();
                                    break;
                                }
                            }
                        }

                        ctx_clone.request_repaint();
                    }
                    Err(e) => {
                        println!("Failed to connect: {}", e);
                        if let Ok(mut status) = status_shared.lock() {
                            *status = format!("Connection failed: {}", e);
                        }
                    }
                }
            });
        }
    }

    fn stop_receiving(&mut self) {
        self.is_receiving = false;
        self.show_receive_dialog = false;

        if let Ok(mut status) = self.receive_status.lock() {
            status.clear();
        }

        // Clear the node
        if let Ok(mut node) = self.node.lock() {
            *node = None;
        }

        #[cfg(target_arch = "wasm32")]
        web_sys::console::log_1(&"Stopped receiving".into());

        #[cfg(not(target_arch = "wasm32"))]
        {
            let log_msg = "⏹ Stopped receiving".to_string();
            println!("{}", log_msg);

            if let Ok(mut logs) = self.terminal_logs.lock() {
                logs.push(log_msg);
            }
        }
    }

    // Added this method to fix the missing generate_magnet_uri error


    fn show_file_info(&mut self, ui: &mut Ui) {
        // Scope the mutex locks to extract data and drop guards early
        let (name, path, size) = {
            let file_name_binding = self.picked_file_name.lock().ok();
            let file_path_binding = self.picked_file_path.lock().ok();
            let file_size_binding = self.picked_file_size.lock().ok();

            match (
                file_name_binding.as_ref().map(|f| f.as_ref().cloned()),
                file_path_binding.as_ref().map(|f| f.as_ref().cloned()),
                file_size_binding.as_ref().map(|f| f.as_ref().cloned()),
            ) {
                (Some(Some(name)), Some(Some(path)), Some(Some(size))) => (name, path, size),
                _ => {
                    // No file selected, display message and return
                    ui.add_space(15.0);
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 8.0;
                        ui.label(RichText::new("📄").color(Color32::GRAY));
                        ui.label(RichText::new("No file selected").color(Color32::GRAY));
                    });
                    return;
                }
            }
        };

        // Generate magnet URI before entering the closure
        // if let Some(magnet_uri) = self.generate_magnet_uri(&path) {
        //     self.magnet_input = magnet_uri;
        // }

        ui.add_space(15.0);
        ui.group(|ui| {
            ui.set_width(ui.available_width());
            ui.vertical(|ui| {
                // Header with icon
                ui.horizontal(|ui| {
                    ui.add(Label::new(RichText::new("📁").heading()));
                    ui.heading(RichText::new("Selected File").color(Color32::from_rgb(50, 150, 200)));
                });

                ui.add_space(8.0);
                ui.separator();
                ui.add_space(8.0);

                // File info in a more compact layout
                Grid::new("file_info_grid")
                    .num_columns(2)
                    .spacing([10.0, 4.0])
                    .show(ui, |ui| {
                        // File name
                        ui.strong("Name:");
                        ui.label(&name);
                        ui.end_row();

                        // File path
                        ui.strong("Path:");
                        ui.label(&path);
                        ui.end_row();

                        // File size
                        ui.strong("Size:");
                        #[cfg(target_arch = "wasm32")]
                        web_sys::console::log_1(&format!("============{:?}", size).into());
                        ui.label(self.format_size(size));
                        ui.end_row();
                    });

                ui.add_space(10.0);
                ui.separator();
                ui.add_space(10.0);

                // Action buttons
                ui.horizontal(|ui| {
                    // Share button with icon
                    if !self.is_accepting {
                        let share_btn = ui.add(
                            Button::new(RichText::new("🔗 Share").text_style(TextStyle::Button))
                        );
                        share_btn.clone().on_hover_text("Start accepting connections for this file");

                        if share_btn.clicked() {
                            self.start_accepting(ui.ctx());
                        }
                    } else {
                        let view_btn = ui.add(
                            Button::new(RichText::new("👁 View").text_style(TextStyle::Button))
                                .fill(Color32::from_rgb(100, 150, 200))
                        );
                        view_btn.clone().on_hover_text("View terminal logs");

                        if view_btn.clicked() {
                            self.show_terminal_view = !self.show_terminal_view;
                        }

                        ui.add_space(5.0);

                        let stop_btn = ui.add(
                            Button::new(RichText::new("⏹ Stop").text_style(TextStyle::Button))
                                .fill(Color32::from_rgb(200, 100, 100))
                        );
                        stop_btn.clone().on_hover_text("Stop accepting connections");

                        if stop_btn.clicked() {
                            self.stop_accepting();
                        }
                    }
                });

                // Display generated magnet URI if available
                if !self.magnet_input.is_empty() {
                    ui.add_space(10.0);
                    ui.group(|ui| {
                        ui.vertical(|ui| {
                            ui.label(RichText::new("Magnet URI:").strong());
                            ui.add_space(5.0);
                            ui.label(&self.magnet_input);
                            ui.add_space(5.0);

                            if ui.button("📋 Copy").clicked() {
                                ui.ctx().copy_text(self.magnet_input.clone());
                            }
                        });
                    });
                }

                // Display connection command if accepting
                if self.is_accepting {
                    ui.add_space(10.0);
                    ui.group(|ui| {
                        ui.vertical(|ui| {
                            ui.label(RichText::new("Waiting for connection...").strong().color(Color32::from_rgb(100, 200, 100)));

                            // Check if node_id is available
                            if let Ok(node_id_opt) = self.shared_node_id.lock() {
                                if let Some(node_id) = *node_id_opt {
                                    ui.add_space(5.0);
                                    ui.label(RichText::new("Node Hash:").strong());
                                    ui.add_space(5.0);

                                    let node_hash = format!("{}", node_id);
                                    ui.label(RichText::new(&node_hash).code());
                                    ui.add_space(5.0);

                                    if ui.button("📋 Copy Hash").clicked() {
                                        ui.ctx().copy_text(node_hash);
                                    }
                                } else {
                                    ui.add_space(5.0);
                                    ui.label("Initializing node...");
                                }
                            }
                        });
                    });
                }
            });
        });
    }
}

impl eframe::App for P2PTransfer {
    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        eframe::set_value(storage, eframe::APP_KEY, self);
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let frame = egui::containers::Frame::new()
            .fill(ctx.style().visuals.window_fill)
            .inner_margin(20.0)
            .stroke(ctx.style().visuals.widgets.noninteractive.bg_stroke);

        egui::TopBottomPanel::top("top_panel")
            .frame(frame.clone())
            .show(ctx, |ui| {
                ui.add_space(4.0);
                egui::menu::bar(ui, |ui| {
                    ui.heading(RichText::new("Syncoxiders").strong());
                    ui.add_space(16.0);

                    let is_web = cfg!(target_arch = "wasm32");
                    if !is_web {
                        ui.menu_button("File", |ui| {
                            if ui.button("Quit").clicked() {
                                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                            }
                        });
                        ui.add_space(16.0);
                    }

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        egui::widgets::global_theme_preference_buttons(ui);
                    });
                });
                ui.add_space(4.0);
            });

        egui::CentralPanel::default()
            .frame(frame)
            .show(ctx, |ui| {
                ui.vertical_centered(|ui| {
                    ui.add_space(20.0);
                    ui.heading(RichText::new("P2P File Sharing").size(24.0));
                    ui.add_space(5.0);
                    ui.label("Easily share files with a secure peer-to-peer connection");
                    ui.add_space(20.0);
                });

                ui.horizontal_centered(|ui| {
                    let btn = ui.add_sized(
                        Vec2::new(200.0, 40.0),
                        egui::Button::new(RichText::new("Choose File").size(16.0))
                            .fill(Color32::from_rgb(50, 150, 200))
                    );

                    if btn.clicked() {
                        #[cfg(target_arch = "wasm32")]
                        self.pick_file(ctx);
                        #[cfg(not(target_arch = "wasm32"))]
                        self.pick_file();
                    }

                    ui.add_space(10.0);

                    let receive_btn = ui.add_sized(
                        Vec2::new(200.0, 40.0),
                        egui::Button::new(RichText::new("Receive").size(16.0))
                            .fill(Color32::from_rgb(100, 200, 100))
                    );

                    if receive_btn.clicked() {
                        self.show_receive_dialog = !self.show_receive_dialog;
                    }
                });

                // Show receive section if active
                if self.show_receive_dialog {
                    ui.add_space(20.0);
                    ui.group(|ui| {
                        ui.set_width(ui.available_width());
                        ui.vertical(|ui| {
                            // Header
                            ui.horizontal(|ui| {
                                ui.add(Label::new(RichText::new("📥").heading()));
                                ui.heading(RichText::new("Receive File").color(Color32::from_rgb(100, 200, 100)));
                            });

                            ui.add_space(8.0);
                            ui.separator();
                            ui.add_space(8.0);

                            ui.label(RichText::new("Enter the node hash to connect:").strong());
                            ui.add_space(10.0);

                            ui.horizontal(|ui| {
                                ui.label("Hash:");
                                ui.text_edit_singleline(&mut self.receive_hash_input);
                            });

                            ui.add_space(10.0);

                            if let Ok(status) = self.receive_status.lock() {
                                if !status.is_empty() {
                                    ui.label(RichText::new(status.as_str()).color(Color32::from_rgb(100, 150, 200)));
                                    ui.add_space(5.0);
                                }
                            }

                            ui.horizontal(|ui| {
                                if !self.is_receiving {
                                    if ui.button("Connect").clicked() {
                                        if let Ok(node_id) = self.receive_hash_input.parse::<NodeId>() {
                                            self.start_receiving(ctx, node_id);
                                        } else {
                                            if let Ok(mut status) = self.receive_status.lock() {
                                                *status = "Invalid hash format".to_string();
                                            }
                                        }
                                    }

                                    if ui.button("Cancel").clicked() {
                                        self.show_receive_dialog = false;
                                        self.receive_hash_input.clear();
                                        if let Ok(mut status) = self.receive_status.lock() {
                                            status.clear();
                                        }
                                    }
                                } else {
                                    let view_btn = ui.add(
                                        Button::new(RichText::new("👁 View").text_style(TextStyle::Button))
                                            .fill(Color32::from_rgb(100, 150, 200))
                                    );
                                    view_btn.clone().on_hover_text("View terminal logs");

                                    if view_btn.clicked() {
                                        self.show_terminal_view = !self.show_terminal_view;
                                    }

                                    ui.add_space(5.0);

                                    let stop_btn = ui.add(
                                        Button::new(RichText::new("⏹ Stop").text_style(TextStyle::Button))
                                            .fill(Color32::from_rgb(200, 100, 100))
                                    );
                                    stop_btn.clone().on_hover_text("Stop receiving");

                                    if stop_btn.clicked() {
                                        self.stop_receiving();
                                    }
                                }
                            });
                        });
                    });
                }

                self.show_file_info(ui);

                ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 0.0;
                        ui.label("Powered by ");
                        ui.hyperlink_to("Syncoxiders", "https://github.com/emilk/eframe_template");
                        ui.label(" • ");
                        ui.hyperlink_to(
                            "Source code",
                            "https://github.com/emilk/eframe_template/blob/main/",
                        );
                    });
                    egui::warn_if_debug_build(ui);
                });
            });

        // Terminal view window
        egui::Window::new("📟 Terminal Logs")
            .resizable(true)
            .default_width(600.0)
            .default_height(400.0)
            .open(&mut self.show_terminal_view)
            .show(ctx, |ui| {
                egui::ScrollArea::vertical()
                    .stick_to_bottom(true)
                    .show(ui, |ui| {
                        if let Ok(logs) = self.terminal_logs.lock() {
                            if logs.is_empty() {
                                ui.label(RichText::new("No logs yet...").italics().color(Color32::GRAY));
                            } else {
                                for log in logs.iter() {
                                    ui.label(RichText::new(log).code());
                                }
                            }
                        } else {
                            ui.label(RichText::new("Error accessing logs").color(Color32::RED));
                        }
                    });

                ui.separator();
                ui.horizontal(|ui| {
                    if ui.button("Clear").clicked() {
                        if let Ok(mut logs) = self.terminal_logs.lock() {
                            logs.clear();
                        }
                    }
                });
            });

        // egui::CentralPanel::default()
        // .frame(frame)
        // .show(ctx, |ui| {
        //     ui.label("Iroh node working");
        // });

    }
}