use eframe::egui;
use egui::{Button, Color32, Grid, Label, RichText, TextStyle, Ui, Vec2};
use serde::{Deserialize, Serialize};
use crate::node::EchoNode;
use iroh::NodeId;

#[derive(Debug, Clone)]
struct ReceivedFile {
    name: String,
    size: u64,
    saved_path: String,
    timestamp: String,
}

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
    #[cfg(target_arch = "wasm32")]
    #[serde(skip)]
    picked_file_data: std::sync::Arc<std::sync::Mutex<Option<Vec<u8>>>>,
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
    is_receiving: std::sync::Arc<std::sync::Mutex<bool>>,
    #[serde(skip)]
    show_receive_dialog: bool,
    #[serde(skip)]
    receive_hash_input: String,
    #[serde(skip)]
    receive_status: std::sync::Arc<std::sync::Mutex<String>>,
    #[serde(skip)]
    terminal_logs: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    #[serde(skip)]
    show_terminal_view: bool,
    #[serde(skip)]
    received_files: std::sync::Arc<std::sync::Mutex<Vec<ReceivedFile>>>,
    #[serde(skip)]
    shared_files: std::sync::Arc<std::sync::Mutex<Vec<(String, String, u64)>>>, // (name, path, size)
    #[serde(skip)]
    save_directory: std::sync::Arc<std::sync::Mutex<Option<String>>>,

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
            #[cfg(target_arch = "wasm32")]
            picked_file_data: std::sync::Arc::new(std::sync::Mutex::new(None)),
            torrent_info: std::sync::Arc::new(std::sync::Mutex::new(TorrentInfo::default())),
            magnet_input: String::new(),
            node: std::sync::Arc::new(std::sync::Mutex::new(None)),
            node_id: None,
            is_accepting: false,
            connect_command: String::new(),
            shared_node_id: std::sync::Arc::new(std::sync::Mutex::new(None)),
            is_receiving: std::sync::Arc::new(std::sync::Mutex::new(false)),
            show_receive_dialog: false,
            receive_hash_input: String::new(),
            receive_status: std::sync::Arc::new(std::sync::Mutex::new(String::new())),
            terminal_logs: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            show_terminal_view: false,
            received_files: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            shared_files: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            save_directory: std::sync::Arc::new(std::sync::Mutex::new(None)),
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
        use web_sys::{Event, HtmlInputElement, FileReader};
        use wasm_bindgen_futures::JsFuture;

        self.file_input_closure = None;

        let document = web_sys::window().unwrap().document().unwrap();

        let input = document.create_element("input").unwrap().dyn_into::<HtmlInputElement>().unwrap();
        input.set_attribute("type", "file").unwrap();

        let ctx_clone = ctx.clone();
        let shared_filename = self.picked_file_name.clone();
        let shared_filepath = self.picked_file_path.clone();
        let shared_filesize = self.picked_file_size.clone();
        let shared_filedata = self.picked_file_data.clone();

        let closure = wasm_bindgen::closure::Closure::wrap(Box::new(move |event: Event| {
            let input = event.target().unwrap().dyn_into::<HtmlInputElement>().unwrap();

            if let Some(files) = input.files() {
                if let Some(file) = files.get(0) {
                    let name = file.name();
                    let size = file.size() as u64;
                    let path = name.clone();

                    web_sys::console::log_1(&format!("Picked file: {} ({} bytes)", name, size).into());

                    // Read file data
                    let reader = FileReader::new().unwrap();
                    let reader_clone = reader.clone();
                    let name_clone = name.clone();
                    let ctx_clone2 = ctx_clone.clone();
                    let shared_filename2 = shared_filename.clone();
                    let shared_filepath2 = shared_filepath.clone();
                    let shared_filesize2 = shared_filesize.clone();
                    let shared_filedata2 = shared_filedata.clone();

                    let onload = wasm_bindgen::closure::Closure::wrap(Box::new(move |_event: Event| {
                        if let Ok(result) = reader_clone.result() {
                            if let Some(array_buffer) = result.dyn_ref::<js_sys::ArrayBuffer>() {
                                let uint8_array = js_sys::Uint8Array::new(array_buffer);
                                let data: Vec<u8> = uint8_array.to_vec();

                                web_sys::console::log_1(&format!("File data read: {} bytes", data.len()).into());

                                // Update shared states
                                if let Ok(mut filename) = shared_filename2.lock() {
                                    *filename = Some(name_clone.clone());
                                }
                                if let Ok(mut filepath) = shared_filepath2.lock() {
                                    *filepath = Some(name_clone.clone());
                                }
                                if let Ok(mut filesize) = shared_filesize2.lock() {
                                    *filesize = Some(data.len() as u64);
                                }
                                if let Ok(mut filedata) = shared_filedata2.lock() {
                                    *filedata = Some(data);
                                }

                                ctx_clone2.request_repaint();
                            }
                        }
                    }) as Box<dyn FnMut(_)>);

                    reader.set_onload(Some(onload.as_ref().unchecked_ref()));
                    onload.forget();

                    let _ = reader.read_as_array_buffer(&file);
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
            let logs_shared = self.terminal_logs.clone();
            let shared_files = self.shared_files.clone();

            spawn_local(async move {
                // Read all files from the shared_files list
                let files_to_share: Vec<(String, Vec<u8>)> = if let Ok(files) = shared_files.lock() {
                    // For WASM, we need to get file data from memory
                    // Files are stored when picked via the file input
                    files.iter().filter_map(|(name, _path, _size)| {
                        // In WASM, the "path" is just the name, and we don't have direct file access
                        // Files should be stored in memory when picked
                        // For now, return empty vec - this will be populated when we add files
                        None
                    }).collect()
                } else {
                    Vec::new()
                };

                match EchoNode::spawn_with_files(files_to_share).await {
                    Ok(node) => {
                        let node_id = node.endpoint().node_id();
                        let log_msg = format!("🚀 Node spawned with ID: {}", node_id);
                        web_sys::console::log_1(&log_msg.into());

                        if let Ok(mut logs) = logs_shared.lock() {
                            logs.push(log_msg);
                        }

                        if let Ok(mut nid) = node_id_shared.lock() {
                            *nid = Some(node_id);
                        }

                        // Subscribe to accept events for sender-side logging
                        let mut accept_events = node.subscribe_accept_events();
                        let logs_for_events = logs_shared.clone();
                        let ctx_for_events = ctx_clone.clone();

                        spawn_local(async move {
                            while let Ok(event) = accept_events.recv().await {
                                match event {
                                    crate::node::AcceptEvent::Accepted { node_id } => {
                                        let log_msg = format!("📥 Incoming connection from: {}", node_id);
                                        web_sys::console::log_1(&log_msg.into());
                                        if let Ok(mut logs) = logs_for_events.lock() {
                                            logs.push(log_msg);
                                        }
                                        ctx_for_events.request_repaint();
                                    }
                                    crate::node::AcceptEvent::Echoed { node_id, bytes_sent } => {
                                        let log_msg = format!("✅ Transfer complete to {} ({} bytes, {:.2} MB)",
                                            node_id, bytes_sent, bytes_sent as f64 / 1024.0 / 1024.0);
                                        web_sys::console::log_1(&log_msg.into());
                                        if let Ok(mut logs) = logs_for_events.lock() {
                                            logs.push(log_msg);
                                        }
                                        ctx_for_events.request_repaint();
                                    }
                                    crate::node::AcceptEvent::Closed { node_id, error } => {
                                        let log_msg = if let Some(err) = error {
                                            format!("❌ Connection closed with error from {}: {}", node_id, err)
                                        } else {
                                            format!("🔒 Connection closed with {}", node_id)
                                        };
                                        web_sys::console::log_1(&log_msg.into());
                                        if let Ok(mut logs) = logs_for_events.lock() {
                                            logs.push(log_msg);
                                        }
                                        ctx_for_events.request_repaint();
                                    }
                                }
                            }
                        });

                        // Store the node to keep it alive
                        if let Ok(mut n) = node_shared.lock() {
                            *n = Some(node);
                        }

                        ctx_clone.request_repaint();
                    }
                    Err(e) => {
                        let log_msg = format!("❌ Failed to spawn node: {}", e);
                        web_sys::console::log_1(&log_msg.into());

                        if let Ok(mut logs) = logs_shared.lock() {
                            logs.push(log_msg);
                        }
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
            let shared_files = self.shared_files.clone();

            tokio::spawn(async move {
                // Read all files from the shared_files list
                let files_to_share: Vec<(String, Vec<u8>)> = if let Ok(files) = shared_files.lock() {
                    let mut result = Vec::new();
                    for (name, path, _size) in files.iter() {
                        match std::fs::read(path) {
                            Ok(data) => {
                                let log_msg = format!("Read file: {} ({} bytes)", name, data.len());
                                println!("{}", log_msg);
                                if let Ok(mut logs) = logs_shared.lock() {
                                    logs.push(log_msg);
                                }
                                result.push((name.clone(), data));
                            }
                            Err(e) => {
                                let log_msg = format!("Failed to read file {}: {}", name, e);
                                println!("{}", log_msg);
                                if let Ok(mut logs) = logs_shared.lock() {
                                    logs.push(log_msg);
                                }
                            }
                        }
                    }
                    result
                } else {
                    Vec::new()
                };

                match EchoNode::spawn_with_files(files_to_share).await {
                    Ok(node) => {
                        let node_id = node.endpoint().node_id();
                        let log_msg = format!("🚀 Node spawned with ID: {}", node_id);
                        println!("{}", log_msg);

                        if let Ok(mut logs) = logs_shared.lock() {
                            logs.push(log_msg);
                        }

                        if let Ok(mut nid) = node_id_shared.lock() {
                            *nid = Some(node_id);
                        }

                        // Subscribe to accept events for sender-side logging
                        let mut accept_events = node.subscribe_accept_events();
                        let logs_for_events = logs_shared.clone();
                        let ctx_for_events = ctx_clone.clone();

                        tokio::spawn(async move {
                            while let Ok(event) = accept_events.recv().await {
                                match event {
                                    crate::node::AcceptEvent::Accepted { node_id } => {
                                        let log_msg = format!("📥 Incoming connection from: {}", node_id);
                                        println!("{}", log_msg);
                                        if let Ok(mut logs) = logs_for_events.lock() {
                                            logs.push(log_msg);
                                        }
                                        ctx_for_events.request_repaint();
                                    }
                                    crate::node::AcceptEvent::Echoed { node_id, bytes_sent } => {
                                        let log_msg = format!("✅ Transfer complete to {} ({} bytes, {:.2} MB)",
                                            node_id, bytes_sent, bytes_sent as f64 / 1024.0 / 1024.0);
                                        println!("{}", log_msg);
                                        if let Ok(mut logs) = logs_for_events.lock() {
                                            logs.push(log_msg);
                                        }
                                        ctx_for_events.request_repaint();
                                    }
                                    crate::node::AcceptEvent::Closed { node_id, error } => {
                                        let log_msg = if let Some(err) = error {
                                            format!("❌ Connection closed with error from {}: {}", node_id, err)
                                        } else {
                                            format!("🔒 Connection closed with {}", node_id)
                                        };
                                        println!("{}", log_msg);
                                        if let Ok(mut logs) = logs_for_events.lock() {
                                            logs.push(log_msg);
                                        }
                                        ctx_for_events.request_repaint();
                                    }
                                }
                            }
                        });

                        // Store the node to keep it alive
                        if let Ok(mut n) = node_shared.lock() {
                            *n = Some(node);
                        }

                        ctx_clone.request_repaint();
                    }
                    Err(e) => {
                        let log_msg = format!("❌ Failed to spawn node: {}", e);
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

        // Clear picked file info
        if let Ok(mut name) = self.picked_file_name.lock() {
            *name = None;
        }
        if let Ok(mut path) = self.picked_file_path.lock() {
            *path = None;
        }
        if let Ok(mut size) = self.picked_file_size.lock() {
            *size = None;
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
        if let Ok(is_recv) = self.is_receiving.lock() {
            if *is_recv {
                return;
            }
        }

        if let Ok(mut is_recv) = self.is_receiving.lock() {
            *is_recv = true;
        }
        if let Ok(mut status) = self.receive_status.lock() {
            *status = "Connecting...".to_string();
        }

        #[cfg(target_arch = "wasm32")]
        {
            use wasm_bindgen_futures::spawn_local;

            let ctx_clone = ctx.clone();
            let node_shared = self.node.clone();
            let status_shared = self.receive_status.clone();
            let is_receiving_shared = self.is_receiving.clone();
            let received_files_shared = self.received_files.clone();

            spawn_local(async move {
                match EchoNode::spawn().await {
                    Ok(node) => {
                        web_sys::console::log_1(&format!("Connecting to node: {}", target_node_id).into());

                        // Get events from connecting
                        let dummy_data = b"SEND_FILE".to_vec();
                        let mut events = node.connect(target_node_id, dummy_data, "request".to_string());

                        // Store the node
                        if let Ok(mut n) = node_shared.lock() {
                            *n = Some(node);
                        }

                        // Store file chunks temporarily
                        let mut current_file: Option<(String, Vec<Vec<u8>>)> = None;

                        // Process connection events
                        use n0_future::StreamExt;
                        while let Some(event) = events.next().await {
                            match event {
                                crate::node::ConnectEvent::Connected => {
                                    web_sys::console::log_1(&"✓ Connected! Waiting for files...".into());
                                    if let Ok(mut status) = status_shared.lock() {
                                        *status = "Connected! Waiting for files...".to_string();
                                    }
                                    ctx_clone.request_repaint();
                                }
                                crate::node::ConnectEvent::Sent { .. } => {}
                                crate::node::ConnectEvent::FileStart { file_name, file_size, total_chunks } => {
                                    web_sys::console::log_1(&format!("📥 Starting file: {} ({} bytes, {} chunks)", file_name, file_size, total_chunks).into());
                                    if let Ok(mut status) = status_shared.lock() {
                                        *status = format!("Receiving: {} (0%)", file_name);
                                    }
                                    current_file = Some((file_name, vec![Vec::new(); total_chunks as usize]));
                                    ctx_clone.request_repaint();
                                }
                                crate::node::ConnectEvent::ChunkReceived { file_name, chunk_index, chunk_data, offset: _ } => {
                                    if let Some((ref name, ref mut chunks)) = current_file {
                                        if name == &file_name && (chunk_index as usize) < chunks.len() {
                                            chunks[chunk_index as usize] = chunk_data;
                                            web_sys::console::log_1(&format!("  ✓ Chunk {} received", chunk_index).into());
                                        }
                                    }
                                    ctx_clone.request_repaint();
                                }
                                crate::node::ConnectEvent::FileComplete { file_name, total_bytes } => {
                                    web_sys::console::log_1(&format!("✅ File complete: {} ({} bytes)", file_name, total_bytes).into());

                                    // Combine all chunks and trigger download
                                    if let Some((name, chunks)) = current_file.take() {
                                        if name == file_name {
                                            let combined_data: Vec<u8> = chunks.into_iter().flatten().collect();

                                            // Trigger automatic download in browser
                                            Self::download_file_wasm(&file_name, &combined_data);

                                            let timestamp = js_sys::Date::now() as u64 / 1000;
                                            let received_file = ReceivedFile {
                                                name: file_name.clone(),
                                                size: total_bytes,
                                                saved_path: "Downloaded to browser".to_string(),
                                                timestamp: format!("{}", timestamp),
                                            };

                                            if let Ok(mut files) = received_files_shared.lock() {
                                                files.push(received_file);
                                            }

                                            if let Ok(mut status) = status_shared.lock() {
                                                *status = format!("File downloaded: {}", file_name);
                                            }
                                        }
                                    }

                                    ctx_clone.request_repaint();
                                }
                                crate::node::ConnectEvent::Closed { error } => {
                                    let msg = if let Some(err) = &error {
                                        format!("✗ Connection closed with error: {}", err)
                                    } else {
                                        "✓ Connection closed successfully".to_string()
                                    };
                                    web_sys::console::log_1(&msg.into());

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
                        web_sys::console::log_1(&format!("Failed to connect: {}", e).into());
                        if let Ok(mut status) = status_shared.lock() {
                            *status = format!("Connection failed: {}", e);
                        }
                        if let Ok(mut is_recv) = is_receiving_shared.lock() {
                            *is_recv = false;
                        }
                        ctx_clone.request_repaint();
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
            let is_receiving_shared = self.is_receiving.clone();
            let received_files_shared = self.received_files.clone();
            let save_directory_shared = self.save_directory.clone();

            tokio::spawn(async move {
                match EchoNode::spawn().await {
                    Ok(node) => {
                        let log_msg = format!("Connecting to node: {}", target_node_id);
                        println!("{}", log_msg);

                        if let Ok(mut logs) = logs_shared.lock() {
                            logs.push(log_msg);
                        }

                        // Get events from connecting - send dummy request to trigger file transfer
                        let dummy_data = b"SEND_FILE".to_vec();
                        let mut events = node.connect(target_node_id, dummy_data, "request".to_string());

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
                                crate::node::ConnectEvent::Sent { .. } => {
                                    // Ignore - this is just the dummy request data
                                }
                                crate::node::ConnectEvent::FileStart { file_name, file_size, total_chunks } => {
                                    let log_msg = format!("📥 Starting file: {} ({} bytes, {} chunks)", file_name, file_size, total_chunks);
                                    println!("{}", log_msg);

                                    if let Ok(mut logs) = logs_shared.lock() {
                                        logs.push(log_msg.clone());
                                    }
                                    if let Ok(mut status) = status_shared.lock() {
                                        *status = format!("Receiving: {} (0%)", file_name);
                                    }

                                    // Create/truncate file with the expected size
                                    if let Ok(save_dir_opt) = save_directory_shared.lock() {
                                        if let Some(save_dir) = save_dir_opt.as_ref() {
                                            let file_path = std::path::Path::new(save_dir).join(&file_name);
                                            // Pre-allocate file with correct size
                                            if let Err(e) = std::fs::OpenOptions::new()
                                                .write(true)
                                                .create(true)
                                                .truncate(true)
                                                .open(&file_path)
                                                .and_then(|f| f.set_len(file_size))
                                            {
                                                let err_msg = format!("Error creating file: {}", e);
                                                println!("{}", err_msg);
                                                if let Ok(mut logs) = logs_shared.lock() {
                                                    logs.push(err_msg);
                                                }
                                            }
                                        }
                                    }

                                    ctx_clone.request_repaint();
                                }
                                crate::node::ConnectEvent::ChunkReceived { file_name, chunk_index, chunk_data, offset } => {
                                    // Write chunk at specific offset
                                    if let Ok(save_dir_opt) = save_directory_shared.lock() {
                                        if let Some(save_dir) = save_dir_opt.as_ref() {
                                            let file_path = std::path::Path::new(save_dir).join(&file_name);

                                            use std::io::{Seek, SeekFrom, Write};
                                            match std::fs::OpenOptions::new()
                                                .write(true)
                                                .open(&file_path)
                                                .and_then(|mut f| {
                                                    f.seek(SeekFrom::Start(offset))?;
                                                    f.write_all(&chunk_data)?;
                                                    Ok(())
                                                })
                                            {
                                                Ok(_) => {
                                                    let log_msg = format!("  ✓ Chunk {}: {} bytes at offset {}", chunk_index, chunk_data.len(), offset);
                                                    if let Ok(mut logs) = logs_shared.lock() {
                                                        logs.push(log_msg);
                                                    }
                                                },
                                                Err(e) => {
                                                    let err_msg = format!("  ✗ Error writing chunk {}: {}", chunk_index, e);
                                                    println!("{}", err_msg);
                                                    if let Ok(mut logs) = logs_shared.lock() {
                                                        logs.push(err_msg);
                                                    }
                                                }
                                            }
                                        }
                                    }

                                    ctx_clone.request_repaint();
                                }
                                crate::node::ConnectEvent::FileComplete { file_name, total_bytes } => {
                                    let log_msg = format!("✅ File complete: {} ({} bytes)", file_name, total_bytes);
                                    println!("{}", log_msg);

                                    if let Ok(mut logs) = logs_shared.lock() {
                                        logs.push(log_msg.clone());
                                    }

                                    // Add to received files list
                                    if let Ok(save_dir_opt) = save_directory_shared.lock() {
                                        if let Some(save_dir) = save_dir_opt.as_ref() {
                                            let file_path = std::path::Path::new(save_dir).join(&file_name);
                                            let saved_path = file_path.to_string_lossy().to_string();

                                            if let Ok(mut status) = status_shared.lock() {
                                                *status = format!("File saved: {}", file_name);
                                            }

                                            let timestamp = std::time::SystemTime::now()
                                                .duration_since(std::time::UNIX_EPOCH)
                                                .unwrap()
                                                .as_secs();
                                            let received_file = ReceivedFile {
                                                name: file_name.clone(),
                                                size: total_bytes,
                                                saved_path,
                                                timestamp: format!("{}", timestamp),
                                            };

                                            if let Ok(mut files) = received_files_shared.lock() {
                                                files.push(received_file);
                                            }
                                        }
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
                        let log_msg = format!("✗ Failed to connect: {}", e);
                        println!("{}", log_msg);

                        if let Ok(mut logs) = logs_shared.lock() {
                            logs.push(log_msg);
                        }
                        if let Ok(mut status) = status_shared.lock() {
                            *status = format!("Connection failed: {}", e);
                        }
                        if let Ok(mut is_recv) = is_receiving_shared.lock() {
                            *is_recv = false;
                        }
                        ctx_clone.request_repaint();
                    }
                }
            });
        }
    }

    fn reconnect_for_files(&mut self, ctx: &egui::Context, target_node_id: NodeId) {
        let ctx_clone = ctx.clone();
        let node_shared = self.node.clone();
        let status_shared = self.receive_status.clone();
        let logs_shared = self.terminal_logs.clone();
        let received_files_shared = self.received_files.clone();
        let save_directory_shared = self.save_directory.clone();

        if let Ok(mut status) = self.receive_status.lock() {
            *status = "Refreshing files...".to_string();
        }

        #[cfg(not(target_arch = "wasm32"))]
        tokio::spawn(async move {
            let log_msg = format!("Refreshing files from node: {}", target_node_id);
            println!("{}", log_msg);

            if let Ok(mut logs) = logs_shared.lock() {
                logs.push(log_msg);
            }

            // Get a reference to the node and connect
            let node_ref = node_shared.clone();
            let events = {
                let node_guard = node_ref.lock();
                if node_guard.is_err() {
                    return;
                }
                let node_guard = node_guard.unwrap();
                if node_guard.is_none() {
                    return;
                }
                let node = node_guard.as_ref().unwrap();

                let dummy_data = b"SEND_FILE".to_vec();
                node.connect(target_node_id, dummy_data, "request".to_string())
            };

            let mut events = events;

            // Process connection events
            use n0_future::StreamExt;
            while let Some(event) = events.next().await {
                match event {
                    crate::node::ConnectEvent::Connected => {
                        let log_msg = "✓ Reconnected! Fetching files...".to_string();
                        println!("{}", log_msg);

                        if let Ok(mut logs) = logs_shared.lock() {
                            logs.push(log_msg);
                        }
                        if let Ok(mut status) = status_shared.lock() {
                            *status = "Fetching files...".to_string();
                        }
                        ctx_clone.request_repaint();
                    }
                    crate::node::ConnectEvent::Sent { .. } => {
                        // Ignore - this is just the dummy request data
                    }
                    crate::node::ConnectEvent::FileStart { file_name, file_size, total_chunks } => {
                        let log_msg = format!("📥 Starting file: {} ({} bytes, {} chunks)", file_name, file_size, total_chunks);
                        println!("{}", log_msg);

                        if let Ok(mut logs) = logs_shared.lock() {
                            logs.push(log_msg.clone());
                        }
                        if let Ok(mut status) = status_shared.lock() {
                            *status = format!("Receiving: {} (0%)", file_name);
                        }

                        // Check if file already exists
                        let file_exists = if let Ok(files) = received_files_shared.lock() {
                            files.iter().any(|f| f.name == file_name)
                        } else {
                            false
                        };

                        if !file_exists {
                            // Create/truncate file with the expected size
                            if let Ok(save_dir_opt) = save_directory_shared.lock() {
                                if let Some(save_dir) = save_dir_opt.as_ref() {
                                    let file_path = std::path::Path::new(save_dir).join(&file_name);
                                    // Pre-allocate file with correct size
                                    if let Err(e) = std::fs::OpenOptions::new()
                                        .write(true)
                                        .create(true)
                                        .truncate(true)
                                        .open(&file_path)
                                        .and_then(|f| f.set_len(file_size))
                                    {
                                        let err_msg = format!("Error creating file: {}", e);
                                        println!("{}", err_msg);
                                        if let Ok(mut logs) = logs_shared.lock() {
                                            logs.push(err_msg);
                                        }
                                    }
                                }
                            }
                        }

                        ctx_clone.request_repaint();
                    }
                    crate::node::ConnectEvent::ChunkReceived { file_name, chunk_index, chunk_data, offset } => {
                        // Check if file already exists in received files
                        let file_exists = if let Ok(files) = received_files_shared.lock() {
                            files.iter().any(|f| f.name == file_name)
                        } else {
                            false
                        };

                        if !file_exists {
                            // Write chunk at specific offset
                            if let Ok(save_dir_opt) = save_directory_shared.lock() {
                                if let Some(save_dir) = save_dir_opt.as_ref() {
                                    let file_path = std::path::Path::new(save_dir).join(&file_name);

                                    use std::io::{Seek, SeekFrom, Write};
                                    match std::fs::OpenOptions::new()
                                        .write(true)
                                        .open(&file_path)
                                        .and_then(|mut f| {
                                            f.seek(SeekFrom::Start(offset))?;
                                            f.write_all(&chunk_data)?;
                                            Ok(())
                                        })
                                    {
                                        Ok(_) => {
                                            let log_msg = format!("  ✓ Chunk {}: {} bytes at offset {}", chunk_index, chunk_data.len(), offset);
                                            if let Ok(mut logs) = logs_shared.lock() {
                                                logs.push(log_msg);
                                            }
                                        },
                                        Err(e) => {
                                            let err_msg = format!("  ✗ Error writing chunk {}: {}", chunk_index, e);
                                            println!("{}", err_msg);
                                            if let Ok(mut logs) = logs_shared.lock() {
                                                logs.push(err_msg);
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        ctx_clone.request_repaint();
                    }
                    crate::node::ConnectEvent::FileComplete { file_name, total_bytes } => {
                        // Check if file already exists
                        let file_exists = if let Ok(files) = received_files_shared.lock() {
                            files.iter().any(|f| f.name == file_name)
                        } else {
                            false
                        };

                        if !file_exists {
                            let log_msg = format!("✅ File complete: {} ({} bytes)", file_name, total_bytes);
                            println!("{}", log_msg);

                            if let Ok(mut logs) = logs_shared.lock() {
                                logs.push(log_msg.clone());
                            }

                            // Add to received files list
                            if let Ok(save_dir_opt) = save_directory_shared.lock() {
                                if let Some(save_dir) = save_dir_opt.as_ref() {
                                    let file_path = std::path::Path::new(save_dir).join(&file_name);
                                    let saved_path = file_path.to_string_lossy().to_string();

                                    if let Ok(mut status) = status_shared.lock() {
                                        *status = format!("File saved: {}", file_name);
                                    }

                                    let timestamp = std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap()
                                        .as_secs();
                                    let received_file = ReceivedFile {
                                        name: file_name.clone(),
                                        size: total_bytes,
                                        saved_path,
                                        timestamp: format!("{}", timestamp),
                                    };

                                    if let Ok(mut files) = received_files_shared.lock() {
                                        files.push(received_file);
                                    }
                                }
                            }
                        } else {
                            if let Ok(mut status) = status_shared.lock() {
                                *status = format!("File already exists: {}", file_name);
                            }
                        }

                        ctx_clone.request_repaint();
                    }
                    crate::node::ConnectEvent::Closed { error } => {
                        let log_msg = if let Some(err) = &error {
                            format!("✗ Connection closed with error: {}", err)
                        } else {
                            "✓ Refresh complete!".to_string()
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
                                *status = "Connected! Files up to date.".to_string();
                            }
                        }
                        ctx_clone.request_repaint();
                        break;
                    }
                }
            }

            ctx_clone.request_repaint();
        });

        #[cfg(target_arch = "wasm32")]
        {
            // For WASM, we'd need to implement a similar reconnection
            web_sys::console::log_1(&"Refresh not yet implemented for WASM".into());
        }
    }

    fn stop_receiving(&mut self) {
        if let Ok(mut is_recv) = self.is_receiving.lock() {
            *is_recv = false;
        }
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

    #[cfg(target_arch = "wasm32")]
    fn download_file_wasm(file_name: &str, file_data: &[u8]) {
        use wasm_bindgen::JsCast;
        use web_sys::{Blob, BlobPropertyBag, Url, HtmlAnchorElement};

        if let Some(window) = web_sys::window() {
            if let Some(document) = window.document() {
                // Create a Blob from the file data
                let array = js_sys::Uint8Array::new_with_length(file_data.len() as u32);
                array.copy_from(file_data);

                let parts = js_sys::Array::new();
                parts.push(&array);

                let mut blob_props = BlobPropertyBag::new();
                blob_props.type_("application/octet-stream");

                if let Ok(blob) = Blob::new_with_u8_array_sequence_and_options(&parts, &blob_props) {
                    if let Ok(url) = Url::create_object_url_with_blob(&blob) {
                        // Create a temporary anchor element and trigger download
                        if let Ok(anchor) = document.create_element("a") {
                            let anchor: HtmlAnchorElement = anchor.dyn_into().unwrap();
                            anchor.set_href(&url);
                            anchor.set_download(file_name);
                            anchor.click();

                            // Clean up
                            let _ = Url::revoke_object_url(&url);
                        }
                    }
                }
            }
        }
    }

    #[cfg(not(target_arch = "wasm32"))]

    fn show_received_files(&mut self, ui: &mut Ui) {
        if let Ok(files) = self.received_files.lock() {
            if files.is_empty() {
                return;
            }

            ui.add_space(20.0);
            ui.group(|ui| {
                ui.set_width(ui.available_width());
                ui.vertical(|ui| {
                    // Header
                    ui.horizontal(|ui| {
                        ui.add(Label::new(RichText::new("📦").heading()));
                        ui.heading(RichText::new("Received Files").color(Color32::from_rgb(100, 200, 100)));
                    });

                    ui.add_space(8.0);
                    ui.separator();
                    ui.add_space(8.0);

                    // Display each received file
                    for (index, file) in files.iter().enumerate() {
                        ui.group(|ui| {
                            ui.vertical(|ui| {
                                ui.strong(&file.name);
                                ui.label(format!("Size: {}", self.format_size(file.size)));
                                ui.label(format!("Saved to: {}", file.saved_path));
                                ui.label(format!("Received: {}", file.timestamp));
                            });
                        });

                        if index < files.len() - 1 {
                            ui.add_space(5.0);
                        }
                    }
                });
            });
        }
    }

    // Added this method to fix the missing generate_magnet_uri error

    fn add_file_to_share(&mut self, _ctx: &egui::Context) {
        // Get the currently picked file
        let file_info = {
            let name = self.picked_file_name.lock().ok().and_then(|f| f.clone());
            let path = self.picked_file_path.lock().ok().and_then(|f| f.clone());
            let size = self.picked_file_size.lock().ok().and_then(|f| f.clone());

            match (name, path, size) {
                (Some(n), Some(p), Some(s)) => Some((n, p, s)),
                _ => None
            }
        };

        let should_restart = self.is_accepting;

        if let Some((name, path, size)) = file_info {
            // Check if file already added
            let mut file_added = false;
            if let Ok(mut files) = self.shared_files.lock() {
                if !files.iter().any(|(_, p, _)| p == &path) {
                    files.push((name.clone(), path.clone(), size));
                    file_added = true;

                    #[cfg(not(target_arch = "wasm32"))]
                    if let Ok(mut logs) = self.terminal_logs.lock() {
                        logs.push(format!("Added file to share: {}", name));
                    }
                }
            }

            // If node is running, update its file list directly
            if file_added && should_restart {
                if let Ok(node_guard) = self.node.lock() {
                    if let Some(node) = node_guard.as_ref() {
                        let node_files = node.get_shared_files();
                        #[cfg(not(target_arch = "wasm32"))]
                        {
                            if let Ok(data) = std::fs::read(&path) {
                                if let Ok(mut nf) = node_files.lock() {
                                    nf.push((name.clone(), data));
                                    if let Ok(mut logs) = self.terminal_logs.lock() {
                                        logs.push(format!("Updated running node with file: {}", name));
                                    }
                                }
                            }
                        }
                        #[cfg(target_arch = "wasm32")]
                        {
                            // For WASM, file data should be in picked_file_data
                            // This needs special handling since we can't read from filesystem
                            web_sys::console::log_1(&"WASM: Cannot update running node file list directly".into());
                        }
                    }
                }
            }

            // Clear the picked file
            if let Ok(mut name) = self.picked_file_name.lock() {
                *name = None;
            }
            if let Ok(mut path) = self.picked_file_path.lock() {
                *path = None;
            }
            if let Ok(mut size) = self.picked_file_size.lock() {
                *size = None;
            }
        }
    }    fn restart_node(&mut self, ctx: &egui::Context) {
        // Stop current node
        if let Ok(mut node) = self.node.lock() {
            *node = None;
        }

        // Wait a moment and restart
        let ctx_clone = ctx.clone();
        let node_id_shared = self.shared_node_id.clone();
        let node_shared = self.node.clone();
        let logs_shared = self.terminal_logs.clone();
        let shared_files = self.shared_files.clone();

        #[cfg(not(target_arch = "wasm32"))]
        tokio::spawn(async move {
            // Small delay to ensure old node is cleaned up
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

            let files_to_share: Vec<(String, Vec<u8>)> = if let Ok(files) = shared_files.lock() {
                let mut result = Vec::new();
                for (name, path, _size) in files.iter() {
                    match std::fs::read(path) {
                        Ok(data) => {
                            result.push((name.clone(), data));
                        }
                        Err(e) => {
                            if let Ok(mut logs) = logs_shared.lock() {
                                logs.push(format!("Failed to read file {}: {}", name, e));
                            }
                        }
                    }
                }
                result
            } else {
                Vec::new()
            };

            match EchoNode::spawn_with_files(files_to_share).await {
                Ok(node) => {
                    let node_id = node.endpoint().node_id();

                    if let Ok(mut nid) = node_id_shared.lock() {
                        *nid = Some(node_id);
                    }

                    if let Ok(mut n) = node_shared.lock() {
                        *n = Some(node);
                    }

                    if let Ok(mut logs) = logs_shared.lock() {
                        logs.push("Node restarted with updated files".to_string());
                    }

                    ctx_clone.request_repaint();
                }
                Err(e) => {
                    if let Ok(mut logs) = logs_shared.lock() {
                        logs.push(format!("Failed to restart node: {}", e));
                    }
                }
            }
        });
    }

    fn show_shared_files(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        let mut to_remove: Option<usize> = None;
        let should_restart;
        let mut should_start_accepting = false;

        {
            let files = self.shared_files.lock();
            if files.is_err() || files.as_ref().unwrap().is_empty() {
                return;
            }

            let files = files.unwrap();

            ui.add_space(15.0);
            ui.group(|ui| {
                ui.set_width(ui.available_width());
                ui.vertical(|ui| {
                    ui.horizontal(|ui| {
                        ui.add(Label::new(RichText::new("📤").heading()));
                        ui.heading(RichText::new("Shared Files").color(Color32::from_rgb(50, 150, 200)));

                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if !self.is_accepting {
                                let share_btn = ui.add(
                                    Button::new(RichText::new("🔗 Share").text_style(TextStyle::Button).color(Color32::WHITE))
                                        .fill(Color32::from_rgb(100, 200, 100))
                                );
                                share_btn.clone().on_hover_text("Start accepting connections and share all files");

                                if share_btn.clicked() {
                                    should_start_accepting = true;
                                }
                            }
                        });
                    });

                    ui.add_space(8.0);
                    ui.separator();
                    ui.add_space(8.0);

                    for (index, (name, _path, size)) in files.iter().enumerate() {
                        ui.group(|ui| {
                            ui.horizontal(|ui| {
                                ui.vertical(|ui| {
                                    ui.strong(name);
                                    ui.label(format!("Size: {}", self.format_size(*size)));
                                });

                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                    if ui.button(RichText::new("🗑 Remove").color(Color32::WHITE)).clicked() {
                                        to_remove = Some(index);
                                    }
                                });
                            });
                        });

                        if index < files.len() - 1 {
                            ui.add_space(5.0);
                        }
                    }
                });
            });

            should_restart = self.is_accepting;
        } // Release lock here

        // Handle removal after lock is released
        if let Some(index) = to_remove {
            let removed_name = if let Ok(mut files) = self.shared_files.lock() {
                let removed = files.remove(index);

                #[cfg(not(target_arch = "wasm32"))]
                if let Ok(mut logs) = self.terminal_logs.lock() {
                    logs.push(format!("Removed file from shared list: {}", removed.0));
                }

                Some(removed.0)
            } else {
                None
            };

            // If node is running, update its file list directly
            if should_restart && removed_name.is_some() {
                let node_files = if let Ok(node_guard) = self.node.lock() {
                    node_guard.as_ref().map(|node| node.get_shared_files())
                } else {
                    None
                };

                if let Some(node_files) = node_files {
                    if let Ok(mut nf) = node_files.lock() {
                        // Rebuild the file list from shared_files
                        nf.clear();
                        if let Ok(shared) = self.shared_files.lock() {
                            for (name, path, _size) in shared.iter() {
                                #[cfg(not(target_arch = "wasm32"))]
                                {
                                    if let Ok(data) = std::fs::read(path) {
                                        nf.push((name.clone(), data));
                                    }
                                }
                                #[cfg(target_arch = "wasm32")]
                                {
                                    // For WASM, we'd need to store the data separately
                                    // This is a limitation - might need restart on WASM
                                }
                            }
                        }

                        #[cfg(not(target_arch = "wasm32"))]
                        if let Ok(mut logs) = self.terminal_logs.lock() {
                            logs.push(format!("Updated running node - removed: {}", removed_name.unwrap()));
                        }
                    }
                }
            }
        }

        // Handle start accepting after locks are released
        if should_start_accepting {
            self.start_accepting(ctx);
        }
    }

    fn show_connection_status(&mut self, ui: &mut Ui) {
        // Display connection status if accepting
        if self.is_accepting {
            ui.add_space(15.0);

            let mut should_stop = false;

            ui.group(|ui| {
                ui.set_width(ui.available_width());
                ui.vertical(|ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("🟢 Sharing Active").strong().color(Color32::from_rgb(100, 200, 100)));

                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            let stop_btn = ui.add(
                                Button::new(RichText::new("⏹ Close Sharing").text_style(TextStyle::Button).color(Color32::WHITE))
                                    .fill(Color32::from_rgb(200, 100, 100))
                            );
                            stop_btn.clone().on_hover_text("Stop sharing and close connections");

                            if stop_btn.clicked() {
                                should_stop = true;
                            }

                            ui.add_space(5.0);

                            let view_btn = ui.add(
                                Button::new(RichText::new("👁 View Logs").text_style(TextStyle::Button).color(Color32::WHITE))
                                    .fill(Color32::from_rgb(100, 150, 200))
                            );
                            view_btn.clone().on_hover_text("View transfer logs");

                            if view_btn.clicked() {
                                self.show_terminal_view = !self.show_terminal_view;
                            }
                        });
                    });

                    // Check if node_id is available
                    if let Ok(node_id_opt) = self.shared_node_id.lock() {
                        if let Some(node_id) = *node_id_opt {
                            ui.add_space(8.0);
                            ui.separator();
                            ui.add_space(8.0);

                            ui.label(RichText::new("Node Hash:").strong());
                            ui.add_space(5.0);

                            let node_hash = format!("{}", node_id);
                            ui.label(RichText::new(&node_hash).code());
                            ui.add_space(5.0);

                            if ui.button(RichText::new("📋 Copy Hash").color(Color32::WHITE)).clicked() {
                                ui.ctx().copy_text(node_hash);
                            }
                        } else {
                            ui.add_space(5.0);
                            ui.label("Initializing node...");
                        }
                    }
                });
            });

            // Handle stop after UI is done
            if should_stop {
                self.stop_accepting();
            }
        }
    }

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
                    // Add to share button
                    let add_btn = ui.add(
                        Button::new(RichText::new("➕ Add to Share").text_style(TextStyle::Button).color(Color32::WHITE))
                            .fill(Color32::from_rgb(70, 130, 180))
                    );
                    add_btn.clone().on_hover_text("Add this file to the shared files list");

                    if add_btn.clicked() {
                        self.add_file_to_share(ui.ctx());
                    }

                    if self.is_accepting {
                        ui.add_space(5.0);

                        let view_btn = ui.add(
                            Button::new(RichText::new("👁 View Logs").text_style(TextStyle::Button).color(Color32::WHITE))
                                .fill(Color32::from_rgb(100, 150, 200))
                        );
                        view_btn.clone().on_hover_text("View terminal logs");

                        if view_btn.clicked() {
                            self.show_terminal_view = !self.show_terminal_view;
                        }

                        ui.add_space(5.0);

                        let stop_btn = ui.add(
                            Button::new(RichText::new("⏹ Stop").text_style(TextStyle::Button).color(Color32::WHITE))
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
                let available_height = ui.available_height() - 30.0; // Reserve space for footer

                egui::ScrollArea::vertical()
                    .max_height(available_height)
                    .show(ui, |ui| {
                    ui.vertical_centered(|ui| {
                        ui.heading(RichText::new("P2P File Sharing").size(24.0));
                        ui.label("Easily share files with a secure peer-to-peer connection");
                        ui.add_space(5.0);
                    });

                    ui.horizontal_centered(|ui| {
                    let btn = ui.add_sized(
                        Vec2::new(200.0, 40.0),
                        egui::Button::new(RichText::new("Choose File").size(16.0).color(Color32::WHITE))
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
                        egui::Button::new(RichText::new("Receive").size(16.0).color(Color32::WHITE))
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

                            // Save directory selection
                            ui.label(RichText::new("Select folder to save files:").strong());
                            ui.add_space(5.0);

                            ui.horizontal(|ui| {
                                if let Ok(save_dir) = self.save_directory.lock() {
                                    if let Some(dir) = save_dir.as_ref() {
                                        ui.label(RichText::new(format!("📁 {}", dir)).color(Color32::from_rgb(100, 200, 100)));
                                    } else {
                                        ui.label(RichText::new("No folder selected").color(Color32::from_rgb(200, 100, 100)));
                                    }
                                }

                                #[cfg(not(target_arch = "wasm32"))]
                                {
                                    let select_folder_btn = ui.add(
                                        Button::new(RichText::new("📂 Select Folder").color(Color32::WHITE))
                                            .fill(Color32::from_rgb(70, 130, 180))
                                    );

                                    if select_folder_btn.clicked() {
                                        use rfd::FileDialog;
                                        if let Some(folder) = FileDialog::new().pick_folder() {
                                            if let Ok(mut save_dir) = self.save_directory.lock() {
                                                *save_dir = Some(folder.to_string_lossy().to_string());
                                            }
                                        }
                                    }
                                }
                            });

                            ui.add_space(10.0);

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
                                let is_receiving = self.is_receiving.lock().map(|r| *r).unwrap_or(false);
                                let has_save_dir = self.save_directory.lock().ok()
                                    .and_then(|d| d.as_ref().map(|_| true))
                                    .unwrap_or(false);

                                if !is_receiving {
                                    let mut connect_btn = ui.add_enabled(
                                        has_save_dir,
                                        Button::new(RichText::new("Connect").color(Color32::WHITE))
                                            .fill(Color32::from_rgb(50, 150, 100))
                                    );

                                    if !has_save_dir {
                                        connect_btn = connect_btn.on_hover_text("Please select a folder first");
                                    }

                                    if connect_btn.clicked() {
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
                                    let refresh_btn = ui.add(
                                        Button::new(RichText::new("🔄 Refresh Files").text_style(TextStyle::Button).color(Color32::WHITE))
                                            .fill(Color32::from_rgb(50, 150, 200))
                                    );
                                    refresh_btn.clone().on_hover_text("Check for new files from sender");

                                    if refresh_btn.clicked() {
                                        if let Ok(node_id) = self.receive_hash_input.parse::<NodeId>() {
                                            self.reconnect_for_files(ctx, node_id);
                                        }
                                    }

                                    ui.add_space(5.0);

                                    let view_btn = ui.add(
                                        Button::new(RichText::new("👁 View Logs").text_style(TextStyle::Button).color(Color32::WHITE))
                                            .fill(Color32::from_rgb(100, 150, 200))
                                    );
                                    view_btn.clone().on_hover_text("View terminal logs");

                                    if view_btn.clicked() {
                                        self.show_terminal_view = !self.show_terminal_view;
                                    }

                                    ui.add_space(5.0);

                                    let stop_btn = ui.add(
                                        Button::new(RichText::new("⏹ Stop").text_style(TextStyle::Button).color(Color32::WHITE))
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

                // Show shared files section
                self.show_shared_files(ui, ctx);

                // Show connection status and hash
                self.show_connection_status(ui);

                // Show received files section
                self.show_received_files(ui);
                });

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