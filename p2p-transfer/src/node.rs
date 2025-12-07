use iroh::endpoint::Connection;
use iroh::{Endpoint, NodeId, TransportMode};
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use tokio::sync::broadcast;
use anyhow::Result;
use async_channel::Sender;
use log::info;
use n0_future::boxed::BoxFuture;
use n0_future::{task, Stream};
use std::sync::atomic::{AtomicUsize, Ordering};

pub struct EchoNode{
    router: Router,
    accept_events: broadcast::Sender<AcceptEvent>,
    shared_files: std::sync::Arc<std::sync::Mutex<Vec<(String, Vec<u8>)>>>,
}

impl EchoNode {
    pub async fn spawn() -> Result<Self> {
        Self::spawn_with_files(Vec::new()).await
    }

    pub async fn spawn_with_files(files: Vec<(String, Vec<u8>)>) -> Result<Self> {

        let endpoint = Endpoint::builder()
            .discovery_n0()
            .alpns(vec![Echo::ALPN.to_vec()])
            .bind_transport(TransportMode::WebrtcRelay)
            .await?;
        let (event_sender, _event_receiver) = broadcast::channel(128);
        let echo = Echo::new(event_sender.clone(), files);
        let shared_files = echo.files.clone();
        let router = Router::builder(endpoint)
            .accept(Echo::ALPN, echo)
            .spawn();
        Ok(Self { router, accept_events: event_sender, shared_files })


    }

    pub fn endpoint(&self) -> &Endpoint {
        self.router.endpoint()
    }

    pub fn get_shared_files(&self) -> std::sync::Arc<std::sync::Mutex<Vec<(String, Vec<u8>)>>> {
        self.shared_files.clone()
    }

    pub fn connect(
        &self,
        node_id: NodeId,
        file_data: Vec<u8>,
        file_name: String
    ) -> impl Stream<Item = ConnectEvent> + Unpin {

        let (event_sender, event_receiver) = async_channel::bounded(16);
        let endpoint = self.router.endpoint().clone();
        task::spawn(async move {
            let res = connect(&endpoint, node_id, file_data, file_name, event_sender.clone()).await;
            let error = res.as_ref().err().map(|e| e.to_string());
            event_sender.send(ConnectEvent::Closed {error}).await.ok();
        });
        Box::pin(event_receiver)
    }
}

#[derive(Debug)]
pub enum ConnectEvent {
    Connected,
    Sent {bytes_sent: u64},
    FileStart {
        file_name: String,
        file_size: u64,
        total_chunks: u32,
    },
    ChunkReceived {
        file_name: String,
        chunk_index: u32,
        chunk_data: Vec<u8>,
        offset: u64,
    },
    FileComplete {
        file_name: String,
        total_bytes: u64,
    },
    Closed {error: Option<String>}
}

#[derive(Debug, Clone)]
pub enum AcceptEvent {

    Accepted {
        node_id: NodeId,
    },
    Echoed {
        node_id: NodeId,
        bytes_sent: u64
    },
    Closed {
        node_id: NodeId,
        error: Option<String>
    }
}

#[derive(Debug, Clone)]
pub struct Echo{
    event_sender: broadcast::Sender<AcceptEvent>,
    files: std::sync::Arc<std::sync::Mutex<Vec<(String, Vec<u8>)>>>, // (filename, filedata)
    current_file_index: std::sync::Arc<AtomicUsize>, // Round-robin index
}

impl Echo{
    pub const ALPN: &[u8] = b"iroh/example-browser-echo/0";
    pub fn new(
        event_sender: broadcast::Sender<AcceptEvent>,
        files: Vec<(String, Vec<u8>)>
    ) -> Self {

        Self {
            event_sender,
            files: std::sync::Arc::new(std::sync::Mutex::new(files)),
            current_file_index: std::sync::Arc::new(AtomicUsize::new(0)),
        }

    }
}impl Echo {
    async fn handle_connection(self, connection: Connection) -> std::result::Result<(), AcceptError> {

        let node_id  = connection.remote_node_id()?;
        self.event_sender.send(AcceptEvent::Accepted {node_id }).ok();
        let res = self.handle_connection_0(&connection).await;
        let error = res.as_ref().err().map(|err| err.to_string());
        self.event_sender.send(AcceptEvent::Closed {node_id, error}).ok();
        res


    }

    async fn handle_connection_0(&self, connection: &Connection) -> std::result::Result<(), AcceptError> {
        const CHUNK_SIZE: usize = 256 * 1024; // 256 KB chunks

        let node_id = connection.remote_node_id()?;
        info!("Accepted connection from {}", node_id);

        let (mut send, mut recv) = connection.accept_bi().await?;

        // Read filename length
        let mut name_len_buf = [0u8; 4];
        recv.read_exact(&mut name_len_buf).await.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        let name_len = u32::from_le_bytes(name_len_buf) as usize;

        // Read filename
        let mut name_buf = vec![0u8; name_len];
        recv.read_exact(&mut name_buf).await.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        let _received_file_name = String::from_utf8(name_buf).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        // Read file data length
        let mut data_len_buf = [0u8; 8];
        recv.read_exact(&mut data_len_buf).await.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        let data_len = u64::from_le_bytes(data_len_buf) as usize;

        // Read file data
        let mut _received_file_data = vec![0u8; data_len];
        recv.read_exact(&mut _received_file_data).await.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        info!("Received request from receiver");

        // Get all files to send
        let files_to_send = if let Ok(files) = self.files.lock() {
            if !files.is_empty() {
                files.clone()
            } else {
                // Fallback: echo back what was received
                vec![(_received_file_name, _received_file_data)]
            }
        } else {
            // Fallback: echo back what was received
            vec![(_received_file_name, _received_file_data)]
        };

        // First, send the number of files
        let num_files = files_to_send.len() as u32;
        send.write_all(&num_files.to_le_bytes()).await.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        info!("Sending {} files", num_files);

        let mut total_bytes_sent = 4; // for num_files

        // Send all files in chunks
        for (idx, (name, data)) in files_to_send.iter().enumerate() {
            info!("Sending file {} of {}: {}", idx + 1, num_files, name);

            let name_bytes = name.as_bytes();
            let name_len = name_bytes.len() as u32;
            let data_len = data.len() as u64;
            let total_chunks = ((data_len + CHUNK_SIZE as u64 - 1) / CHUNK_SIZE as u64) as u32;

            // Send file metadata: name_len, name, data_len, total_chunks
            send.write_all(&name_len.to_le_bytes()).await.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
            send.write_all(name_bytes).await.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
            send.write_all(&data_len.to_le_bytes()).await.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
            send.write_all(&total_chunks.to_le_bytes()).await.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

            total_bytes_sent += 4 + name_bytes.len() + 8 + 4;

            // Send file data in chunks
            for chunk_idx in 0..total_chunks {
                let offset = chunk_idx as usize * CHUNK_SIZE;
                let chunk_size = std::cmp::min(CHUNK_SIZE, data.len() - offset);
                let chunk_data = &data[offset..offset + chunk_size];

                // Send: chunk_index (u32), chunk_size (u32), chunk_data
                send.write_all(&chunk_idx.to_le_bytes()).await.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
                send.write_all(&(chunk_size as u32).to_le_bytes()).await.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
                send.write_all(chunk_data).await.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

                total_bytes_sent += 4 + 4 + chunk_size;
                info!("Sent chunk {}/{} of file: {} ({} bytes)", chunk_idx + 1, total_chunks, name, chunk_size);
            }

            info!("Sent file: {} ({} bytes in {} chunks)", name, data.len(), total_chunks);
        }

        let bytes_sent = total_bytes_sent;

        self.event_sender.send(AcceptEvent::Echoed {node_id, bytes_sent: bytes_sent as u64}).ok();

        send.finish()?;
        connection.closed().await;
        Ok(())


    }
}

impl ProtocolHandler for Echo{
    #[allow(refining_impl_trait)]
    fn accept(&self, connection: Connection) -> BoxFuture<std::result::Result<(), AcceptError>> {
        Box::pin(self.clone().handle_connection(connection))
    }
}

async fn connect(
    endpoint: &Endpoint,
    node_id: NodeId,
    file_data: Vec<u8>,
    file_name: String,
    event_sender: Sender<ConnectEvent>
) -> Result<()>{

    let connection = endpoint.connect(node_id, Echo::ALPN).await?;
    event_sender.send(ConnectEvent::Connected).await?;
    let (mut send_stream , mut recv_stream) = connection.open_bi().await?;
    let event_sender_clone = event_sender.clone();

    let send_task = task::spawn(async move {
        // First send the filename length as u32
        let name_bytes = file_name.as_bytes();
        let name_len = name_bytes.len() as u32;
        send_stream.write_all(&name_len.to_le_bytes()).await?;

        // Send the filename
        send_stream.write_all(name_bytes).await?;

        // Send the file data length as u64
        let data_len = file_data.len() as u64;
        send_stream.write_all(&data_len.to_le_bytes()).await?;

        // Send the file data
        send_stream.write_all(&file_data).await?;

        let bytes_sent = 4 + name_bytes.len() + 8 + file_data.len();
        event_sender_clone.send(ConnectEvent::Sent {
            bytes_sent: bytes_sent as u64,
        })
            .await?;

        send_stream.finish()?;
        anyhow::Ok(())
    });

    // First, read the number of files
    let mut num_files_buf = [0u8; 4];
    recv_stream.read_exact(&mut num_files_buf).await?;
    let num_files = u32::from_le_bytes(num_files_buf) as usize;

    // Read all files in chunks
    for _ in 0..num_files {
        // Read file metadata
        let mut name_len_buf = [0u8; 4];
        recv_stream.read_exact(&mut name_len_buf).await?;
        let name_len = u32::from_le_bytes(name_len_buf) as usize;

        let mut name_buf = vec![0u8; name_len];
        recv_stream.read_exact(&mut name_buf).await?;
        let received_file_name = String::from_utf8(name_buf)?;

        let mut data_len_buf = [0u8; 8];
        recv_stream.read_exact(&mut data_len_buf).await?;
        let data_len = u64::from_le_bytes(data_len_buf);

        let mut total_chunks_buf = [0u8; 4];
        recv_stream.read_exact(&mut total_chunks_buf).await?;
        let total_chunks = u32::from_le_bytes(total_chunks_buf);

        // Notify that file transfer is starting
        event_sender.send(ConnectEvent::FileStart {
            file_name: received_file_name.clone(),
            file_size: data_len,
            total_chunks,
        }).await?;

        // Read all chunks for this file
        let mut total_bytes_received = 0u64;
        for _ in 0..total_chunks {
            // Read chunk metadata
            let mut chunk_idx_buf = [0u8; 4];
            recv_stream.read_exact(&mut chunk_idx_buf).await?;
            let chunk_index = u32::from_le_bytes(chunk_idx_buf);

            let mut chunk_size_buf = [0u8; 4];
            recv_stream.read_exact(&mut chunk_size_buf).await?;
            let chunk_size = u32::from_le_bytes(chunk_size_buf) as usize;

            // Read chunk data
            let mut chunk_data = vec![0u8; chunk_size];
            recv_stream.read_exact(&mut chunk_data).await?;

            let offset = chunk_index as u64 * 256 * 1024; // 256KB chunk size
            total_bytes_received += chunk_size as u64;

            // Send chunk received event
            event_sender.send(ConnectEvent::ChunkReceived {
                file_name: received_file_name.clone(),
                chunk_index,
                chunk_data,
                offset,
            }).await?;
        }

        // Notify that file transfer is complete
        event_sender.send(ConnectEvent::FileComplete {
            file_name: received_file_name,
            total_bytes: total_bytes_received,
        }).await?;
    }

    connection.close(1u8.into(), b"done");

    send_task.await??;
    Ok(())

}