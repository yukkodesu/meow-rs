use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const MAX_FRAME_SIZE: usize = 64 * 1024 * 1024;

#[derive(Debug, Deserialize)]
pub struct Request {
    pub id: Option<String>,
    pub method: String,
    #[serde(default)]
    pub arguments: Value,
}

#[derive(Debug, Serialize)]
pub struct Response {
    pub id: Option<String>,
    pub result: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}

#[derive(Debug, thiserror::Error, Serialize)]
#[error("{message}")]
pub struct RpcError {
    pub code: String,
    pub message: String,
    pub details: Value,
}

impl RpcError {
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        Self { code: code.into(), message: message.into(), details: Value::Null }
    }
}

pub async fn read_frame(reader: &mut (impl AsyncRead + Unpin)) -> io::Result<Option<Vec<u8>>> {
    let mut header = [0; 4];
    if reader.read(&mut header[..1]).await? == 0 {
        return Ok(None);
    }
    reader.read_exact(&mut header[1..]).await?;
    let length = u32::from_le_bytes(header) as usize;
    if length == 0 || length > MAX_FRAME_SIZE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid IPC frame size"));
    }
    let mut frame = vec![0; length];
    reader.read_exact(&mut frame).await?;
    Ok(Some(frame))
}

pub async fn write_frame(writer: &mut (impl AsyncWrite + Unpin), frame: &[u8]) -> io::Result<()> {
    if frame.is_empty() || frame.len() > MAX_FRAME_SIZE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid IPC frame size"));
    }
    writer.write_all(&(frame.len() as u32).to_le_bytes()).await?;
    writer.write_all(frame).await?;
    writer.flush().await
}
