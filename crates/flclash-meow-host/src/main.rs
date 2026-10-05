use flclash_meow_host::{serve, Host};
use std::sync::Arc;
use tracing_subscriber::prelude::*;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let address = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("Usage: flclash-meow-host <IPC address>"))?;
    if address == "--version" {
        println!(
            "flclash-meow-host {} (meow-rs {}, {})",
            env!("CARGO_PKG_VERSION"),
            env!("MEOW_CORE_VERSION"),
            env!("MEOW_HOST_COMMIT")
        );
        return Ok(());
    }
    let host = Arc::new(Host::new());
    let (filter, reload) =
        tracing_subscriber::reload::Layer::new(tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::registry()
        .with(filter)
        .with(meow_api::log_stream::LogBroadcastLayer {
            tx: host.log_sender(),
        })
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .init();
    meow_api::log_stream::install_log_reloader(move |level| {
        let level = match level {
            "warning" => "warn",
            "silent" => "off",
            other => other,
        };
        reload
            .reload(tracing_subscriber::EnvFilter::try_new(level).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())
    });
    let stream = connect(&address).await?;
    let result =
        tokio::select! {result=serve(Arc::clone(&host),stream)=>result,_=shutdown_signal()=>Ok(())};
    host.shutdown().await;
    result?;
    Ok(())
}

#[cfg(windows)]
async fn connect(
    address: &str,
) -> anyhow::Result<tokio::net::windows::named_pipe::NamedPipeClient> {
    anyhow::ensure!(
        address.starts_with(r"\\.\pipe\FlClashMeowCore_"),
        "Unexpected product IPC address"
    );
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        match tokio::net::windows::named_pipe::ClientOptions::new().open(address) {
            Ok(stream) => return Ok(stream),
            Err(error)
                if tokio::time::Instant::now() < deadline
                    && (error.kind() == std::io::ErrorKind::NotFound
                        || error.raw_os_error() == Some(231)) =>
            {
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
            Err(error) => return Err(error.into()),
        }
    }
}

#[cfg(unix)]
async fn connect(address: &str) -> anyhow::Result<tokio::net::UnixStream> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let path = std::path::Path::new(address);
    anyhow::ensure!(
        path.file_name()
            .and_then(|s| s.to_str())
            .is_some_and(|s| s.starts_with("FlClashMeowSocket_")),
        "Unexpected product IPC address"
    );
    let metadata = std::fs::symlink_metadata(path)?;
    anyhow::ensure!(
        metadata.permissions().mode() & 0o077 == 0,
        "IPC socket must be private to its owner"
    );
    let stream = tokio::net::UnixStream::connect(path).await?;
    let peer = stream.peer_cred()?;
    anyhow::ensure!(
        peer.uid() == metadata.uid(),
        "IPC peer does not own the socket"
    );
    Ok(stream)
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        if let Ok(mut terminate) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            tokio::select! {_=terminate.recv()=>{},_=tokio::signal::ctrl_c()=>{}};
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}
