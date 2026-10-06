//! Optional descriptor-bound product storage; ordinary CLI storage is unchanged.

use std::{fs::File, io, path::Path};

#[cfg(unix)]
#[path = "managed_files/unix.rs"]
mod unix;
#[cfg(unix)]
pub use unix::{authorize_home, ManagedHome};

#[cfg(windows)]
#[path = "managed_files/windows.rs"]
mod windows;
#[cfg(windows)]
#[path = "managed_files/windows_caller.rs"]
mod windows_caller;
#[cfg(windows)]
pub use windows::{authorize_home_windows, ManagedHome};
#[cfg(windows)]
pub use windows_caller::WindowsCaller;

pub fn is_managed() -> bool {
    #[cfg(unix)]
    {
        unix::home().is_some()
    }
    #[cfg(windows)]
    {
        windows::home().is_some()
    }
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

pub fn open(path: &Path) -> io::Result<File> {
    #[cfg(unix)]
    if let Some(home) = unix::home() {
        return home.open_file(path);
    }
    #[cfg(windows)]
    if let Some(home) = windows::home() {
        return home.open_file(path);
    }
    File::open(path)
}

pub fn read(path: &Path) -> io::Result<Vec<u8>> {
    use std::io::Read;
    let mut bytes = Vec::new();
    open(path)?.read_to_end(&mut bytes)?;
    Ok(bytes)
}

pub fn read_to_string(path: &Path) -> io::Result<String> {
    String::from_utf8(read(path)?).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

pub async fn read_async(path: &Path) -> io::Result<Vec<u8>> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || read(&path))
        .await
        .map_err(io::Error::other)?
}

pub async fn read_to_string_async(path: &Path) -> io::Result<String> {
    String::from_utf8(read_async(path).await?)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

pub fn write_atomic_if_managed(path: &Path, bytes: &[u8]) -> Option<io::Result<()>> {
    #[cfg(unix)]
    {
        unix::home().map(|home| home.write_atomic(path, bytes))
    }
    #[cfg(windows)]
    {
        windows::home().map(|home| home.write_atomic(path, bytes))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (path, bytes);
        None
    }
}

pub async fn write_atomic_if_managed_async(path: &Path, bytes: &[u8]) -> Option<io::Result<()>> {
    if !is_managed() {
        return None;
    }
    let path = path.to_path_buf();
    let bytes = bytes.to_vec();
    Some(
        tokio::task::spawn_blocking(move || {
            write_atomic_if_managed(&path, &bytes)
                .expect("The product home policy cannot be removed")
        })
        .await
        .map_err(io::Error::other)
        .and_then(std::convert::identity),
    )
}
