use serde::{Deserialize, Serialize};
use std::{
    fs, io,
    path::{Path, PathBuf},
};

pub trait ResourceBackend {
    fn read(&mut self, resource: &str) -> io::Result<Option<String>>;
    fn write(&mut self, resource: &str, value: Option<&str>) -> io::Result<()>;
    fn owner_alive(&self, pid: u32) -> io::Result<bool>;
    fn create_journal(&self, path: &Path) -> io::Result<fs::File> {
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
    }
}

pub struct JournalLease(fs::File);

impl JournalLease {
    pub fn acquire(directory: &Path) -> io::Result<Self> {
        let path = directory.join("resources.lock");
        let file = match create_privileged_journal(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let mut options = fs::OpenOptions::new();
                options.read(true).write(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.custom_flags(libc::O_NOFOLLOW);
                }
                #[cfg(windows)]
                {
                    use std::os::windows::fs::OpenOptionsExt;
                    options.custom_flags(
                        windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT,
                    );
                }
                options.open(path)?
            }
            Err(error) => return Err(error),
        };
        if !file.metadata()?.is_file() {
            return Err(io::Error::other("Journal lease is not a regular file"));
        }
        Self::lock(file)
    }

    pub fn lock(file: fs::File) -> io::Result<Self> {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            use windows_sys::Win32::{Storage::FileSystem::LockFileEx, System::IO::OVERLAPPED};
            let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
            if unsafe {
                LockFileEx(
                    file.as_raw_handle(),
                    3,
                    0,
                    u32::MAX,
                    u32::MAX,
                    &mut overlapped,
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(Self(file))
    }
}

impl Drop for JournalLease {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            use windows_sys::Win32::{Storage::FileSystem::UnlockFileEx, System::IO::OVERLAPPED};
            let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
            unsafe {
                UnlockFileEx(
                    self.0.as_raw_handle(),
                    0,
                    u32::MAX,
                    u32::MAX,
                    &mut overlapped,
                )
            };
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Change {
    resource: String,
    before: Option<String>,
    installed: String,
}

#[derive(Serialize, Deserialize)]
struct Record {
    version: u8,
    pid: u32,
    changes: Vec<Change>,
}

pub struct OwnedResources<B: ResourceBackend> {
    backend: B,
    path: Option<PathBuf>,
    record: Record,
}

impl<B: ResourceBackend> OwnedResources<B> {
    pub fn install(
        mut backend: B,
        path: Option<PathBuf>,
        plan: Vec<(String, String)>,
        replace: bool,
    ) -> io::Result<Self> {
        if let Some(path) = path.as_ref() {
            Self::recover(&mut backend, path)?;
        }
        let mut owned = Self {
            backend,
            path,
            record: Record {
                version: 1,
                pid: std::process::id(),
                changes: Vec::new(),
            },
        };
        for (resource, installed) in plan {
            let result = (|| {
                let before = owned.backend.read(&resource)?;
                if before.as_ref() == Some(&installed) {
                    return Ok(());
                }
                if !replace && before.is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        format!("Resource conflict: {resource}"),
                    ));
                }
                owned.record.changes.push(Change {
                    resource: resource.clone(),
                    before,
                    installed: installed.clone(),
                });
                owned.persist()?;
                owned.backend.write(&resource, Some(&installed))?;
                if owned.backend.read(&resource)?.as_ref() != Some(&installed) {
                    return Err(io::Error::other(format!(
                        "Resource installation not confirmed: {resource}"
                    )));
                }
                Ok(())
            })();
            if let Err(error) = result {
                return match owned.cleanup() {
                    Ok(()) => Err(error),
                    Err(cleanup) => Err(io::Error::other(format!(
                        "{error}; resources_release_unconfirmed: {cleanup}"
                    ))),
                };
            }
        }
        Ok(owned)
    }

    pub fn cleanup(&mut self) -> io::Result<()> {
        let mut pending = Vec::new();
        let mut errors = Vec::new();
        for change in self.record.changes.drain(..).rev() {
            let result = (|| {
                let current = self.backend.read(&change.resource)?;
                if current.as_ref() != Some(&change.installed) {
                    return Ok(());
                }
                self.backend
                    .write(&change.resource, change.before.as_deref())?;
                if self.backend.read(&change.resource)? != change.before {
                    return Err(io::Error::other("Restoration not confirmed"));
                }
                Ok(())
            })();
            if let Err(error) = result {
                errors.push(format!("{}: {error}", change.resource));
                pending.push(change);
            }
        }
        pending.reverse();
        self.record.changes = pending;
        self.persist()?;
        if errors.is_empty() {
            Ok(())
        } else {
            Err(io::Error::other(errors.join("; ")))
        }
    }

    pub fn recover(backend: &mut B, path: &Path) -> io::Result<()> {
        match fs::symlink_metadata(path) {
            Ok(metadata) if !metadata.is_file() || metadata.file_type().is_symlink() => {
                return Err(io::Error::other("Resource journal is not a regular file"))
            }
            Ok(metadata) if metadata.len() > 1024 * 1024 => {
                return Err(io::Error::other("Resource journal exceeds its size limit"))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
            _ => {}
        }
        let record = match fs::read(path) {
            Ok(bytes) if bytes.len() <= 1024 * 1024 => {
                serde_json::from_slice::<Record>(&bytes).map_err(io::Error::other)?
            }
            Ok(_) => return Err(io::Error::other("Resource journal exceeds its size limit")),
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        };
        if record.version != 1 {
            return Err(io::Error::other("Unknown resource journal version"));
        }
        if backend.owner_alive(record.pid)? {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "A live process owns these network resources",
            ));
        }
        let mut pending = Vec::new();
        let mut errors = Vec::new();
        for change in record.changes {
            let result = (|| {
                if backend.read(&change.resource)?.as_ref() == Some(&change.installed) {
                    backend.write(&change.resource, change.before.as_deref())?;
                    if backend.read(&change.resource)? != change.before {
                        return Err(io::Error::other(
                            "Residual resource restoration not confirmed",
                        ));
                    }
                }
                Ok(())
            })();
            if let Err(error) = result {
                errors.push(format!("{}: {error}", change.resource));
                pending.push(change);
            }
        }
        save(
            backend,
            path,
            &Record {
                version: 1,
                pid: record.pid,
                changes: pending,
            },
        )?;
        if errors.is_empty() {
            Ok(())
        } else {
            Err(io::Error::other(errors.join("; ")))
        }
    }

    fn persist(&self) -> io::Result<()> {
        match &self.path {
            Some(path) => save(&self.backend, path, &self.record),
            None => Ok(()),
        }
    }
}

fn save(backend: &impl ResourceBackend, path: &Path, record: &Record) -> io::Result<()> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(io::Error::other("Resource journal is not a regular file"));
        }
    }
    if record.changes.is_empty() {
        return match fs::remove_file(path) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
            _ => Ok(()),
        };
    }
    let pending = path.with_extension("pending");
    match fs::remove_file(&pending) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
        _ => {}
    }
    let mut file = backend.create_journal(&pending)?;
    serde_json::to_writer(&mut file, record).map_err(io::Error::other)?;
    file.sync_all()?;
    drop(file);
    #[cfg(unix)]
    {
        fs::rename(&pending, path)?;
        fs::File::open(
            path.parent()
                .ok_or_else(|| io::Error::other("Journal has no directory"))?,
        )?
        .sync_all()
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn MoveFileExW(from: *const u16, to: *const u16, flags: u32) -> i32;
        }
        let from: Vec<u16> = pending.as_os_str().encode_wide().chain(Some(0)).collect();
        let to: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), 1 | 8) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

pub(super) fn create_privileged_journal(path: &Path) -> io::Result<fs::File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
    }
    #[cfg(windows)]
    {
        use std::os::windows::{ffi::OsStrExt, io::FromRawHandle};
        use windows_sys::Win32::{
            Foundation::{LocalFree, GENERIC_WRITE, INVALID_HANDLE_VALUE},
            Security::{
                Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW,
                SECURITY_ATTRIBUTES,
            },
            Storage::FileSystem::{
                CreateFileW, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
            },
        };
        let descriptor: Vec<u16> = "O:BAG:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;0x80;;;BU)"
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let mut security = std::ptr::null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                descriptor.as_ptr(),
                1,
                &mut security,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: security,
            bInheritHandle: 0,
        };
        let path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let handle = unsafe {
            CreateFileW(
                path.as_ptr(),
                GENERIC_WRITE,
                FILE_SHARE_READ,
                &attributes,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                std::ptr::null_mut(),
            )
        };
        let error = if handle == INVALID_HANDLE_VALUE {
            Some(io::Error::last_os_error())
        } else {
            None
        };
        unsafe { LocalFree(security) };
        match error {
            Some(error) => Err(error),
            None => Ok(unsafe { fs::File::from_raw_handle(handle) }),
        }
    }
}

pub(super) fn owner_alive(pid: u32) -> io::Result<bool> {
    #[cfg(unix)]
    {
        let result = unsafe { libc::kill(pid.try_into().map_err(io::Error::other)?, 0) };
        if result == 0 {
            return Ok(true);
        }
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::ESRCH) => Ok(false),
            Some(libc::EPERM) => Ok(true),
            _ => Err(error),
        }
    }
    #[cfg(windows)]
    {
        Ok(!powershell(&format!(
            "if (Get-Process -Id {pid} -ErrorAction SilentlyContinue) {{ 'alive' }}"
        ))?
        .is_empty())
    }
}

#[cfg(windows)]
pub fn powershell(script: &str) -> io::Result<String> {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetSystemDirectoryW(buffer: *mut u16, size: u32) -> u32;
    }
    let mut buffer = [0u16; 32768];
    let size = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) };
    if size == 0 || size as usize >= buffer.len() {
        return Err(io::Error::last_os_error());
    }
    let executable =
        PathBuf::from(String::from_utf16(&buffer[..size as usize]).map_err(io::Error::other)?)
            .join("WindowsPowerShell/v1.0/powershell.exe");
    let mut command = std::process::Command::new(executable);
    command.args([
        "-NoProfile", "-NonInteractive", "-Command",
        &format!("[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); $ErrorActionPreference='Stop'; {script}"),
    ]);
    let output = owned_command_output(&mut command, std::time::Duration::from_secs(20))?;
    if !output.status.success() {
        return Err(io::Error::other(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

pub fn owned_command_output(
    command: &mut std::process::Command,
    timeout: std::time::Duration,
) -> io::Result<std::process::Output> {
    use std::{io::Read, process::Stdio, time::Instant};
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let (exceeded, errors) = std::sync::mpsc::channel();
    let read = |pipe: &mut dyn Read, exceeded: std::sync::mpsc::Sender<()>| {
        let mut bytes = Vec::new();
        pipe.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
        if bytes.len() > 1024 * 1024 {
            let _ = exceeded.send(());
            return Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                "Native command output exceeded 1 MiB",
            ));
        }
        Ok(bytes)
    };
    std::thread::scope(|scope| {
        let output_exceeded = exceeded.clone();
        let output = scope.spawn(move || read(&mut { stdout }, output_exceeded));
        let error = scope.spawn(move || read(&mut { stderr }, exceeded));
        let deadline = Instant::now() + timeout;
        let status = loop {
            if errors.try_recv().is_ok() {
                break Err(io::Error::new(
                    io::ErrorKind::FileTooLarge,
                    "Native command output exceeded 1 MiB",
                ));
            }
            match child.try_wait() {
                Ok(Some(status)) => break Ok(status),
                Ok(None) => {}
                Err(error) => break Err(error),
            }
            if Instant::now() >= deadline {
                break Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Native command did not finish before its cleanup deadline",
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        if status.is_err() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let stdout = output
            .join()
            .map_err(|_| io::Error::other("Native stdout reader failed"))?;
        let stderr = error
            .join()
            .map_err(|_| io::Error::other("Native stderr reader failed"))?;
        Ok(std::process::Output {
            status: status?,
            stdout: stdout?,
            stderr: stderr?,
        })
    })
}
