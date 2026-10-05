use serde::{Deserialize, Serialize};
use std::{
    fs, io,
    path::{Path, PathBuf},
};

pub trait ResourceBackend {
    fn read(&mut self, resource: &str) -> io::Result<Option<String>>;
    fn write(&mut self, resource: &str, value: Option<&str>) -> io::Result<()>;
    fn owner_alive(&self, pid: u32) -> io::Result<bool>;
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
            Some(path) => save(path, &self.record),
            None => Ok(()),
        }
    }
}

fn save(path: &Path, record: &Record) -> io::Result<()> {
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
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&pending)?;
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

pub fn flclash_meow_recovery_directory() -> io::Result<PathBuf> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let path = PathBuf::from(if cfg!(target_os = "macos") {
            "/Library/Application Support/FlClash-Meow/tun"
        } else {
            "/var/lib/flclash-meow/tun"
        });
        let parent = path
            .parent()
            .ok_or_else(|| io::Error::other("Invalid recovery directory"))?;
        for directory in [parent, path.as_path()] {
            match fs::create_dir(directory) {
                Ok(()) => fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
            let metadata = fs::symlink_metadata(directory)?;
            if !metadata.is_dir()
                || metadata.uid() != 0
                || metadata.permissions().mode() & 0o077 != 0
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Recovery directory must be root-owned, private and not a symlink",
                ));
            }
        }
        Ok(path)
    }
    #[cfg(windows)]
    {
        let script = r#"$ErrorActionPreference='Stop'; $base=[Environment]::GetFolderPath('CommonApplicationData'); $path=Join-Path $base 'FlClash-Meow'; foreach($directory in @($path,(Join-Path $path 'tun'))) { if (!(Test-Path -LiteralPath $directory)) { $null=New-Item -ItemType Directory -Path $directory; $acl=New-Object System.Security.AccessControl.DirectorySecurity; $acl.SetAccessRuleProtection($true,$false); $admin=New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544'); $system=New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18'); $acl.SetOwner($admin); foreach($sid in @($admin,$system)) { $rule=New-Object System.Security.AccessControl.FileSystemAccessRule($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow'); $acl.AddAccessRule($rule) }; Set-Acl -LiteralPath $directory -AclObject $acl }; $item=Get-Item -LiteralPath $directory; if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Recovery directory is a reparse point' }; $acl=Get-Acl -LiteralPath $directory; $owner=$acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value; if ($owner -notin @('S-1-5-32-544','S-1-5-18')) { throw 'Recovery directory has an untrusted owner' }; foreach($rule in $acl.Access) { $sid=$rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value; if ($rule.AccessControlType -eq 'Allow' -and $sid -notin @('S-1-5-32-544','S-1-5-18') -and ($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::Write)) { throw 'Recovery directory permits untrusted writes' } } }; Join-Path $path 'tun'"#;
        Ok(PathBuf::from(powershell(script)?))
    }
}

pub(super) fn product_recovery_path() -> io::Result<PathBuf> {
    #[cfg(unix)]
    {
        Ok(PathBuf::from(if cfg!(target_os = "macos") {
            "/Library/Application Support/FlClash-Meow/tun"
        } else {
            "/var/lib/flclash-meow/tun"
        }))
    }
    #[cfg(windows)]
    {
        Ok(PathBuf::from(powershell(
            "Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'FlClash-Meow/tun'",
        )?))
    }
}

pub(super) fn privileged() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(windows)]
    {
        #[link(name = "shell32")]
        unsafe extern "system" {
            fn IsUserAnAdmin() -> i32;
        }
        unsafe { IsUserAnAdmin() != 0 }
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
pub(super) fn powershell(script: &str) -> io::Result<String> {
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
    let output = std::process::Command::new(executable).args([
        "-NoProfile", "-NonInteractive", "-Command",
        &format!("[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); $ErrorActionPreference='Stop'; {script}"),
    ]).output()?;
    if !output.status.success() {
        return Err(io::Error::other(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}
