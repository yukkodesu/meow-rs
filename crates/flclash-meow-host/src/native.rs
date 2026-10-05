use meow_listener::tun::{RecoveryState, RecoveryStatus};
use std::{fs, io, path::PathBuf};

pub fn recover_existing_product_resources() -> RecoveryStatus {
    let result = (|| {
        let path = product_recovery_path()?;
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
            Ok(_) => {}
        }
        if !privileged() {
            for name in ["dns.json", "routes.json"] {
                match fs::symlink_metadata(path.join(name)) {
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error),
                    Ok(_) => {
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "Privilege is required to inspect and restore recorded TUN state",
                        ))
                    }
                }
            }
            return Ok(false);
        }
        let path = recovery_directory()?;
        meow_listener::tun::recover_tun_resources(&path)
    })();
    match result {
        Ok(found) => RecoveryStatus {
            state: if found {
                RecoveryState::Recovered
            } else {
                RecoveryState::Clean
            },
            details: Vec::new(),
        },
        Err(error) => RecoveryStatus {
            state: if error.kind() == io::ErrorKind::PermissionDenied || !privileged() {
                RecoveryState::NeedsPrivilege
            } else {
                RecoveryState::Failed
            },
            details: vec![format!("Cannot confirm previous TUN state: {error}")],
        },
    }
}
pub fn recovery_directory() -> io::Result<PathBuf> {
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
        for name in [
            "dns.json",
            "routes.json",
            "dns.pending",
            "routes.pending",
            "resources.lock",
        ] {
            let metadata = match fs::symlink_metadata(path.join(name)) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            if !metadata.is_file()
                || metadata.uid() != 0
                || metadata.permissions().mode() & 0o077 != 0
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Recovery journal must be root-owned, private and not a symlink",
                ));
            }
        }
        Ok(path)
    }
    #[cfg(windows)]
    {
        let script = include_str!("recovery_directory.ps1");
        Ok(PathBuf::from(meow_listener::tun::ownership::powershell(
            script,
        )?))
    }
}

fn product_recovery_path() -> io::Result<PathBuf> {
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
        Ok(PathBuf::from(meow_listener::tun::ownership::powershell(
            "Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'FlClash-Meow/tun'",
        )?))
    }
}

fn privileged() -> bool {
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
