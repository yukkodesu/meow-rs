use std::{
    ffi::{CString, OsStr},
    fs::File,
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Component, Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex, OnceLock,
    },
};

static HOME: OnceLock<ManagedHome> = OnceLock::new();
static SCRATCH: AtomicUsize = AtomicUsize::new(0);

pub(super) fn home() -> Option<&'static ManagedHome> {
    HOME.get()
}

pub fn authorize_home(path: &Path, uid: u32, gid: u32) -> io::Result<PathBuf> {
    let home = ManagedHome::open(path, uid, gid)?;
    let path = home.path.clone();
    if let Err(candidate) = HOME.set(home) {
        let current = HOME.get().expect("An installed home cannot be removed");
        if current.path != candidate.path
            || current.uid != uid
            || current.gid != gid
            || current.root.metadata()?.ino() != candidate.root.metadata()?.ino()
            || current.root.metadata()?.dev() != candidate.root.metadata()?.dev()
        {
            return Err(denied("A host process cannot change its authorized home"));
        }
    }
    Ok(path)
}

pub struct ManagedHome {
    path: PathBuf,
    root: File,
    uid: u32,
    gid: u32,
    directories: Mutex<()>,
}

impl ManagedHome {
    pub fn open(path: &Path, uid: u32, gid: u32) -> io::Result<Self> {
        if !path.is_absolute() {
            return Err(denied(
                "The product home must be absolute and already exist",
            ));
        }
        if !std::fs::symlink_metadata(path)?.is_dir() {
            return Err(denied(
                "The product home must be an existing ordinary directory",
            ));
        }
        let path = path.canonicalize()?;
        let mut root = File::open("/")?;
        for component in path.components() {
            if let Component::Normal(name) = component {
                root = open_at(&root, name, libc::O_RDONLY | libc::O_DIRECTORY)?;
            }
        }
        require_directory(&root, uid)?;
        Ok(Self {
            path,
            root,
            uid,
            gid,
            directories: Mutex::new(()),
        })
    }

    pub fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        self.open_file(path)?.read_to_end(&mut bytes)?;
        Ok(bytes)
    }

    pub fn open_file(&self, path: &Path) -> io::Result<File> {
        let (parent, name) = self.parent(path, false)?;
        let file = open_at(&parent, &name, libc::O_RDONLY | libc::O_NONBLOCK)?;
        require_file(&file, self.uid)?;
        Ok(file)
    }

    pub fn write_atomic(&self, path: &Path, bytes: &[u8]) -> io::Result<()> {
        let (parent, name) = self.parent(path, true)?;
        match open_at(&parent, &name, libc::O_RDONLY | libc::O_NONBLOCK) {
            Ok(file) => require_file(&file, self.uid)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let name = c_string(&name)?;
        let temporary = CString::new(format!(
            ".meow-managed-{}-{}.tmp",
            std::process::id(),
            SCRATCH.fetch_add(1, Ordering::Relaxed)
        ))?;
        let mut file = open_at(
            &parent,
            OsStr::from_bytes(temporary.as_bytes()),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        )?;
        let scratch = Scratch {
            parent: &parent,
            name: temporary,
        };
        file.write_all(bytes)?;
        set_owner(&file, self.uid, self.gid, 0o600)?;
        file.sync_all()?;
        syscall(unsafe {
            libc::renameat(
                parent.as_raw_fd(),
                scratch.name.as_ptr(),
                parent.as_raw_fd(),
                name.as_ptr(),
            )
        })?;
        parent.sync_all()?;
        Ok(())
    }

    fn parent(&self, path: &Path, create: bool) -> io::Result<(File, std::ffi::OsString)> {
        let _directories = self
            .directories
            .lock()
            .map_err(|error| io::Error::other(error.to_string()))?;
        let relative = if path.is_absolute() {
            path.strip_prefix(&self.path)
                .map_err(|_| denied("Managed paths must remain inside the authorized home"))?
        } else {
            path
        };
        let mut names = Vec::new();
        for component in relative.components() {
            match component {
                Component::Normal(name) => names.push(name),
                Component::CurDir => {}
                _ => return Err(denied("Parent traversal is forbidden in managed paths")),
            }
        }
        let name = names
            .pop()
            .ok_or_else(|| denied("A managed file name is required"))?;
        let mut parent = self.root.try_clone()?;
        for directory in names {
            let next = match open_at(&parent, directory, libc::O_RDONLY | libc::O_DIRECTORY) {
                Ok(file) => file,
                Err(error) if create && error.kind() == io::ErrorKind::NotFound => {
                    let name = c_string(directory)?;
                    let created =
                        unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) };
                    if created == -1
                        && io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists
                    {
                        return Err(io::Error::last_os_error());
                    }
                    let next = open_at(&parent, directory, libc::O_RDONLY | libc::O_DIRECTORY)?;
                    if created == 0 {
                        set_owner(&next, self.uid, self.gid, 0o700)?;
                    }
                    next
                }
                Err(error) => return Err(error),
            };
            require_directory(&next, self.uid)?;
            parent = next;
        }
        Ok((parent, name.to_os_string()))
    }
}

struct Scratch<'a> {
    parent: &'a File,
    name: CString,
}

impl Drop for Scratch<'_> {
    fn drop(&mut self) {
        unsafe {
            libc::unlinkat(self.parent.as_raw_fd(), self.name.as_ptr(), 0);
        }
    }
}

fn require_directory(file: &File, uid: u32) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_dir() || metadata.uid() != uid || metadata.mode() & 0o022 != 0 {
        return Err(denied("Managed directories must be owned by the authenticated caller and not writable by others"));
    }
    Ok(())
}

fn require_file(file: &File, uid: u32) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.uid() != uid || metadata.nlink() != 1 {
        return Err(denied(
            "Managed files must be ordinary caller-owned files without hard links",
        ));
    }
    Ok(())
}

fn set_owner(file: &File, uid: u32, gid: u32, mode: libc::mode_t) -> io::Result<()> {
    let metadata = file.metadata()?;
    if metadata.uid() != uid || metadata.gid() != gid {
        syscall(unsafe { libc::fchown(file.as_raw_fd(), uid, gid) })?;
    }
    syscall(unsafe { libc::fchmod(file.as_raw_fd(), mode) })
}

fn open_at(parent: &File, name: &OsStr, flags: libc::c_int) -> io::Result<File> {
    let name = c_string(name)?;
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if descriptor == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn c_string(name: &OsStr) -> io::Result<CString> {
    CString::new(name.as_bytes()).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
}

fn syscall(result: libc::c_int) -> io::Result<()> {
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn denied(reason: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, reason)
}
