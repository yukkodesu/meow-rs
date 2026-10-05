use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io::{self, Read, Write},
    os::windows::{ffi::OsStrExt, io::FromRawHandle},
    path::{Component, Path, PathBuf, Prefix},
    ptr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex, OnceLock,
    },
};

use windows_sys::{
    Wdk::Storage::FileSystem::{FileRenameInformation, NtSetInformationFile},
    Win32::{
        Foundation::{
            LocalFree, RtlNtStatusToDosError, ERROR_ALREADY_EXISTS, GENERIC_READ, GENERIC_WRITE,
            INVALID_HANDLE_VALUE,
        },
        Security::{
            Authorization::{GetSecurityInfo, SE_FILE_OBJECT},
            InitializeSecurityDescriptor, SetSecurityDescriptorOwner, OWNER_SECURITY_INFORMATION,
            SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR,
        },
        Storage::FileSystem::{
            CreateDirectoryW, CreateFileW, FileDispositionInfo, GetFileInformationByHandle,
            GetFileType, GetFinalPathNameByHandleW, SetFileInformationByHandle,
            BY_HANDLE_FILE_INFORMATION, CREATE_NEW, DELETE, FILE_ATTRIBUTE_DIRECTORY,
            FILE_ATTRIBUTE_REPARSE_POINT, FILE_DISPOSITION_INFO, FILE_FLAG_BACKUP_SEMANTICS,
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_RENAME_INFO, FILE_SHARE_READ,
            FILE_TYPE_DISK, OPEN_EXISTING, READ_CONTROL,
        },
        System::{SystemServices::SECURITY_DESCRIPTOR_REVISION, IO::IO_STATUS_BLOCK},
    },
};

use super::windows_caller::{check, raw, WindowsCaller};

static HOME: OnceLock<ManagedHome> = OnceLock::new();
static SCRATCH: AtomicUsize = AtomicUsize::new(0);

pub(super) fn home() -> Option<&'static ManagedHome> {
    HOME.get()
}

pub fn authorize_home_windows(path: &Path, caller: &WindowsCaller) -> io::Result<PathBuf> {
    let home = ManagedHome::open(path, caller)?;
    let path = home.path.clone();
    if let Err(candidate) = HOME.set(home) {
        let current = HOME.get().expect("An installed home cannot be removed");
        if current.path != candidate.path
            || !current.caller.same_token(caller)
            || identity(current.root())? != identity(candidate.root())?
        {
            return Err(denied("A host process cannot change its authorized home"));
        }
    }
    Ok(path)
}

pub struct ManagedHome {
    path: PathBuf,
    requested_path: PathBuf,
    roots: Vec<File>,
    caller: WindowsCaller,
    directories: Mutex<()>,
}

impl ManagedHome {
    pub fn open(path: &Path, caller: &WindowsCaller) -> io::Result<Self> {
        let _authority = caller.enter()?;
        let mut components = path.components();
        let drive = match components.next() {
            Some(Component::Prefix(prefix))
                if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)) =>
            {
                PathBuf::from(prefix.as_os_str())
            }
            _ => {
                return Err(denied(
                    "The product home must be an absolute local drive path",
                ))
            }
        };
        if components.next() != Some(Component::RootDir) {
            return Err(denied(
                "The product home must be absolute and already exist",
            ));
        }
        let mut current = drive.join(Path::new("\\"));
        let mut roots = vec![open_directory(&current)?];
        for component in components {
            let Component::Normal(name) = component else {
                return Err(denied("The product home contains traversal components"));
            };
            require_name(name)?;
            current.push(name);
            roots.push(open_directory(&current)?);
        }
        let root = roots.last().expect("A drive directory is always open");
        require_owner(root, caller)?;
        let path = final_path(root)?;
        Ok(Self {
            path,
            requested_path: current,
            roots,
            caller: caller.clone(),
            directories: Mutex::new(()),
        })
    }

    fn root(&self) -> &File {
        self.roots
            .last()
            .expect("The authorized home retains its root")
    }

    pub fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        self.open_file(path)?.read_to_end(&mut bytes)?;
        Ok(bytes)
    }

    pub fn open_file(&self, path: &Path) -> io::Result<File> {
        let _authority = self.caller.enter()?;
        let (parent, name, _locks) = self.parent(path, false)?;
        let file = create_file(
            &parent.join(name),
            GENERIC_READ | READ_CONTROL,
            OPEN_EXISTING,
            ptr::null(),
        )?;
        require_file(&file, &self.caller)?;
        Ok(file)
    }

    pub fn write_atomic(&self, path: &Path, bytes: &[u8]) -> io::Result<()> {
        let _authority = self.caller.enter()?;
        let _creation = self
            .directories
            .lock()
            .map_err(|_| io::Error::other("Managed directory lock poisoned"))?;
        let (parent, name, locks) = self.parent(path, true)?;
        match create_file(
            &parent.join(&name),
            GENERIC_READ | READ_CONTROL,
            OPEN_EXISTING,
            ptr::null(),
        ) {
            Ok(file) => require_file(&file, &self.caller)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let temporary = format!(
            ".meow-managed-{}-{}.tmp",
            std::process::id(),
            SCRATCH.fetch_add(1, Ordering::Relaxed)
        );
        let mut security = Security::new(&self.caller)?;
        let file = create_file(
            &parent.join(temporary),
            GENERIC_WRITE | GENERIC_READ | READ_CONTROL | DELETE,
            CREATE_NEW,
            security.attributes(),
        )?;
        let mut scratch = Scratch(Some(file));
        let file = scratch
            .0
            .as_mut()
            .expect("The new scratch retains its file");
        require_file(file, &self.caller)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        let directory = locks.last().unwrap_or_else(|| self.root());
        rename(file, directory, &name)?;
        scratch.0.take();
        Ok(())
    }

    fn parent(&self, path: &Path, create: bool) -> io::Result<(PathBuf, OsString, Vec<File>)> {
        let relative = if path.is_absolute() {
            path.strip_prefix(&self.path)
                .or_else(|_| path.strip_prefix(&self.requested_path))
                .map_err(|_| denied("Managed files must remain inside the authorized home"))?
        } else {
            path
        };
        let mut names = Vec::new();
        for component in relative.components() {
            let Component::Normal(name) = component else {
                return Err(denied(
                    "Managed file paths must contain only ordinary names",
                ));
            };
            require_name(name)?;
            names.push(name.to_os_string());
        }
        let name = names
            .pop()
            .ok_or_else(|| denied("A managed file name is required"))?;
        let mut parent = self.path.clone();
        let mut locks = Vec::new();
        for name in names {
            parent.push(name);
            if create {
                let mut security = Security::new(&self.caller)?;
                if unsafe {
                    CreateDirectoryW(wide(parent.as_os_str()).as_ptr(), security.attributes())
                } == 0
                {
                    let error = io::Error::last_os_error();
                    if error.raw_os_error() != Some(ERROR_ALREADY_EXISTS as i32) {
                        return Err(error);
                    }
                }
            }
            let directory = open_directory(&parent)?;
            require_owner(&directory, &self.caller)?;
            locks.push(directory);
        }
        Ok((parent, name, locks))
    }
}

fn denied(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

fn require_name(name: &OsStr) -> io::Result<()> {
    let name = name
        .to_str()
        .ok_or_else(|| denied("Managed names must be valid Unicode"))?;
    let stem = name.split('.').next().unwrap_or("").to_ascii_uppercase();
    let device = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.as_bytes()[3].is_ascii_digit());
    if name.contains([':', '\0']) || name.ends_with(['.', ' ']) || device {
        return Err(denied("Managed names cannot address streams or devices"));
    }
    Ok(())
}

fn wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}

fn create_file(
    path: &Path,
    access: u32,
    disposition: u32,
    security: *const SECURITY_ATTRIBUTES,
) -> io::Result<File> {
    let handle = unsafe {
        CreateFileW(
            wide(path.as_os_str()).as_ptr(),
            access,
            FILE_SHARE_READ,
            security,
            disposition,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_handle(handle) })
    }
}

fn information(file: &File) -> io::Result<BY_HANDLE_FILE_INFORMATION> {
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    check(unsafe { GetFileInformationByHandle(raw(file), &mut information) })?;
    if unsafe { GetFileType(raw(file)) } != FILE_TYPE_DISK
        || information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(denied(
            "Managed storage cannot follow reparse points or devices",
        ));
    }
    Ok(information)
}

fn identity(file: &File) -> io::Result<(u32, u32, u32)> {
    let info = information(file)?;
    Ok((
        info.dwVolumeSerialNumber,
        info.nFileIndexHigh,
        info.nFileIndexLow,
    ))
}

fn open_directory(path: &Path) -> io::Result<File> {
    let directory = create_file(
        path,
        READ_CONTROL | FILE_READ_ATTRIBUTES,
        OPEN_EXISTING,
        ptr::null(),
    )?;
    if information(&directory)?.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
        return Err(denied("Managed parents must be ordinary directories"));
    }
    Ok(directory)
}

fn require_file(file: &File, caller: &WindowsCaller) -> io::Result<()> {
    let info = information(file)?;
    if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 || info.nNumberOfLinks != 1 {
        return Err(denied(
            "Managed files must be ordinary files without hard links",
        ));
    }
    require_owner(file, caller)
}

fn require_owner(file: &File, caller: &WindowsCaller) -> io::Result<()> {
    let mut owner = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    let result = unsafe {
        GetSecurityInfo(
            raw(file),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if result != 0 {
        return Err(io::Error::from_raw_os_error(result as i32));
    }
    let accepted = !owner.is_null() && caller.accepts_owner(owner);
    unsafe {
        LocalFree(descriptor.cast());
    }
    if accepted {
        Ok(())
    } else {
        Err(denied(
            "Managed storage must be owned by its authenticated caller",
        ))
    }
}

fn final_path(file: &File) -> io::Result<PathBuf> {
    let mut buffer = vec![0u16; 512];
    loop {
        let length = unsafe {
            GetFinalPathNameByHandleW(raw(file), buffer.as_mut_ptr(), buffer.len() as u32, 0)
        };
        if length == 0 {
            return Err(io::Error::last_os_error());
        }
        if (length as usize) < buffer.len() {
            use std::os::windows::ffi::OsStringExt;
            return Ok(PathBuf::from(OsString::from_wide(
                &buffer[..length as usize],
            )));
        }
        buffer.resize(length as usize + 1, 0);
    }
}

struct Security {
    descriptor: Box<SECURITY_DESCRIPTOR>,
    attributes: SECURITY_ATTRIBUTES,
}

impl Security {
    fn new(caller: &WindowsCaller) -> io::Result<Self> {
        let mut descriptor = Box::new(SECURITY_DESCRIPTOR::default());
        check(unsafe {
            InitializeSecurityDescriptor(
                (&mut *descriptor as *mut SECURITY_DESCRIPTOR).cast(),
                SECURITY_DESCRIPTOR_REVISION,
            )
        })?;
        check(unsafe {
            SetSecurityDescriptorOwner(
                (&mut *descriptor as *mut SECURITY_DESCRIPTOR).cast(),
                caller.user(),
                0,
            )
        })?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: (&mut *descriptor as *mut SECURITY_DESCRIPTOR).cast(),
            bInheritHandle: 0,
        };
        Ok(Self {
            descriptor,
            attributes,
        })
    }

    fn attributes(&mut self) -> *const SECURITY_ATTRIBUTES {
        let _retain = &self.descriptor;
        &self.attributes
    }
}

fn rename(file: &File, directory: &File, name: &OsStr) -> io::Result<()> {
    let name: Vec<u16> = name.encode_wide().collect();
    let length = std::mem::offset_of!(FILE_RENAME_INFO, FileName) + name.len() * 2;
    let mut buffer = vec![0usize; length.div_ceil(size_of::<usize>())];
    let info = buffer.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    unsafe {
        (*info).Anonymous.ReplaceIfExists = true;
        (*info).RootDirectory = raw(directory);
        (*info).FileNameLength = (name.len() * 2) as u32;
        ptr::copy_nonoverlapping(name.as_ptr(), (*info).FileName.as_mut_ptr(), name.len());
        let mut status = IO_STATUS_BLOCK::default();
        // Kernel32 rejects relative RootDirectory despite FILE_RENAME_INFO documentation.
        let result = NtSetInformationFile(
            raw(file),
            &mut status,
            info.cast(),
            length as u32,
            FileRenameInformation,
        );
        if result < 0 {
            Err(io::Error::from_raw_os_error(
                RtlNtStatusToDosError(result) as i32
            ))
        } else {
            Ok(())
        }
    }
}

struct Scratch(Option<File>);

impl Drop for Scratch {
    fn drop(&mut self) {
        if let Some(file) = &self.0 {
            let info = FILE_DISPOSITION_INFO { DeleteFile: true };
            unsafe {
                SetFileInformationByHandle(
                    raw(file),
                    FileDispositionInfo,
                    (&info as *const FILE_DISPOSITION_INFO).cast(),
                    size_of::<FILE_DISPOSITION_INFO>() as u32,
                );
            }
        }
    }
}
