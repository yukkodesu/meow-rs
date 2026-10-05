#![cfg(windows)]

use meow_common::managed_files::{ManagedHome, WindowsCaller};
use std::{
    io,
    os::windows::{
        ffi::OsStrExt,
        io::{AsHandle, AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::Path,
};
use windows_sys::Win32::{
    Foundation::{GENERIC_WRITE, INVALID_HANDLE_VALUE},
    Security::{
        DuplicateTokenEx, GetTokenInformation, RevertToSelf, SecurityImpersonation,
        TokenImpersonation, TokenStatistics, TOKEN_DUPLICATE, TOKEN_IMPERSONATE, TOKEN_QUERY,
        TOKEN_STATISTICS,
    },
    Storage::FileSystem::{
        CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, OPEN_EXISTING,
    },
    System::{
        Ioctl::FSCTL_SET_REPARSE_POINT,
        SystemServices::IO_REPARSE_TAG_MOUNT_POINT,
        Threading::{
            GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken, SetThreadToken,
        },
        IO::DeviceIoControl,
    },
};

fn caller() -> WindowsCaller {
    WindowsCaller::duplicate(process_token().as_handle()).unwrap()
}

fn process_token() -> OwnedHandle {
    let mut token = std::ptr::null_mut();
    assert_ne!(
        unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_QUERY | TOKEN_DUPLICATE,
                &mut token,
            )
        },
        0
    );
    unsafe { OwnedHandle::from_raw_handle(token) }
}

#[test]
fn managed_reads_and_replacements_reject_hardlinks_and_outside_paths() {
    let dir = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let secret = outside.path().join("private.yaml");
    std::fs::write(&secret, b"outside contents").unwrap();
    std::fs::hard_link(&secret, dir.path().join("linked.yaml")).unwrap();
    let home = ManagedHome::open(dir.path(), &caller()).unwrap();
    for path in [
        Path::new("linked.yaml"),
        secret.as_path(),
        Path::new("../private.yaml"),
        Path::new("nodes.yaml:stream"),
        Path::new("NUL"),
        Path::new("trailing."),
    ] {
        assert!(home.read(path).is_err(), "read accepted {path:?}");
        assert!(
            home.write_atomic(path, b"changed").is_err(),
            "write accepted {path:?}"
        );
    }
    assert_eq!(std::fs::read(secret).unwrap(), b"outside contents");
    assert_eq!(
        std::fs::read(dir.path().join("linked.yaml")).unwrap(),
        b"outside contents"
    );
}

fn junction(link: &Path, target: &Path) -> io::Result<()> {
    std::fs::create_dir(link)?;
    set_junction(link, target)
}

fn set_junction(link: &Path, target: &Path) -> io::Result<()> {
    let path: Vec<u16> = link.as_os_str().encode_wide().chain(Some(0)).collect();
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            GENERIC_WRITE,
            3,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
    let target = target.canonicalize()?;
    let target = target
        .to_str()
        .unwrap()
        .strip_prefix("\\\\?\\")
        .unwrap()
        .to_owned();
    let substitute: Vec<u16> = format!("\\??\\{target}").encode_utf16().collect();
    let print: Vec<u16> = target.encode_utf16().collect();
    let length = 16 + (substitute.len() + print.len() + 2) * 2;
    let mut buffer = vec![0u32; length.div_ceil(4)];
    unsafe {
        let bytes = buffer.as_mut_ptr().cast::<u8>();
        bytes.cast::<u32>().write(IO_REPARSE_TAG_MOUNT_POINT);
        bytes.add(4).cast::<u16>().write((length - 8) as u16);
        let names = bytes.add(8).cast::<u16>();
        names.add(1).write((substitute.len() * 2) as u16);
        names.add(2).write(((substitute.len() + 1) * 2) as u16);
        names.add(3).write((print.len() * 2) as u16);
        std::ptr::copy_nonoverlapping(substitute.as_ptr(), names.add(4), substitute.len());
        std::ptr::copy_nonoverlapping(print.as_ptr(), names.add(5 + substitute.len()), print.len());
        let mut returned = 0;
        if DeviceIoControl(
            handle.as_raw_handle(),
            FSCTL_SET_REPARSE_POINT,
            bytes.cast(),
            length as u32,
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[test]
fn managed_home_and_cache_parents_reject_junctions() {
    let dir = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("nodes.yaml"), b"outside contents").unwrap();
    let link = dir.path().join("providers");
    junction(&link, outside.path()).unwrap();
    assert!(ManagedHome::open(&link, &caller()).is_err());
    let home = ManagedHome::open(dir.path(), &caller()).unwrap();
    assert!(home.read(Path::new("providers/nodes.yaml")).is_err());
    assert!(home
        .write_atomic(Path::new("providers/nodes.yaml"), b"changed")
        .is_err());
    assert_eq!(
        std::fs::read(outside.path().join("nodes.yaml")).unwrap(),
        b"outside contents"
    );
    std::fs::remove_dir(link).unwrap();
}

#[test]
fn retained_home_handle_blocks_directory_replacement_until_released() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("home");
    let renamed = dir.path().join("replaced");
    std::fs::create_dir(&root).unwrap();
    let home = ManagedHome::open(&root, &caller()).unwrap();
    let error = std::fs::rename(&root, &renamed).unwrap_err();
    assert_eq!(error.raw_os_error(), Some(32));
    home.write_atomic(Path::new("provider.yaml"), b"owned contents")
        .unwrap();
    assert_eq!(
        home.read(Path::new("provider.yaml")).unwrap(),
        b"owned contents"
    );
    drop(home);
    std::fs::rename(root, renamed).unwrap();
}

#[test]
fn changing_authorized_directory_to_junction_cannot_redirect_writes() {
    let dir = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("nodes.yaml"), b"outside contents").unwrap();
    let root = dir.path().join("home");
    std::fs::create_dir(&root).unwrap();
    let home = ManagedHome::open(&root, &caller()).unwrap();
    set_junction(&root, outside.path()).unwrap();
    assert!(home.read(Path::new("nodes.yaml")).is_err());
    assert!(home
        .write_atomic(Path::new("nodes.yaml"), b"changed")
        .is_err());
    assert_eq!(
        std::fs::read(outside.path().join("nodes.yaml")).unwrap(),
        b"outside contents"
    );
    drop(home);
    std::fs::remove_dir(root).unwrap();
}

fn thread_token_id() -> Option<(u32, i32)> {
    let mut token = std::ptr::null_mut();
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) } == 0 {
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(1008));
        return None;
    }
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    let mut stats = TOKEN_STATISTICS::default();
    let mut length = 0;
    assert_ne!(
        unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                TokenStatistics,
                (&mut stats as *mut TOKEN_STATISTICS).cast(),
                size_of::<TOKEN_STATISTICS>() as u32,
                &mut length,
            )
        },
        0
    );
    Some((stats.TokenId.LowPart, stats.TokenId.HighPart))
}

#[test]
fn caller_operations_restore_preexisting_thread_identity_on_success_and_error() {
    std::thread::spawn(|| {
        assert_eq!(thread_token_id(), None);
        let mut process = std::ptr::null_mut();
        assert_ne!(
            unsafe {
                OpenProcessToken(
                    GetCurrentProcess(),
                    TOKEN_QUERY | TOKEN_DUPLICATE,
                    &mut process,
                )
            },
            0
        );
        let process = unsafe { OwnedHandle::from_raw_handle(process) };
        let mut outer = std::ptr::null_mut();
        assert_ne!(
            unsafe {
                DuplicateTokenEx(
                    process.as_raw_handle(),
                    TOKEN_QUERY | TOKEN_IMPERSONATE,
                    std::ptr::null(),
                    SecurityImpersonation,
                    TokenImpersonation,
                    &mut outer,
                )
            },
            0
        );
        let outer = unsafe { OwnedHandle::from_raw_handle(outer) };
        assert_ne!(
            unsafe { SetThreadToken(std::ptr::null(), outer.as_raw_handle()) },
            0
        );
        let identity = thread_token_id().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let home = ManagedHome::open(dir.path(), &caller()).unwrap();
        assert_eq!(thread_token_id(), Some(identity));
        home.write_atomic(Path::new("cache/nodes.json"), b"{}")
            .unwrap();
        assert_eq!(thread_token_id(), Some(identity));
        assert!(home.read(Path::new("missing.yaml")).is_err());
        assert_eq!(thread_token_id(), Some(identity));
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            home.write_atomic(Path::new("../denied.yaml"), b"{}")
                .unwrap();
        }));
        assert!(panic.is_err());
        assert_eq!(thread_token_id(), Some(identity));
        assert_ne!(unsafe { RevertToSelf() }, 0);
        assert_eq!(thread_token_id(), None);
        home.read(Path::new("cache/nodes.json")).unwrap();
        assert_eq!(thread_token_id(), None);
    })
    .join()
    .unwrap();
}

#[test]
fn caller_can_atomically_replace_nested_cache_and_edit_it_directly() {
    let dir = tempfile::tempdir().unwrap();
    let home = ManagedHome::open(dir.path(), &caller()).unwrap();
    home.write_atomic("providers/nodes.yaml".as_ref(), b"proxies: []")
        .unwrap();
    home.write_atomic("providers/nodes.yaml".as_ref(), b"proxies: [DIRECT]")
        .unwrap();
    assert_eq!(
        home.read("providers/nodes.yaml".as_ref()).unwrap(),
        b"proxies: [DIRECT]"
    );
    std::fs::write(
        dir.path().join("providers/nodes.yaml"),
        b"ordinary replacement",
    )
    .unwrap();
    assert_eq!(
        home.read("providers/nodes.yaml".as_ref()).unwrap(),
        b"ordinary replacement"
    );
}

fn token_information(token: &OwnedHandle, class: i32) -> Vec<usize> {
    let mut length = 0;
    unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            class,
            std::ptr::null_mut(),
            0,
            &mut length,
        );
    }
    assert!(length > 0);
    let mut bytes = vec![0usize; (length as usize).div_ceil(size_of::<usize>())];
    assert_ne!(
        unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                class,
                bytes.as_mut_ptr().cast(),
                length,
                &mut length,
            )
        },
        0
    );
    bytes
}

fn owner_equals_user(path: &Path, token: &OwnedHandle) -> bool {
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::{
            Authorization::{GetSecurityInfo, SE_FILE_OBJECT},
            EqualSid, TokenUser, OWNER_SECURITY_INFORMATION, TOKEN_USER,
        },
    };
    let file = std::fs::File::open(path).unwrap();
    let mut owner = std::ptr::null_mut();
    let mut descriptor = std::ptr::null_mut();
    assert_eq!(
        unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut owner,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut descriptor,
            )
        },
        0
    );
    let user_info = token_information(token, TokenUser);
    let equal =
        unsafe { EqualSid(owner, (*user_info.as_ptr().cast::<TOKEN_USER>()).User.Sid) } != 0;
    unsafe {
        LocalFree(descriptor.cast());
    }
    equal
}

#[test]
fn product_files_use_token_user_owner_and_restricted_caller_has_no_ambient_access() {
    use windows_sys::Win32::Security::{
        CreateRestrictedToken, CreateWellKnownSid, WinBuiltinGuestsSid, DISABLE_MAX_PRIVILEGE,
        SID_AND_ATTRIBUTES,
    };
    let dir = tempfile::tempdir().unwrap();
    let token = process_token();
    let home = ManagedHome::open(
        dir.path(),
        &WindowsCaller::duplicate(token.as_handle()).unwrap(),
    )
    .unwrap();
    home.write_atomic(
        Path::new("cache/fakeip.json"),
        b"{\"example.test\":\"198.18.0.1\"}",
    )
    .unwrap();
    assert!(owner_equals_user(
        &dir.path().join("cache/fakeip.json"),
        &token
    ));
    let mut sid = vec![0u32; 32];
    let mut length = 128;
    assert_ne!(
        unsafe {
            CreateWellKnownSid(
                WinBuiltinGuestsSid,
                std::ptr::null_mut(),
                sid.as_mut_ptr().cast(),
                &mut length,
            )
        },
        0
    );
    let restricted_sid = SID_AND_ATTRIBUTES {
        Sid: sid.as_mut_ptr().cast(),
        Attributes: 0,
    };
    let mut restricted = std::ptr::null_mut();
    assert_ne!(
        unsafe {
            CreateRestrictedToken(
                token.as_raw_handle(),
                DISABLE_MAX_PRIVILEGE,
                0,
                std::ptr::null(),
                0,
                std::ptr::null(),
                1,
                &restricted_sid,
                &mut restricted,
            )
        },
        0
    );
    let restricted = unsafe { OwnedHandle::from_raw_handle(restricted) };
    let caller = WindowsCaller::duplicate(restricted.as_handle()).unwrap();
    assert!(ManagedHome::open(dir.path(), &caller).is_err());
    assert_eq!(
        std::fs::read(dir.path().join("cache/fakeip.json")).unwrap(),
        b"{\"example.test\":\"198.18.0.1\"}"
    );
}

#[test]
#[ignore = "Requires an elevated disposable Windows runner; no privileges are enabled by this fixture"]
fn elevated_exact_owner_is_accepted_but_ordinary_caller_rejects_admin_owned_home() {
    use windows_sys::Win32::{
        Foundation::GENERIC_READ,
        Security::{
            Authorization::{SetSecurityInfo, SE_FILE_OBJECT},
            CreateRestrictedToken, CreateWellKnownSid, EqualSid, TokenElevation, TokenOwner,
            WinBuiltinAdministratorsSid, DISABLE_MAX_PRIVILEGE, LUA_TOKEN,
            OWNER_SECURITY_INFORMATION, SID_AND_ATTRIBUTES, TOKEN_ELEVATION, TOKEN_OWNER,
        },
        Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL, WRITE_OWNER},
    };
    let dir = tempfile::tempdir().unwrap();
    let token = process_token();
    let elevation = token_information(&token, TokenElevation);
    assert_ne!(
        unsafe { (*elevation.as_ptr().cast::<TOKEN_ELEVATION>()).TokenIsElevated },
        0,
        "This fixture requires an already elevated runner"
    );
    let owner_info = token_information(&token, TokenOwner);
    let owner = unsafe { (*owner_info.as_ptr().cast::<TOKEN_OWNER>()).Owner };
    let mut admin = vec![0u32; 32];
    let mut length = 128;
    assert_ne!(
        unsafe {
            CreateWellKnownSid(
                WinBuiltinAdministratorsSid,
                std::ptr::null_mut(),
                admin.as_mut_ptr().cast(),
                &mut length,
            )
        },
        0
    );
    assert_ne!(
        unsafe { EqualSid(owner, admin.as_mut_ptr().cast()) },
        0,
        "Runner token must use its actual Admin owner for this case"
    );
    let path: Vec<u16> = dir
        .path()
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            GENERIC_READ | READ_CONTROL | WRITE_OWNER,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            std::ptr::null_mut(),
        )
    };
    assert_ne!(handle, INVALID_HANDLE_VALUE);
    let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
    assert_eq!(
        unsafe {
            SetSecurityInfo(
                handle.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                owner,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        },
        0
    );
    drop(handle);
    let elevated = WindowsCaller::duplicate(token.as_handle()).unwrap();
    let home = ManagedHome::open(dir.path(), &elevated).unwrap();
    home.write_atomic(Path::new("providers/nodes.yaml"), b"owned cache")
        .unwrap();
    assert!(owner_equals_user(
        &dir.path().join("providers/nodes.yaml"),
        &token
    ));
    let disabled = SID_AND_ATTRIBUTES {
        Sid: admin.as_mut_ptr().cast(),
        Attributes: 0,
    };
    let mut ordinary = std::ptr::null_mut();
    assert_ne!(
        unsafe {
            CreateRestrictedToken(
                token.as_raw_handle(),
                LUA_TOKEN | DISABLE_MAX_PRIVILEGE,
                1,
                &disabled,
                0,
                std::ptr::null(),
                0,
                std::ptr::null(),
                &mut ordinary,
            )
        },
        0
    );
    let ordinary = unsafe { OwnedHandle::from_raw_handle(ordinary) };
    let ordinary_elevation = token_information(&ordinary, TokenElevation);
    assert_eq!(
        unsafe { (*ordinary_elevation.as_ptr().cast::<TOKEN_ELEVATION>()).TokenIsElevated },
        0
    );
    let ordinary = WindowsCaller::duplicate(ordinary.as_handle()).unwrap();
    assert!(ManagedHome::open(dir.path(), &ordinary).is_err());
    assert_eq!(
        home.read(Path::new("providers/nodes.yaml")).unwrap(),
        b"owned cache"
    );
}

#[test]
fn concurrent_parent_replacement_never_reads_or_overwrites_junction_target() {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    let dir = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("nodes.yaml"), b"outside contents").unwrap();
    let parent = dir.path().join("providers");
    let hidden = dir.path().join("hidden");
    std::fs::create_dir(&parent).unwrap();
    std::fs::write(parent.join("nodes.yaml"), b"owned contents").unwrap();
    let home = ManagedHome::open(dir.path(), &caller()).unwrap();
    let running = Arc::new(AtomicBool::new(true));
    std::thread::scope(|scope| {
        let racing = Arc::clone(&running);
        let parent = &parent;
        let hidden = &hidden;
        let outside = outside.path();
        scope.spawn(move || {
            while racing.load(Ordering::Relaxed) {
                if std::fs::rename(parent, hidden).is_ok() {
                    if junction(parent, outside).is_err() {
                        break;
                    }
                    std::thread::yield_now();
                    while std::fs::remove_dir(parent).is_err() {
                        std::thread::yield_now();
                    }
                    if std::fs::rename(hidden, parent).is_err() {
                        break;
                    }
                }
            }
        });
        for _ in 0..200 {
            if let Ok(bytes) = home.read(Path::new("providers/nodes.yaml")) {
                assert_eq!(bytes, b"owned contents");
            }
            let _ = home.write_atomic(Path::new("providers/nodes.yaml"), b"owned contents");
        }
        running.store(false, Ordering::Relaxed);
    });
    assert_eq!(
        std::fs::read(outside.path().join("nodes.yaml")).unwrap(),
        b"outside contents"
    );
    home.write_atomic(Path::new("providers/nodes.yaml"), b"owned contents")
        .unwrap();
    assert_eq!(
        home.read(Path::new("providers/nodes.yaml")).unwrap(),
        b"owned contents"
    );
}

#[test]
fn installed_policy_is_immutable_and_background_file_work_retains_caller_authority() {
    use meow_common::managed_files;
    if let Some(path) = std::env::var_os("MEOW_WINDOWS_POLICY_FIXTURE") {
        let path = std::path::PathBuf::from(path);
        let identity = caller();
        let canonical = managed_files::authorize_home_windows(&path, &identity).unwrap();
        assert_eq!(
            managed_files::authorize_home_windows(&path, &identity).unwrap(),
            canonical
        );
        assert!(managed_files::authorize_home_windows(&path, &caller()).is_err());
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let mut tasks = Vec::new();
            for index in 0..8 {
                let path = path.join(format!("cache/provider-{index}.yaml"));
                tasks.push(tokio::spawn(async move {
                    managed_files::write_atomic_if_managed_async(&path, b"owned cache")
                        .await
                        .unwrap()
                        .unwrap();
                    assert_eq!(
                        managed_files::read_async(&path).await.unwrap(),
                        b"owned cache"
                    );
                }));
            }
            for task in tasks {
                task.await.unwrap();
            }
        });
        assert!(managed_files::read(&path.parent().unwrap().join("outside.yaml")).is_err());
        assert_eq!(thread_token_id(), None);
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir(&home).unwrap();
    std::fs::write(dir.path().join("outside.yaml"), b"outside contents").unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "installed_policy_is_immutable_and_background_file_work_retains_caller_authority",
            "--nocapture",
        ])
        .env("MEOW_WINDOWS_POLICY_FIXTURE", &home)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read(home.join("cache/provider-7.yaml")).unwrap(),
        b"owned cache"
    );
    std::fs::write(home.join("cache/provider-7.yaml"), b"ordinary edit").unwrap();
    assert_eq!(
        std::fs::read(dir.path().join("outside.yaml")).unwrap(),
        b"outside contents"
    );
}
