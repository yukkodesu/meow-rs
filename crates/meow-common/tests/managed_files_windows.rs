#![cfg(windows)]

use meow_common::managed_files::{ManagedHome, WindowsCaller};
use std::os::windows::io::{AsHandle, FromRawHandle, OwnedHandle};
use windows_sys::Win32::{
    Security::{TOKEN_DUPLICATE, TOKEN_QUERY},
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

fn caller() -> WindowsCaller {
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
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    WindowsCaller::duplicate(token.as_handle()).unwrap()
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
