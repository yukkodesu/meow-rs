#![cfg(unix)]

use meow_common::managed_files::ManagedHome;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

fn identity() -> (u32, u32) {
    unsafe { (libc::geteuid(), libc::getegid()) }
}

#[test]
fn authenticated_owner_can_replace_and_read_nested_cache() {
    let dir = tempfile::tempdir().unwrap();
    let (uid, gid) = identity();
    let home = ManagedHome::open(dir.path(), uid, gid).unwrap();
    home.write_atomic("providers/nodes.yaml".as_ref(), b"proxies: []")
        .unwrap();
    assert_eq!(
        home.read("providers/nodes.yaml".as_ref()).unwrap(),
        b"proxies: []"
    );
    home.write_atomic("providers/nodes.yaml".as_ref(), b"proxies: [DIRECT]")
        .unwrap();
    assert_eq!(
        home.read("providers/nodes.yaml".as_ref()).unwrap(),
        b"proxies: [DIRECT]"
    );
    let file = std::fs::metadata(dir.path().join("providers/nodes.yaml")).unwrap();
    let parent = std::fs::metadata(dir.path().join("providers")).unwrap();
    assert_eq!(
        (file.uid(), file.gid(), file.permissions().mode() & 0o777),
        (uid, gid, 0o600)
    );
    assert_eq!(
        (
            parent.uid(),
            parent.gid(),
            parent.permissions().mode() & 0o777
        ),
        (uid, gid, 0o700)
    );
}

#[test]
fn symlinked_home_does_not_establish_caller_provenance() {
    let dir = tempfile::tempdir().unwrap();
    let link_root = tempfile::tempdir().unwrap();
    let link = link_root.path().join("home");
    symlink(dir.path(), &link).unwrap();
    let (uid, gid) = identity();
    assert!(ManagedHome::open(&link, uid, gid).is_err());
}

#[test]
fn caller_identity_and_private_directory_permissions_are_required() {
    let dir = tempfile::tempdir().unwrap();
    let (uid, gid) = identity();
    assert!(ManagedHome::open(dir.path(), uid.wrapping_add(1), gid).is_err());
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(ManagedHome::open(dir.path(), uid, gid).is_err());
}

#[test]
fn provider_paths_cannot_read_or_replace_symlinks_hard_links_or_parent_paths() {
    let dir = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let secret = outside.path().join("secret");
    std::fs::write(&secret, b"outside").unwrap();
    symlink(outside.path(), dir.path().join("escape")).unwrap();
    symlink(&secret, dir.path().join("linked")).unwrap();
    std::fs::hard_link(&secret, dir.path().join("hard-linked")).unwrap();
    let (uid, gid) = identity();
    let home = ManagedHome::open(dir.path(), uid, gid).unwrap();
    for path in [
        "escape/secret".as_ref(),
        "linked".as_ref(),
        "hard-linked".as_ref(),
        "../secret".as_ref(),
        secret.as_path(),
    ] {
        assert!(home.read(path).is_err(), "{}", path.display());
        assert!(
            home.write_atomic(path, b"replaced").is_err(),
            "{}",
            path.display()
        );
    }
    assert_eq!(std::fs::read(&secret).unwrap(), b"outside");
}

#[test]
fn renamed_home_keeps_its_directory_capability_instead_of_following_a_replacement() {
    let parent = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let path = parent.path().join("home");
    std::fs::create_dir(&path).unwrap();
    let (uid, gid) = identity();
    let home = ManagedHome::open(&path, uid, gid).unwrap();
    std::fs::rename(&path, parent.path().join("original")).unwrap();
    symlink(outside.path(), &path).unwrap();
    home.write_atomic("providers/cache".as_ref(), b"owned cache")
        .unwrap();
    assert_eq!(
        std::fs::read(parent.path().join("original/providers/cache")).unwrap(),
        b"owned cache"
    );
    assert!(!outside.path().join("providers").exists());
}

#[test]
fn installed_session_policy_confines_shared_core_io_and_cannot_switch_homes() {
    use meow_common::managed_files::{authorize_home, read, write_atomic_if_managed};
    let dir = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let (uid, gid) = identity();
    let path = authorize_home(dir.path(), uid, gid).unwrap();
    write_atomic_if_managed(&path.join("config.yaml"), b"mode: rule")
        .unwrap()
        .unwrap();
    assert_eq!(read(&path.join("config.yaml")).unwrap(), b"mode: rule");
    assert!(read(&outside.path().join("config.yaml")).is_err());
    assert!(authorize_home(outside.path(), uid, gid).is_err());
    assert_eq!(authorize_home(dir.path(), uid, gid).unwrap(), path);
}

#[test]
#[ignore = "Requires explicit root execution with an ordinary test UID/GID"]
fn elevated_host_creates_caches_the_authenticated_ordinary_user_can_replace() {
    use std::os::unix::process::CommandExt;
    let uid: u32 = std::env::var("FLCLASH_MEOW_TEST_UID")
        .unwrap()
        .parse()
        .unwrap();
    let gid: u32 = std::env::var("FLCLASH_MEOW_TEST_GID")
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(identity().0, 0);
    assert_ne!(uid, 0);
    let dir = tempfile::tempdir().unwrap();
    let name = std::ffi::CString::new(std::os::unix::ffi::OsStrExt::as_bytes(
        dir.path().as_os_str(),
    ))
    .unwrap();
    assert_eq!(unsafe { libc::chown(name.as_ptr(), uid, gid) }, 0);
    let home = std::sync::Arc::new(ManagedHome::open(dir.path(), uid, gid).unwrap());
    let start = std::sync::Arc::new(std::sync::Barrier::new(16));
    let writes: Vec<_> = (0..16)
        .map(|index| {
            let home = std::sync::Arc::clone(&home);
            let start = std::sync::Arc::clone(&start);
            std::thread::spawn(move || {
                start.wait();
                home.write_atomic(
                    std::path::Path::new(&format!("parallel/cache/{index}.yaml")),
                    b"payload: []",
                )
            })
        })
        .collect();
    for write in writes {
        write.join().unwrap().unwrap();
    }
    home.write_atomic("providers/cache.yaml".as_ref(), b"proxies: []")
        .unwrap();
    let output = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg("printf 'ordinary replacement' > \"$1.new\" && mv \"$1.new\" \"$1\"")
        .arg("ownership-probe")
        .arg(dir.path().join("providers/cache.yaml"))
        .uid(uid)
        .gid(gid)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        home.read("providers/cache.yaml".as_ref()).unwrap(),
        b"ordinary replacement"
    );
    assert_eq!(
        std::fs::metadata(dir.path().join("providers/cache.yaml"))
            .unwrap()
            .uid(),
        uid
    );
    std::fs::write(dir.path().join("root-owned"), b"private").unwrap();
    assert!(home.read("root-owned".as_ref()).is_err());
    assert!(home
        .write_atomic("root-owned".as_ref(), b"replacement")
        .is_err());
}
