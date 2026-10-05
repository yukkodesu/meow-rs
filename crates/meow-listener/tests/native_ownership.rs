#![cfg(feature = "listener-tun")]
use meow_listener::tun::ownership::{OwnedResources, ResourceBackend};
use std::{
    collections::HashMap,
    io,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};

#[derive(Clone, Default)]
struct Network(
    Arc<Mutex<HashMap<String, String>>>,
    Arc<AtomicBool>,
    Arc<AtomicBool>,
);

impl ResourceBackend for Network {
    fn read(&mut self, key: &str) -> io::Result<Option<String>> {
        Ok(self.0.lock().unwrap().get(key).cloned())
    }
    fn write(&mut self, key: &str, value: Option<&str>) -> io::Result<()> {
        if self.1.load(Ordering::Relaxed) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Injected native permission failure",
            ));
        }
        let mut network = self.0.lock().unwrap();
        match value {
            Some(value) => {
                network.insert(key.into(), value.into());
            }
            None => {
                network.remove(key);
            }
        }
        Ok(())
    }
    fn owner_alive(&self, _: u32) -> io::Result<bool> {
        Ok(self.2.load(Ordering::Relaxed))
    }
}

#[test]
fn failed_restoration_retains_residue_for_recovery() {
    let folder = tempfile::tempdir().unwrap();
    let journal = folder.path().join("dns.json");
    let mut network = Network::default();
    network.write("wifi", Some("dhcp")).unwrap();
    let mut owned = OwnedResources::install(
        network.clone(),
        Some(journal.clone()),
        vec![("wifi".into(), "127.0.0.1".into())],
        true,
    )
    .unwrap();
    network.1.store(true, Ordering::Relaxed);
    assert_eq!(owned.cleanup().unwrap_err().kind(), io::ErrorKind::Other);
    assert!(journal.exists());
    network.1.store(false, Ordering::Relaxed);
    OwnedResources::recover(&mut network, &journal).unwrap();
    assert_eq!(network.read("wifi").unwrap().as_deref(), Some("dhcp"));
    assert!(!journal.exists());
}

#[test]
fn recovery_refuses_a_live_generation_and_conflicting_routes_are_preserved() {
    let folder = tempfile::tempdir().unwrap();
    let journal = folder.path().join("routes.json");
    let mut network = Network::default();
    let _owned = OwnedResources::install(
        network.clone(),
        Some(journal.clone()),
        vec![("split-default".into(), "FlClashMeowTun".into())],
        false,
    )
    .unwrap();
    network.2.store(true, Ordering::Relaxed);
    assert_eq!(
        OwnedResources::recover(&mut network, &journal)
            .unwrap_err()
            .kind(),
        io::ErrorKind::AlreadyExists
    );
    assert_eq!(
        network.read("split-default").unwrap().as_deref(),
        Some("FlClashMeowTun")
    );
    network.2.store(false, Ordering::Relaxed);
    OwnedResources::recover(&mut network, &journal).unwrap();
    network.write("split-default", Some("another-vpn")).unwrap();
    assert!(OwnedResources::install(
        network.clone(),
        Some(journal),
        vec![("split-default".into(), "FlClashMeowTun".into())],
        false
    )
    .is_err());
    assert_eq!(
        network.read("split-default").unwrap().as_deref(),
        Some("another-vpn")
    );
}

#[test]
fn stop_and_crash_recovery_preserve_later_dns_changes() {
    let folder = tempfile::tempdir().unwrap();
    let journal = folder.path().join("dns.json");
    let mut network = Network::default();
    network.write("wifi", Some("9.9.9.9")).unwrap();
    network.write("ethernet", Some("dhcp")).unwrap();
    let mut owned = OwnedResources::install(
        network.clone(),
        Some(journal.clone()),
        vec![
            ("wifi".into(), "127.0.0.1".into()),
            ("ethernet".into(), "127.0.0.1".into()),
        ],
        true,
    )
    .unwrap();
    network.write("wifi", Some("192.168.1.1")).unwrap();
    owned.cleanup().unwrap();
    assert_eq!(
        network.read("wifi").unwrap().as_deref(),
        Some("192.168.1.1")
    );
    assert_eq!(network.read("ethernet").unwrap().as_deref(), Some("dhcp"));
    let _crashed = OwnedResources::install(
        network.clone(),
        Some(journal.clone()),
        vec![("ethernet".into(), "127.0.0.1".into())],
        true,
    )
    .unwrap();
    OwnedResources::recover(&mut network, &journal).unwrap();
    assert_eq!(network.read("ethernet").unwrap().as_deref(), Some("dhcp"));
    assert!(!journal.exists());
}
