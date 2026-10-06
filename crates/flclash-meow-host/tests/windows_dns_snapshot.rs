#![cfg(windows)]

use meow_listener::tun::ownership::powershell;
use serde_json::{json, Value};

const SNAPSHOT: &str = include_str!("fixtures/windows_dns_snapshot.ps1");
const REGISTRY: &str = include_str!("fixtures/windows_dns_registry.ps1");

#[test]
fn windows_dns_snapshot_records_actual_guid_shape_and_missing_family() {
    let output = powershell(&format!("{REGISTRY}\n{SNAPSHOT}")).unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&output).unwrap(),
        json!([
            {"adapter":"11111111-1111-1111-1111-111111111111","family":"Tcpip","servers":"192.0.2.53"},
            {"adapter":"11111111-1111-1111-1111-111111111111","family":"Tcpip6","servers":""},
            {"adapter":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","family":"Tcpip","servers":"198.51.100.53"},
        ]),
    );
    for (flag, expected) in [
        ("registryFailure", "Registry snapshot access denied"),
        ("adapterFailure", "Adapter snapshot provider failed"),
        ("noKeys", "captured no adapter registry resources"),
    ] {
        let error =
            powershell(&format!("{REGISTRY}\n$script:{flag} = $true\n{SNAPSHOT}")).unwrap_err();
        assert!(error.to_string().contains(expected), "{error}");
    }
}

#[test]
#[ignore = "read-only Windows registry inspection; opt in explicitly"]
fn windows_dns_snapshot_readonly_inspection() {
    assert_eq!(
        std::env::var("MEOW_NATIVE_READ_ONLY_INSPECTION").as_deref(),
        Ok("1"),
    );
    let output = powershell(SNAPSHOT).unwrap();
    let resources: Vec<Value> = serde_json::from_str(&output).unwrap();
    assert!(!resources.is_empty(), "Native DNS snapshot is empty");
    for resource in &resources {
        assert_eq!(resource["adapter"].as_str().unwrap().len(), 36);
        assert!(matches!(
            resource["family"].as_str(),
            Some("Tcpip" | "Tcpip6")
        ));
        assert!(resource["servers"].is_string());
    }
    println!(
        "Read-only native DNS registry snapshot inspected: {} resources",
        resources.len()
    );
}
