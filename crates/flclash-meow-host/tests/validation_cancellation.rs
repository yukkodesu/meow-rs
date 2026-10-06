use flclash_meow_host::{protocol::write_frame, serve, Host};
use std::{
    collections::HashMap,
    sync::{Arc, Condvar, Mutex, OnceLock},
    time::Duration,
};

struct ValidationGate {
    entered: tokio::sync::Notify,
    released: Mutex<bool>,
    wake: Condvar,
}

static GATE: OnceLock<ValidationGate> = OnceLock::new();

#[expect(
    clippy::unnecessary_wraps,
    reason = "The embedding validator contract returns a Result"
)]
fn hold_validation(_: &HashMap<String, serde_yaml::Value>) -> Result<(), String> {
    let gate = GATE.get().unwrap();
    gate.entered.notify_one();
    let mut released = gate.released.lock().unwrap();
    while !*released {
        released = gate.wake.wait(released).unwrap();
    }
    Ok(())
}

struct ReleaseValidation;

impl Drop for ReleaseValidation {
    fn drop(&mut self) {
        let gate = GATE.get().unwrap();
        *gate.released.lock().unwrap() = true;
        gate.wake.notify_all();
    }
}

#[tokio::test]
async fn disconnected_rpc_does_not_certify_shutdown_until_validation_finishes() {
    GATE.set(ValidationGate {
        entered: tokio::sync::Notify::new(),
        released: Mutex::new(false),
        wake: Condvar::new(),
    })
    .ok()
    .unwrap();
    let release = ReleaseValidation;
    meow_config::proxy_parser::install_proxy_config_validator(hold_validation);
    let host = Arc::new(Host::new());
    let home = tempfile::tempdir().unwrap();
    let initialized = host
        .call(flclash_meow_host::protocol::Request {
            id: None,
            method: "initClash".into(),
            arguments: serde_json::json!({"home-dir":home.path()}),
        })
        .await;
    assert!(initialized.error.is_none());
    let (mut peer, stream) = tokio::io::duplex(4096);
    let mut session = tokio::spawn(serve(host, stream));
    let request = serde_json::json!({"id":"held","method":"checkConfig","arguments":"proxies: [{name: held, type: http, server: localhost, port: 80}]\nrules: ['MATCH,DIRECT']"});
    write_frame(&mut peer, request.to_string().as_bytes())
        .await
        .unwrap();
    tokio::time::timeout(
        Duration::from_secs(5),
        GATE.get().unwrap().entered.notified(),
    )
    .await
    .expect("The actual proxy validation must have entered");
    drop(peer);
    let premature = tokio::time::timeout(Duration::from_millis(100), &mut session).await;
    let finished_early = premature.is_ok();
    drop(release);
    if !finished_early {
        tokio::time::timeout(Duration::from_secs(5), session)
            .await
            .expect("Shutdown must converge after releasing validation")
            .unwrap()
            .unwrap();
    }
    assert!(
        !finished_early,
        "IPC shutdown escaped a running validation worker"
    );
}
