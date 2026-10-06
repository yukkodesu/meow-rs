use super::Host;
use crate::protocol::{read_frame, write_frame, Request, Response};
use serde_json::{json, Value};
use std::sync::Arc;

async fn call(host: &Host, method: &str, arguments: Value) -> Response {
    host.call(Request {
        id: Some(method.into()),
        method: method.into(),
        arguments,
    })
    .await
}

#[tokio::test]
async fn tun_settings_preserve_listener_endpoints_and_traffic_history() {
    let host = Host::new();
    let home = tempfile::tempdir().unwrap();
    host.state.lock().await.home = Some(home.path().to_path_buf());
    tokio::fs::write(home.path().join("config.yaml"), "listeners: [{name: local, type: mixed, listen: 127.0.0.1, port: 0}]\nrules: ['MATCH,DIRECT']\n").await.unwrap();
    assert!(call(&host, "setupConfig", Value::Null)
        .await
        .error
        .is_none());
    assert_eq!(call(&host, "startListener", Value::Null).await.result, true);
    let before = call(&host, "getRuntimeState", Value::Null).await.result;
    {
        let state = host.state.lock().await;
        let statistics = state.runtime.as_ref().unwrap().state.tunnel.statistics();
        statistics.add_upload(128);
        statistics.add_download(256);
    }
    let traffic = call(&host, "getTotalTraffic", json!(false)).await.result;
    let changed = call(
        &host,
        "updateConfig",
        json!({"tun":{"enable":false,"mtu":1400}}),
    )
    .await;
    assert!(changed.error.is_none(), "{:?}", changed.error);
    assert_eq!(
        call(&host, "getTotalTraffic", json!(false)).await.result,
        traffic
    );
    assert_eq!(
        call(&host, "getRuntimeState", Value::Null).await.result["listeners"],
        before["listeners"]
    );
    let document = host.state.lock().await.document.clone();
    let mode = host
        .state
        .lock()
        .await
        .runtime
        .as_ref()
        .unwrap()
        .state
        .raw_config
        .read()
        .mode
        .clone();
    for patch in [
        json!({"mode":"invalid","tun":{"enable":false,"mtu":1450}}),
        json!({"mode":"global","tun":{"enable":"invalid"}}),
    ] {
        assert!(call(&host, "updateConfig", patch).await.error.is_some());
        let state = host.state.lock().await;
        assert_eq!(state.document, document);
        let runtime = state.runtime.as_ref().unwrap();
        assert_eq!(runtime.state.raw_config.read().mode, mode);
    }
    assert!(call(&host, "shutdown", Value::Null).await.error.is_none());
}

#[tokio::test]
async fn failed_crash_recovery_blocks_configuration_and_listener_start() {
    use meow_listener::tun::{RecoveryState, RecoveryStatus};

    let host = Host::new();
    for recovery in [RecoveryState::Failed, RecoveryState::NeedsPrivilege] {
        host.state.lock().await.recovery = RecoveryStatus {
            state: recovery,
            details: vec!["Recorded DNS state could not be restored".into()],
        };
        for method in ["setupConfig", "updateConfig", "startListener"] {
            assert_eq!(
                call(&host, method, Value::Null).await.error.unwrap().code,
                "resources_release_unconfirmed"
            );
        }
        assert_eq!(
            call(&host, "getRuntimeState", Value::Null).await.result["running"],
            false
        );
    }
}

#[tokio::test]
async fn cleanup_failure_retains_the_session_and_prevents_runtime_replacement() {
    let host = Arc::new(Host::new());
    let home = tempfile::tempdir().unwrap();
    host.state.lock().await.home = Some(home.path().to_path_buf());
    for file in ["Country.mmdb", "GeoLite2-ASN.mmdb", "geosite.dat"] {
        tokio::fs::write(home.path().join(file), []).await.unwrap();
    }
    tokio::fs::write(home.path().join("config.yaml"),"listeners:\n  - name: local\n    type: mixed\n    listen: 127.0.0.1\n    port: 0\nrules: ['MATCH,DIRECT']\n").await.unwrap();
    assert!(call(&host, "setupConfig", Value::Null)
        .await
        .error
        .is_none());
    assert_eq!(call(&host, "startListener", Value::Null).await.result, true);
    let running = call(&host, "getRuntimeState", Value::Null).await.result;
    let address = running["listeners"][0]["address"].as_str().unwrap();
    assert!(tokio::net::TcpStream::connect(address).await.is_ok());
    {
        let state = host.state.lock().await;
        state
            .runtime
            .as_ref()
            .unwrap()
            .state
            .tunnel
            .report_tun_cleanup_failure("fixture route restoration failure".into());
    }
    let failed = call(&host, "getRuntimeState", Value::Null).await.result;
    assert_eq!(failed["running"], false);
    assert!(failed["failure"]
        .as_str()
        .unwrap()
        .contains("fixture route restoration failure"));
    for method in [
        "changeProxy",
        "unfixProxy",
        "asyncTestDelay",
        "updateExternalProvider",
    ] {
        assert_eq!(
            call(&host, method, Value::Null).await.error.unwrap().code,
            "resources_release_unconfirmed"
        );
    }
    let replacement = call(&host, "setupConfig", Value::Null).await;
    assert_eq!(
        replacement.error.unwrap().code,
        "resources_release_unconfirmed"
    );
    assert!(tokio::net::TcpStream::connect(address).await.is_err());
    let stopped = call(&host, "getRuntimeState", Value::Null).await.result;
    assert_eq!(stopped["configured"], true);
    assert_eq!(stopped["running"], false);
    assert_eq!(stopped["generation"], running["generation"]);
    assert!(stopped["failure"]
        .as_str()
        .unwrap()
        .contains("fixture route restoration failure"));
    for method in ["startListener", "setupConfig", "updateConfig"] {
        assert_eq!(
            call(&host, method, Value::Null).await.error.unwrap().code,
            "resources_release_unconfirmed"
        );
    }

    let (mut peer, stream) = tokio::io::duplex(4096);
    let session = tokio::spawn(crate::serve(Arc::clone(&host), stream));
    for id in ["first", "retry"] {
        write_frame(
            &mut peer,
            &serde_json::to_vec(&json!({"id":id,"method":"shutdown"})).unwrap(),
        )
        .await
        .unwrap();
        let response: Value =
            serde_json::from_slice(&read_frame(&mut peer).await.unwrap().unwrap()).unwrap();
        assert_eq!(response["id"], id);
        assert_eq!(response["error"]["code"], "resources_release_unconfirmed");
        assert!(response["result"].is_null());
    }
    write_frame(&mut peer, br#"{"id":"alive","method":"getIsInit"}"#)
        .await
        .unwrap();
    let response: Value =
        serde_json::from_slice(&read_frame(&mut peer).await.unwrap().unwrap()).unwrap();
    assert_eq!(response["result"], true);
    drop(peer);
    assert!(session
        .await
        .unwrap()
        .unwrap_err()
        .to_string()
        .contains("fixture route restoration failure"));
}

#[tokio::test]
async fn a_later_stop_cancels_startup_and_waits_for_core_release() {
    let host = Arc::new(Host::new());
    let home = tempfile::tempdir().unwrap();
    host.state.lock().await.home = Some(home.path().to_path_buf());
    for file in ["Country.mmdb", "GeoLite2-ASN.mmdb", "geosite.dat"] {
        tokio::fs::write(home.path().join(file), []).await.unwrap();
    }
    let occupied = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = occupied.local_addr().unwrap();
    tokio::fs::write(
        home.path().join("config.yaml"),
        format!("mixed-port: {}\nrules: ['MATCH,DIRECT']\n", address.port()),
    )
    .await
    .unwrap();
    assert!(call(&host, "setupConfig", Value::Null)
        .await
        .error
        .is_none());
    let (core_done, core_wait) = tokio::sync::watch::channel(false);
    let (released, release_started) = tokio::sync::oneshot::channel();
    struct ListenerRelease(Option<tokio::sync::oneshot::Sender<()>>);
    impl Drop for ListenerRelease {
        fn drop(&mut self) {
            if let Some(released) = self.0.take() {
                let _ = released.send(());
            }
        }
    }
    let release = ListenerRelease(Some(released));
    let task = tokio::spawn(async move {
        let _release = release;
        std::future::pending::<()>().await;
    });
    host.state
        .lock()
        .await
        .runtime
        .as_ref()
        .unwrap()
        .state
        .tunnel
        .set_tun_handle(meow_tunnel::TunHandle {
            task,
            core_done: Some(core_wait),
            udp_flows: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        })
        .await
        .unwrap();
    let starting = tokio::spawn({
        let host = Arc::clone(&host);
        async move { call(&host, "startListener", Value::Null).await }
    });
    tokio::time::timeout(std::time::Duration::from_secs(2), release_started)
        .await
        .unwrap()
        .unwrap();
    let mut stopping = Box::pin(call(&host, "stopListener", Value::Null));
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(20), &mut stopping)
            .await
            .is_err(),
        "Stop must await the retired core release"
    );
    core_done.send(true).unwrap();
    assert_eq!(
        starting.await.unwrap().error.unwrap().code,
        "request_superseded"
    );
    assert_eq!(stopping.await.result, true);
    let state = call(&host, "getRuntimeState", Value::Null).await.result;
    assert_eq!(state["running"], false);
    assert!(state["listeners"].as_array().unwrap().is_empty());
    drop(occupied);
    assert_eq!(call(&host, "startListener", Value::Null).await.result, true);
    assert!(tokio::net::TcpStream::connect(address).await.is_ok());
    host.shutdown().await.unwrap();
}
