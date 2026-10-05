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
async fn cleanup_failure_retains_the_session_and_prevents_runtime_replacement() {
    let host = Arc::new(Host::new());
    let home = tempfile::tempdir().unwrap();
    assert!(call(
        &host,
        "initClash",
        json!({"home-dir":home.path(),"version":1})
    )
    .await
    .error
    .is_none());
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
