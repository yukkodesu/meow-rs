#![cfg(unix)]

use flclash_meow_host::{protocol::Request, Host};
use serde_json::{json, Value};

async fn call(host: &Host, method: &str, arguments: Value) -> Value {
    let response = host
        .call(Request {
            id: Some(method.into()),
            method: method.into(),
            arguments,
        })
        .await;
    assert!(response.error.is_none(), "{}: {:?}", method, response.error);
    response.result
}

#[tokio::test]
async fn authenticated_peer_home_is_required_and_serves_the_original_profile() {
    let home = tempfile::tempdir().unwrap();
    let uid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getegid() };
    let rejected = Host::with_peer_identity(uid.wrapping_add(1), gid);
    let response = rejected
        .call(Request {
            id: None,
            method: "initClash".into(),
            arguments: json!({"home-dir":home.path(),"version":1}),
        })
        .await;
    assert_eq!(response.error.unwrap().code, "invalid_home_owner");
    assert_eq!(call(&rejected, "getIsInit", Value::Null).await, false);
    rejected.shutdown().await.unwrap();

    for file in ["Country.mmdb", "GeoLite2-ASN.mmdb", "geosite.dat"] {
        tokio::fs::write(home.path().join(file), []).await.unwrap();
    }
    tokio::fs::create_dir(home.path().join("profiles"))
        .await
        .unwrap();
    tokio::fs::write(
        home.path().join("profiles/1.yaml"),
        "unknown-original: retained\nrules: ['MATCH,DIRECT']\n",
    )
    .await
    .unwrap();
    tokio::fs::write(home.path().join("config.yaml"), "listeners:\n  - name: local\n    type: mixed\n    listen: 127.0.0.1\n    port: 0\nrules: ['MATCH,DIRECT']\n").await.unwrap();
    let host = Host::with_peer_identity(uid, gid);
    assert_eq!(
        call(
            &host,
            "initClash",
            json!({"home-dir":home.path(),"version":1})
        )
        .await,
        true
    );
    assert_eq!(
        call(&host, "getProfileConfig", json!(1)).await["unknown-original"],
        "retained"
    );
    assert_eq!(call(&host, "setupConfig", Value::Null).await, "");
    assert_eq!(call(&host, "startListener", Value::Null).await, true);
    let state = call(&host, "getRuntimeState", Value::Null).await;
    let address = state["listeners"][0]["address"].as_str().unwrap();
    assert!(tokio::net::TcpStream::connect(address).await.is_ok());
    assert_eq!(call(&host, "stopListener", Value::Null).await, true);
    assert!(tokio::net::TcpStream::connect(address).await.is_err());
    host.shutdown().await.unwrap();
}
