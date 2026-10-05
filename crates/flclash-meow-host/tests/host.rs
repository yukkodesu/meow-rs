use flclash_meow_host::{protocol::Request, Host};
use serde_json::{json, Value};

async fn call(host: &Host, method: &str, arguments: Value) -> Value {
    let response = host
        .call(Request {
            id: Some("request".into()),
            method: method.into(),
            arguments,
        })
        .await;
    assert!(response.error.is_none(), "{:?}", response.error);
    response.result
}

#[tokio::test]
async fn initialization_is_idle_and_unknown_nested_options_are_reported() {
    let host = Host::new();
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(
        call(&host, "getCoreInfo", Value::Null).await["protocolVersion"],
        1
    );
    assert_eq!(
        call(
            &host,
            "initClash",
            json!({"home-dir":dir.path(),"version":1})
        )
        .await,
        true
    );
    let state = call(&host, "getRuntimeState", Value::Null).await;
    assert_eq!(state["configured"], false);
    assert_eq!(state["running"], false);
    let check = call(&host, "checkConfig", json!("proxies:\n  - name: edge\n    type: vless\n    server: localhost\n    port: 443\n    uuid: 00000000-0000-0000-0000-000000000000\n    reality-opts:\n      public-key: x\n      imaginary: true\n")).await;
    assert_eq!(check["valid"], false);
    assert!(check["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .any(|d| d["path"] == "proxies[0].reality-opts.imaginary"));
    let malformed = call(&host, "checkConfig", json!("proxies: [")).await;
    assert_eq!(malformed["valid"], false);
    assert_eq!(malformed["diagnostics"][0]["path"], "$");
    let alias = call(
        &host,
        "checkConfig",
        json!("proxies: [{name: local, type: direct}]\nrules: ['MATCH,local']\n"),
    )
    .await;
    assert_eq!(alias["valid"], false);
    assert!(alias["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .any(|d| d["path"] == "proxies[0].name"));
    let outside = tempfile::tempdir().unwrap();
    for path in [
        "../../../config.yaml".to_string(),
        outside
            .path()
            .join("private.yaml")
            .to_string_lossy()
            .into_owned(),
    ] {
        let yaml = serde_yaml::to_string(&json!({"proxy-providers":{"private":{"type":"file","path":path}},"proxy-groups":[{"name":"group","type":"select","use":["private"]}]})).unwrap();
        let checked = call(&host, "checkConfig", json!(yaml)).await;
        assert_eq!(checked["valid"], false);
        assert!(checked["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["path"] == "proxy-providers.private.path"));
    }
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(outside.path(), dir.path().join("escape")).unwrap();
        let checked = call(
            &host,
            "checkConfig",
            json!("proxy-providers:\n  private:\n    type: file\n    path: escape/private.yaml\n"),
        )
        .await;
        assert_eq!(checked["valid"], false);
        assert!(checked["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["path"] == "proxy-providers.private.path"));
    }
    assert!(!call(&host, "validateConfig", json!("proxies: ["))
        .await
        .as_str()
        .unwrap()
        .is_empty());
    host.shutdown().await;
}

#[tokio::test]
async fn proxy_ready_transfers_data_and_failed_replacement_restores_the_previous_listener() {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_address = origin.local_addr().unwrap();
    let origin_task = tokio::spawn(async move {
        loop {
            let (mut peer, _) = origin.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = [0; 1024];
                let _ = peer.read(&mut buf).await;
                peer.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nmeow",
                )
                .await
                .unwrap();
            });
        }
    });
    let reservation = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_address = reservation.local_addr().unwrap();
    drop(reservation);
    let host = Host::new();
    let dir = tempfile::tempdir().unwrap();
    for file in ["Country.mmdb", "GeoLite2-ASN.mmdb", "geosite.dat"] {
        tokio::fs::write(dir.path().join(file), []).await.unwrap();
    }
    call(
        &host,
        "initClash",
        json!({"home-dir":dir.path(),"version":1}),
    )
    .await;
    let config = format!(
        "mixed-port: {}\nmode: rule\nrules: ['MATCH,DIRECT']\n",
        proxy_address.port()
    );
    tokio::fs::write(dir.path().join("config.yaml"), &config)
        .await
        .unwrap();
    call(
        &host,
        "setupConfig",
        json!({"selected-map":{},"test-url":"http://localhost/"}),
    )
    .await;
    assert!(
        TcpStream::connect(proxy_address).await.is_err(),
        "setup must leave proxy idle"
    );
    assert_eq!(call(&host, "startListener", Value::Null).await, true);
    async fn fetch(proxy: std::net::SocketAddr, origin: std::net::SocketAddr) -> String {
        let mut peer = TcpStream::connect(proxy).await.unwrap();
        peer.write_all(
            format!("GET http://{origin}/ HTTP/1.1\r\nHost: {origin}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
        let mut response = String::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            peer.read_to_string(&mut response),
        )
        .await
        .unwrap()
        .unwrap();
        response
    }
    assert!(fetch(proxy_address, origin_address).await.ends_with("meow"));
    let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
    tokio::fs::write(
        dir.path().join("config.yaml"),
        format!(
            "mixed-port: {}\nrules: ['MATCH,DIRECT']\n",
            occupied.local_addr().unwrap().port()
        ),
    )
    .await
    .unwrap();
    let replacement = host
        .call(Request {
            id: Some("replace".into()),
            method: "setupConfig".into(),
            arguments: json!({"selected-map":{},"test-url":"http://localhost/"}),
        })
        .await;
    assert_eq!(replacement.error.unwrap().code, "config_apply_failed");
    assert!(fetch(proxy_address, origin_address).await.ends_with("meow"));
    assert_eq!(
        call(&host, "getRuntimeState", Value::Null).await["running"],
        true
    );
    assert_eq!(call(&host, "stopListener", Value::Null).await, true);
    assert!(TcpStream::connect(proxy_address).await.is_err());
    assert_eq!(call(&host, "getIsInit", Value::Null).await, true);
    host.shutdown().await;
    origin_task.abort();
}

#[tokio::test]
async fn provider_nodes_with_unknown_options_cannot_silently_enter_a_group() {
    let host = Host::new();
    let dir = tempfile::tempdir().unwrap();
    call(
        &host,
        "initClash",
        json!({"home-dir":dir.path(),"version":1}),
    )
    .await;
    tokio::fs::write(
        dir.path().join("nodes.yaml"),
        "proxies:\n  - name: local\n    type: direct\n    imaginary-route: true\n",
    )
    .await
    .unwrap();
    tokio::fs::write(dir.path().join("config.yaml"),"proxy-providers:\n  local:\n    type: file\n    path: nodes.yaml\nproxy-groups:\n  - name: route\n    type: select\n    use: [local]\nrules: ['MATCH,route']\n").await.unwrap();
    let result = host
        .call(Request {
            id: Some("apply".into()),
            method: "setupConfig".into(),
            arguments: json!({"selected-map":{},"test-url":"http://localhost/"}),
        })
        .await;
    let error = result
        .error
        .expect("Unknown provider routing options must prevent application");
    assert!(
        error.message.contains("imaginary-route"),
        "{}",
        error.message
    );
    assert_eq!(
        call(&host, "getRuntimeState", Value::Null).await["configured"],
        false
    );
    host.shutdown().await;
}

#[tokio::test]
async fn provider_members_can_be_selected_probed_and_refreshed_without_losing_valid_data() {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    let service = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/", service.local_addr().unwrap());
    let address = service.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = service.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = [0; 1024];
                let _ = stream.read(&mut buf).await;
                stream
                    .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    .await
                    .unwrap();
                let _ = stream.read(&mut buf).await;
                stream
                    .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                    .await
                    .unwrap();
            });
        }
    });
    let host = Host::new();
    let dir = tempfile::tempdir().unwrap();
    call(
        &host,
        "initClash",
        json!({"home-dir":dir.path(),"version":1}),
    )
    .await;
    let nodes = dir.path().join("nodes.yaml");
    let node = |name: &str| {
        format!(
            "  - name: {name}\n    type: http\n    server: 127.0.0.1\n    port: {}\n",
            address.port()
        )
    };
    tokio::fs::write(
        &nodes,
        format!("proxies:\n{}{}", node("first"), node("second")),
    )
    .await
    .unwrap();
    tokio::fs::write(dir.path().join("config.yaml"),"proxy-providers:\n  local:\n    type: file\n    path: nodes.yaml\nproxy-groups:\n  - name: route\n    type: select\n    use: [local]\nrules: ['MATCH,route']\n").await.unwrap();
    call(
        &host,
        "setupConfig",
        json!({"selected-map":{},"test-url":url}),
    )
    .await;
    call(
        &host,
        "changeProxy",
        json!({"group-name":"route","proxy-name":"second"}),
    )
    .await;
    let proxies = call(&host, "getProxies", Value::Null).await;
    assert_eq!(proxies["proxies"]["route"]["now"], "second");
    assert_eq!(proxies["proxies"]["first"]["type"], "Http");
    let delay = call(
        &host,
        "asyncTestDelay",
        json!({"proxy-name":"first","test-url":url,"timeout":1000}),
    )
    .await;
    assert_eq!(delay["url"], url);
    assert!(delay["value"].as_u64().unwrap() > 0);
    let provider = call(&host, "getExternalProvider", json!("local")).await;
    assert_eq!(provider["count"], 2);
    assert_eq!(provider["vehicle-type"], "File");
    assert!(provider["update-at"].is_string());
    tokio::fs::write(
        &nodes,
        "proxies:\n  - name: wrong\n    type: direct\n    impossible-routing-option: true\n",
    )
    .await
    .unwrap();
    let failed = host
        .call(Request {
            id: Some("refresh".into()),
            method: "updateExternalProvider".into(),
            arguments: json!("local"),
        })
        .await;
    assert!(failed.error.is_some());
    assert_eq!(
        call(&host, "getExternalProvider", json!("local")).await["count"],
        2
    );
    tokio::fs::write(&nodes, format!("proxies:\n{}", node("third")))
        .await
        .unwrap();
    call(&host, "updateExternalProvider", json!("local")).await;
    assert_eq!(
        call(&host, "getProxies", Value::Null).await["proxies"]["route"]["all"],
        json!(["third"])
    );
    host.shutdown().await;
    task.abort();
}
