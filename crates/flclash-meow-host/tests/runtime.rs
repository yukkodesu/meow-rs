use flclash_meow_host::{protocol::Request, Host};
use serde_json::{json, Value};
use std::{path::Path, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
};

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

async fn initialize(host: &Host, home: &Path) {
    for file in ["Country.mmdb", "GeoLite2-ASN.mmdb", "geosite.dat"] {
        tokio::fs::write(home.join(file), []).await.unwrap();
    }
    call(host, "initClash", json!({"home-dir": home, "version":1})).await;
}

async fn request(address: &str, path: &str) -> String {
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let mut body = String::new();
    tokio::time::timeout(Duration::from_secs(3), stream.read_to_string(&mut body))
        .await
        .unwrap()
        .unwrap();
    body
}

async fn read_header(peer: &mut TcpStream) {
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        assert!(header.len() < 8192, "fixture header exceeded limit");
        header.push(peer.read_u8().await.unwrap());
    }
}

#[tokio::test]
async fn runtime_reports_real_endpoints_config_logs_traffic_and_owned_cancellation() {
    Box::pin(endpoints_configuration_logs_and_traffic()).await;
    Box::pin(geodata_download_is_owned_and_uses_product_home()).await;
    Box::pin(stopping_cancels_pending_provider_preparation()).await;
}

async fn endpoints_configuration_logs_and_traffic() {
    use tracing_subscriber::prelude::*;
    let host = Host::new();
    let home = tempfile::tempdir().unwrap();
    initialize(&host, home.path()).await;
    let (filter, reload) =
        tracing_subscriber::reload::Layer::new(tracing_subscriber::EnvFilter::new("info"));
    tracing::subscriber::set_global_default(tracing_subscriber::registry().with(filter).with(
        meow_api::log_stream::LogBroadcastLayer {
            tx: host.log_sender(),
        },
    ))
    .unwrap();
    meow_api::log_stream::install_log_reloader(move |level| {
        let level = match level {
            "warning" => "warn",
            "silent" => "off",
            value => value,
        };
        reload
            .reload(tracing_subscriber::EnvFilter::try_new(level).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())
    });
    tokio::fs::create_dir(home.path().join("dashboard"))
        .await
        .unwrap();
    tokio::fs::write(
        home.path().join("dashboard/index.html"),
        "product-home-dashboard",
    )
    .await
    .unwrap();
    #[cfg(unix)]
    let custom_ui = unsafe { libc::geteuid() } != 0;
    #[cfg(windows)]
    let custom_ui = {
        #[link(name = "shell32")]
        unsafe extern "system" {
            fn IsUserAnAdmin() -> i32;
        }
        unsafe { IsUserAnAdmin() == 0 }
    };
    let mut profile = "listeners:\n  - name: local\n    type: mixed\n    listen: 127.0.0.1\n    port: 0\nexternal-controller: 127.0.0.1:0\nexternal-ui: dashboard\nmode: rule\nlog-level: debug\nrules: ['MATCH,REJECT']\nhosts: { test.example: 127.0.0.42 }\ndns:\n  enable: true\n  listen: 127.0.0.1:0\n".to_string();
    if !custom_ui {
        let check = call(&host, "checkConfig", json!(profile)).await;
        assert_eq!(check["valid"], false);
        assert!(check["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|diagnostic| diagnostic["path"] == "external-ui"));
        profile = profile.replace("external-ui: dashboard\n", "");
    }
    tokio::fs::write(home.path().join("config.yaml"), profile)
        .await
        .unwrap();
    call(&host, "setupConfig", Value::Null).await;
    call(&host, "startListener", Value::Null).await;
    let state = call(&host, "getRuntimeState", Value::Null).await;
    let proxy = state["listeners"][0]["address"].as_str().unwrap();
    let controller = state["externalController"].as_str().unwrap();
    let dns = state["dnsListen"].as_str().unwrap();
    assert_ne!(proxy.parse::<std::net::SocketAddr>().unwrap().port(), 0);
    let configs = request(controller, "/configs").await;
    assert!(configs.contains("\"mode\":\"rule\""));
    if custom_ui {
        assert!(request(controller, "/ui/index.html")
            .await
            .ends_with("product-home-dashboard"));
    }
    let dns_peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    dns_peer
        .send_to(
            b"\x12\x34\x01\0\0\x01\0\0\0\0\0\0\x04test\x07example\0\0\x01\0\x01",
            dns,
        )
        .await
        .unwrap();
    let mut answer = [0; 512];
    let (length, source) =
        tokio::time::timeout(Duration::from_secs(3), dns_peer.recv_from(&mut answer))
            .await
            .unwrap()
            .unwrap();
    assert_eq!(source.to_string(), dns);
    assert_eq!(&answer[..2], b"\x12\x34");
    assert!(answer[..length].windows(4).any(|a| a == [127, 0, 0, 42]));

    tracing::debug!("host-debug-visible");
    let history = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let logs = call(&host, "startLogNotify", Value::Null).await;
            if logs
                .as_array()
                .unwrap()
                .iter()
                .any(|log| log["Payload"] == "host-debug-visible")
            {
                break logs;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let log = history
        .as_array()
        .unwrap()
        .iter()
        .find(|log| log["Payload"] == "host-debug-visible")
        .unwrap();
    assert_eq!(log["LogLevel"], "debug");
    time::OffsetDateTime::parse(
        log["dateTime"].as_str().unwrap(),
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap();
    call(
        &host,
        "updateConfig",
        json!({"mode":"direct","log-level":"info"}),
    )
    .await;
    tracing::debug!("host-debug-hidden");
    tracing::info!("host-info-visible");
    let config = request(controller, "/configs").await;
    assert!(config.contains("\"mode\":\"direct\""));
    assert!(config.contains("\"log-level\":\"info\""));
    let invalid = host
        .call(Request {
            id: None,
            method: "updateConfig".into(),
            arguments: json!({"mode":"rule","log-level":"nonsense"}),
        })
        .await;
    assert!(invalid.error.is_some());
    assert!(request(controller, "/configs")
        .await
        .contains("\"mode\":\"direct\""));

    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_address = origin.local_addr().unwrap();
    let origin_task = tokio::spawn(async move {
        let (mut stream, _) = origin.accept().await.unwrap();
        read_header(&mut stream).await;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1024\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        stream.write_all(&[b'x'; 1024]).await.unwrap();
    });
    assert!(request(proxy, &format!("http://{origin_address}/"))
        .await
        .ends_with(&"x".repeat(1024)));
    origin_task.await.unwrap();
    tokio::time::sleep(Duration::from_millis(2100)).await;
    let totals = call(&host, "getTotalTraffic", json!(false)).await;
    let rates = call(&host, "getTraffic", json!(false)).await;
    assert!(rates["down"].as_i64().unwrap() > 0);
    assert!(rates["down"].as_i64().unwrap() < totals["down"].as_i64().unwrap());
    assert_eq!(call(&host, "getTraffic", json!(false)).await, rates);
    call(&host, "resetTraffic", Value::Null).await;
    assert_eq!(
        call(&host, "getTotalTraffic", json!(false)).await,
        json!({"up":0,"down":0})
    );
    let history = call(&host, "startLogNotify", Value::Null).await;
    assert!(history
        .as_array()
        .unwrap()
        .iter()
        .any(|log| log["Payload"] == "host-info-visible"));
    assert!(!history
        .as_array()
        .unwrap()
        .iter()
        .any(|log| log["Payload"] == "host-debug-hidden"));
    call(&host, "stopListener", Value::Null).await;
    let stopped = call(&host, "getRuntimeState", Value::Null).await;
    assert_eq!(stopped["listeners"], json!([]));
    assert!(stopped["dnsListen"].is_null());
    assert!(stopped["externalController"].is_null());
    assert!(TcpStream::connect(proxy).await.is_err());
    assert!(TcpStream::connect(controller).await.is_err());
    host.shutdown().await.unwrap();
}

async fn geodata_download_is_owned_and_uses_product_home() {
    let host = Host::new();
    let home = tempfile::tempdir().unwrap();
    initialize(&host, home.path()).await;
    let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = server.local_addr().unwrap();
    let (target_sent, target_received) = tokio::sync::oneshot::channel();
    let server_task = tokio::spawn(async move {
        let (mut peer, _) = server.accept().await.unwrap();
        let mut buf = [0; 2048];
        read_header(&mut peer).await;
        target_sent.send(()).unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(3), peer.read(&mut buf))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        let (mut peer, _) = server.accept().await.unwrap();
        read_header(&mut peer).await;
        peer.write_all(
            b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\ngeodata!",
        )
        .await
        .unwrap();
    });
    tokio::fs::write(home.path().join("config.yaml"),format!("geodata:\n  mmdb-path: resources/country.mmdb\n  auto-update: true\n  url:\n    mmdb: http://{address}/country\nrules: ['MATCH,DIRECT']\n")).await.unwrap();
    call(&host, "setupConfig", Value::Null).await;
    call(&host, "startListener", Value::Null).await;
    tokio::time::timeout(Duration::from_secs(3), target_received)
        .await
        .unwrap()
        .unwrap();
    call(&host, "stopListener", Value::Null).await;
    assert!(!home.path().join("resources/country.mmdb").exists());
    call(&host, "startListener", Value::Null).await;
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if home.path().join("resources/country.mmdb").exists() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        tokio::fs::read(home.path().join("resources/country.mmdb"))
            .await
            .unwrap(),
        b"geodata!"
    );
    call(&host, "stopListener", Value::Null).await;
    host.shutdown().await.unwrap();
    server_task.await.unwrap();
}

async fn stopping_cancels_pending_provider_preparation() {
    let host = Arc::new(Host::new());
    let home = tempfile::tempdir().unwrap();
    initialize(&host, home.path()).await;
    let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = server.local_addr().unwrap();
    let (sent, received) = tokio::sync::oneshot::channel();
    let server_task = tokio::spawn(async move {
        let (mut peer, _) = server.accept().await.unwrap();
        let mut buf = [0; 2048];
        read_header(&mut peer).await;
        sent.send(()).unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(3), peer.read(&mut buf))
                .await
                .unwrap()
                .unwrap(),
            0
        );
    });
    tokio::fs::write(home.path().join("config.yaml"),format!("proxy-providers:\n  pending:\n    type: http\n    url: http://{address}/nodes\n    path: providers/pending.yaml\nproxy-groups:\n  - name: select\n    type: select\n    use: [pending]\nrules: ['MATCH,select']\n")).await.unwrap();
    let applying = {
        let host = Arc::clone(&host);
        tokio::spawn(async move {
            host.call(Request {
                id: None,
                method: "setupConfig".into(),
                arguments: Value::Null,
            })
            .await
        })
    };
    tokio::time::timeout(Duration::from_secs(3), received)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(call(&host, "stopListener", Value::Null).await, true);
    assert_eq!(
        applying.await.unwrap().error.unwrap().code,
        "request_superseded"
    );
    assert_eq!(
        call(&host, "getRuntimeState", Value::Null).await["configured"],
        false
    );
    assert!(!home.path().join("providers/pending.yaml").exists());
    server_task.await.unwrap();
    host.shutdown().await.unwrap();
}
