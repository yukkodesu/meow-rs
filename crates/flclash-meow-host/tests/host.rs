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
async fn system_dns_compatibility_covers_upstream_lists_and_policies() {
    let host = Host::new();
    let home = tempfile::tempdir().unwrap();
    call(&host, "initClash", json!({"home-dir":home.path()})).await;
    for field in [
        "nameserver",
        "fallback",
        "default-nameserver",
        "proxy-server-nameserver",
        "nameserver-policy",
    ] {
        let servers = "[' system ', 'system://', 'system://#DIRECT', 'dhcp://system', '127.0.0.1']";
        let value = if field == "nameserver-policy" {
            format!("{{example.com: {servers}}}")
        } else {
            servers.into()
        };
        let yaml = format!("dns:\n  enable: true\n  {field}: {value}\nrules: ['MATCH,DIRECT']\n");
        let checked = call(&host, "checkConfig", json!(yaml)).await;
        assert_eq!(checked["valid"], true, "{field}: {checked}");
        let path = if field == "nameserver-policy" {
            "dns.nameserver-policy.example.com".into()
        } else {
            format!("dns.{field}")
        };
        assert!(
            checked["diagnostics"]
                .as_array()
                .unwrap()
                .iter()
                .any(|d| d["severity"] == "warning" && d["path"] == path),
            "{field}: {checked}"
        );
        let strict = call(&host, "checkConfig", json!(format!("strict: true\n{yaml}"))).await;
        assert_eq!(strict["valid"], false, "{field}: {strict}");
        let only_system = yaml.replace(
            &value,
            if field == "nameserver-policy" {
                "{example.com: 'system://'}"
            } else {
                "['system://']"
            },
        );
        let rejected = call(&host, "checkConfig", json!(only_system)).await;
        assert_eq!(rejected["valid"], false, "{field}: {rejected}");
        let invalid = yaml.replace("127.0.0.1", "quic://127.0.0.1");
        let rejected = call(&host, "checkConfig", json!(invalid)).await;
        assert_eq!(rejected["valid"], false, "{field}: {rejected}");
    }
    host.shutdown().await.unwrap();
}

#[tokio::test]
async fn compatibility_warnings_preserve_native_configuration_policy() {
    let host = Host::new();
    let home = tempfile::tempdir().unwrap();
    call(&host, "initClash", json!({"home-dir": home.path()})).await;
    for yaml in [
        "dns: {cache-algorithm: arc, ipv6: true, prefer-h3: true}\netag-support: true\nprofile: {store-selected: true}\nproxies: [{name: edge, type: http, server: localhost, port: 80, client-fingerprint: chrome}]\nrules: ['MATCH,DIRECT']\n",
        "proxies: [{name: unavailable, type: tuic}]\nrules: ['MATCH,DIRECT']\n",
        "strict: true\nproxies: [{name: unavailable, type: tuic}]\nrules: ['MATCH,DIRECT']\n",
        "tun: {mtu: 1200}\nrules: ['MATCH,DIRECT']\n",
    ] {
        let raw = meow_config::parse_raw_yaml(yaml).unwrap();
        let native = meow_config::validate_config(raw, Some(home.path())).await;
        let checked = call(&host, "checkConfig", json!(yaml)).await;
        assert_eq!(checked["valid"], native.is_ok(), "{yaml}: {checked}; native: {native:?}");
        if native.is_ok() {
            tokio::fs::write(home.path().join("config.yaml"), yaml).await.unwrap();
            call(&host, "setupConfig", Value::Null).await;
        }
    }
    host.shutdown().await.unwrap();
}

#[tokio::test]
async fn fresh_http_providers_are_checked_before_application_without_persisting_payloads() {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = server.local_addr().unwrap();
    let requests = tokio::spawn(async move {
        let mut peers = tokio::task::JoinSet::new();
        while let Ok((mut peer, _)) = server.accept().await {
            peers.spawn(async move {
                let mut request = [0; 4096];
                let count = peer.read(&mut request).await.unwrap();
                let request = String::from_utf8_lossy(&request[..count]);
                let body = if request.starts_with("GET /rules") {
                    "payload: ['example.com']\n"
                } else if request.starts_with("GET /unsafe") {
                    "proxies: [{name: edge, type: http, server: localhost, port: invalid}]\n"
                } else {
                    "proxies: [{name: edge, type: http, server: localhost, port: 80}]\n"
                };
                peer.write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            });
        }
    });
    let host = Host::new();
    let home = tempfile::tempdir().unwrap();
    call(&host, "initClash", json!({"home-dir":home.path()})).await;
    let profile = format!("strict: true\nproxy-providers: {{remote: {{type: http, url: 'http://{address}/nodes', path: nodes.yaml}}}}\nproxy-groups: [{{name: route, type: select, use: [remote]}}]\nrule-providers: {{domains: {{type: http, url: 'http://{address}/rules', path: domains.yaml, behavior: domain}}}}\nrules: ['RULE-SET,domains,DIRECT', 'MATCH,route']\n");
    let checked = call(&host, "checkConfig", json!(profile)).await;
    assert_eq!(checked["valid"], true, "{checked}");
    assert!(!home.path().join("nodes.yaml").exists());
    assert!(!home.path().join("domains.yaml").exists());
    let unsafe_profile = profile.replace("/nodes", "/unsafe");
    let rejected = call(&host, "checkConfig", json!(unsafe_profile)).await;
    assert_eq!(
        rejected["valid"], false,
        "Native provider parse errors must block under explicit strict mode"
    );
    assert!(rejected["diagnostics"].to_string().contains("port"));
    assert!(!home.path().join("nodes.yaml").exists());
    tokio::fs::write(home.path().join("config.yaml"), profile)
        .await
        .unwrap();
    call(&host, "setupConfig", Value::Null).await;
    assert!(home.path().join("nodes.yaml").exists());
    assert!(home.path().join("domains.yaml").exists());
    call(&host, "shutdown", Value::Null).await;
    requests.abort();
    let _ = requests.await;
}

#[tokio::test]
async fn plugin_file_reads_remain_confined_before_engine_parsing() {
    let host = Host::new();
    let home = tempfile::tempdir().unwrap();
    call(&host, "initClash", json!({"home-dir": home.path()})).await;
    for opts in [
        "{certificate: /outside/cert.pem}",
        "'certificate=/outside/cert.pem'",
    ] {
        let yaml = format!("proxies: [{{name: edge, type: ss, server: localhost, port: 443, cipher: aes-128-gcm, password: fixture, plugin: gost-plugin, plugin-opts: {opts}}}]\nrules: ['MATCH,DIRECT']\n");
        let check = call(&host, "checkConfig", json!(yaml)).await;
        assert_eq!(check["valid"], false);
        assert!(check["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["path"] == "proxies[0].plugin-opts.certificate"));
        tokio::fs::write(home.path().join("nodes.yaml"), &yaml)
            .await
            .unwrap();
        tokio::fs::write(home.path().join("config.yaml"), "strict: true\nproxy-providers: {local: {type: file, path: nodes.yaml}}\nproxy-groups: [{name: route, type: select, use: [local]}]\nrules: ['MATCH,route']\n").await.unwrap();
        let result = host
            .call(Request {
                id: None,
                method: "setupConfig".into(),
                arguments: Value::Null,
            })
            .await;
        assert!(result
            .error
            .unwrap()
            .message
            .contains("plugin-opts.certificate"));
    }
    host.shutdown().await.unwrap();
}

#[tokio::test]
async fn successful_configuration_does_not_announce_an_unnamed_provider() {
    let host = Host::new();
    let home = tempfile::tempdir().unwrap();
    for file in ["Country.mmdb", "GeoLite2-ASN.mmdb", "geosite.dat"] {
        tokio::fs::write(home.path().join(file), []).await.unwrap();
    }
    call(&host, "initClash", json!({"home-dir":home.path()})).await;
    tokio::fs::write(home.path().join("config.yaml"), "rules: ['MATCH,DIRECT']\n")
        .await
        .unwrap();
    let mut events = host.subscribe_events();
    call(&host, "setupConfig", Value::Null).await;
    assert!(
        events.try_recv().is_err(),
        "Configuration completion is not a provider refresh"
    );
    call(&host, "shutdown", Value::Null).await;
}

#[tokio::test]
async fn initialization_is_idle_and_unknown_nested_options_are_reported() {
    let host = Host::new();
    let dir = tempfile::tempdir().unwrap();
    for method in ["checkConfig", "validateConfig"] {
        let response = host
            .call(Request {
                id: None,
                method: method.into(),
                arguments: json!("rules: ['MATCH,DIRECT']\n"),
            })
            .await;
        assert_eq!(response.error.unwrap().code, "not_initialized");
    }
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
    assert!(matches!(
        state["recovery"]["state"].as_str(),
        Some("clean" | "recovered" | "needsPrivilege" | "failed")
    ));
    assert!(state["recovery"]["details"].is_array());
    let auth = call(&host, "checkConfig", json!("authentication: ['fixture:local-only']\nskip-auth-prefixes: []\nrules: ['MATCH,DIRECT']\n")).await;
    assert_eq!(auth["valid"], true);
    assert!(auth["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .any(|diagnostic| {
            diagnostic["severity"] == "warning"
                && diagnostic["path"] == "authentication"
                && diagnostic["reason"].as_str().unwrap().contains("127.0.0.1")
                && diagnostic["reason"].as_str().unwrap().contains("::1")
        }));
    let check = call(&host, "checkConfig", json!("proxies:\n  - name: edge\n    type: vless\n    server: localhost\n    port: 443\n    uuid: 00000000-0000-0000-0000-000000000000\n    reality-opts:\n      public-key: x\n      imaginary: true\n")).await;
    assert_eq!(check["valid"], true);
    assert!(check["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .any(|d| d["path"] == "proxies[0].reality-opts.imaginary"));
    let malformed = call(&host, "checkConfig", json!("proxies: [")).await;
    assert_eq!(malformed["valid"], false);
    assert_eq!(malformed["diagnostics"][0]["path"], "$");
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
    host.shutdown().await.unwrap();
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
    for (runtime_fields, path) in [
        ("tun: {mtu: 1200}", "tun.mtu"),
        ("authentication: [missing-colon]", "authentication"),
        ("external-controller: invalid", "external-controller"),
        ("dns: {enable: true, listen: invalid}", "dns.listen"),
        (
            "dns: {enable: true, nameserver: ['invalid://resolver']}",
            "dns.nameserver",
        ),
        (
            "dns: {enable: true, enhanced-mode: fake-ip, fake-ip-range: invalid}",
            "dns.fake-ip-range",
        ),
        (
            "listeners: [{name: edge, type: mixed, listen: invalid, port: 0}]",
            "listeners[0].listen",
        ),
    ] {
        let check = call(
            &host,
            "checkConfig",
            json!(format!("{runtime_fields}\nrules: ['MATCH,DIRECT']\n")),
        )
        .await;
        assert_eq!(check["valid"], false, "{runtime_fields}");
        assert!(
            check["diagnostics"]
                .as_array()
                .unwrap()
                .iter()
                .any(|d| d["path"] == path),
            "{check}"
        );
        assert!(fetch(proxy_address, origin_address).await.ends_with("meow"));
        assert_eq!(
            tokio::fs::read_to_string(dir.path().join("config.yaml"))
                .await
                .unwrap(),
            config
        );
    }
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
    for _ in 0..3 {
        assert_eq!(call(&host, "startListener", Value::Null).await, true);
        assert!(fetch(proxy_address, origin_address).await.ends_with("meow"));
        assert_eq!(call(&host, "stopListener", Value::Null).await, true);
        assert!(TcpStream::connect(proxy_address).await.is_err());
        let released = TcpListener::bind(proxy_address).await.unwrap();
        drop(released);
        let state = call(&host, "getRuntimeState", Value::Null).await;
        assert_eq!(state["configured"], true);
        assert_eq!(state["running"], false);
        assert!(state["failure"].is_null());
    }
    assert_eq!(call(&host, "getIsInit", Value::Null).await, true);
    host.shutdown().await.unwrap();
    origin_task.abort();
}

#[tokio::test]
async fn provider_nodes_with_unknown_options_follow_native_policy() {
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
        "proxies:\n  - name: local\n    type: http\n    server: localhost\n    port: 80\n    imaginary-route: true\n",
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
    assert!(result.error.is_none(), "{:?}", result.error);
    assert_eq!(
        call(&host, "getRuntimeState", Value::Null).await["configured"],
        true
    );
    host.shutdown().await.unwrap();
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
    tokio::fs::write(dir.path().join("config.yaml"),"strict: true\nproxy-providers:\n  local:\n    type: file\n    path: nodes.yaml\nproxy-groups:\n  - name: route\n    type: select\n    use: [local]\nrules: ['MATCH,route']\n").await.unwrap();
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
        "proxies:\n  - name: wrong\n    type: http\n    server: localhost\n    port: invalid\n",
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
    host.shutdown().await.unwrap();
    task.abort();
}
