use meow_config::{build_config, parse_raw_yaml, validate_config};
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

#[tokio::test]
async fn first_use_geosite_is_validated_in_memory_before_normal_application() {
    let home = tempfile::tempdir().unwrap();
    let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = server.local_addr().unwrap();
    let bytes =
        meow_rules::mrs_parser::write_geosite_mrs(&meow_rules::mrs_parser::GeositePayload {
            categories: vec![("local".into(), vec!["example.com".into()])],
        })
        .unwrap();
    let expected = bytes.clone();
    let served = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut peer, _) = tokio::time::timeout(Duration::from_secs(5), server.accept())
                .await
                .unwrap()
                .unwrap();
            let mut request = [0; 2048];
            assert!(peer.read(&mut request).await.unwrap() > 0);
            peer.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    bytes.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
            peer.write_all(&bytes).await.unwrap();
        }
    });
    let path = home.path().join("sites.mrs");
    let raw = parse_raw_yaml(&format!("strict: true\ngeodata: {{geosite-path: '{}', url: {{geosite: 'http://{address}/sites'}}}}\ndns: {{enable: true, nameserver-policy: {{'geosite:local': 'rcode://success'}}}}\nrules: ['GEOSITE,local,DIRECT', 'MATCH,DIRECT']\n", path.display())).unwrap();
    validate_config(raw.clone(), Some(home.path()))
        .await
        .unwrap();
    assert!(
        !path.exists(),
        "Preflight must not populate persistent geodata"
    );
    let live = build_config(raw, Some(home.path())).await.unwrap();
    served.await.unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), expected);
    assert!(live.dns.resolver.nameserver_policy().is_some());
}

#[tokio::test]
async fn complete_validation_is_read_only_and_does_not_make_live_builds_offline() {
    let home = tempfile::tempdir().unwrap();
    let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = server.local_addr().unwrap();
    let provider = "proxies: [{name: cached, type: http, server: localhost, port: 80}]\n";
    std::fs::write(home.path().join("provider.yaml"), provider).unwrap();
    std::fs::write(
        home.path().join("selector-cache.json"),
        "{\"route\":\"cached\"}",
    )
    .unwrap();
    let mut raw = parse_raw_yaml(&format!("strict: true\nproxy-providers: {{local: {{type: http, url: 'http://{address}/nodes', path: provider.yaml}}}}\nproxy-groups: [{{name: route, type: select, use: [local]}}]\ndns: {{enable: true, enhanced-mode: fake-ip, store-fake-ip: true}}\nrules: ['MATCH,route']\n")).unwrap();
    let served = tokio::spawn(async move {
        for name in ["preflight", "online"] {
            let (mut peer, _) = tokio::time::timeout(Duration::from_secs(5), server.accept())
                .await
                .unwrap()
                .unwrap();
            let mut request = [0; 2048];
            assert!(peer.read(&mut request).await.unwrap() > 0);
            let body =
                format!("proxies: [{{name: {name}, type: http, server: localhost, port: 80}}]\n");
            peer.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        }
    });
    validate_config(raw.clone(), Some(home.path()))
        .await
        .unwrap();
    assert_eq!(
        std::fs::read_to_string(home.path().join("provider.yaml")).unwrap(),
        provider
    );
    assert_eq!(
        std::fs::read_to_string(home.path().join("selector-cache.json")).unwrap(),
        "{\"route\":\"cached\"}"
    );
    assert!(!home.path().join("fakeip-v4.json").exists());
    assert!(!home.path().join("fakeip-v6.json").exists());
    raw.dns = None;
    let live = build_config(raw, Some(home.path())).await.unwrap();
    served.await.unwrap();
    assert_eq!(live.proxy_providers["local"].proxies()[0].name(), "online");
    assert!(std::fs::read_to_string(home.path().join("provider.yaml"))
        .unwrap()
        .contains("online"));
}
