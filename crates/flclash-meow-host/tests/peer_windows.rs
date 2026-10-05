#![cfg(windows)]

use flclash_meow_host::protocol::{read_frame, write_frame};
use serde_json::{json, Value};
use std::{process::Stdio, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        windows::named_pipe::{NamedPipeServer, ServerOptions},
        TcpListener, TcpStream,
    },
};

async fn call(pipe: &mut NamedPipeServer, method: &str, arguments: Value) -> Value {
    let request = json!({"id":method,"method":method,"arguments":arguments});
    write_frame(pipe, &serde_json::to_vec(&request).unwrap())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let frame = read_frame(pipe).await.unwrap().unwrap();
            let response: Value = serde_json::from_slice(&frame).unwrap();
            if response["id"] == method {
                return response;
            }
        }
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn a_real_windows_host_rejects_an_imported_profile_hard_link() {
    let directory = tempfile::tempdir().unwrap();
    let home = directory.path().join("home");
    std::fs::create_dir_all(home.join("profiles")).unwrap();
    let outside = directory.path().join("outside.yaml");
    std::fs::write(&outside, "boundary-fixture: outside-product-home\n").unwrap();
    std::fs::hard_link(&outside, home.join("profiles/1.yaml")).unwrap();
    std::fs::write(home.join("profiles/2.yaml"), "name: retained-profile\n").unwrap();
    std::fs::write(
        home.join("config.yaml"),
        "listeners:\n  - name: local\n    type: mixed\n    listen: 127.0.0.1\n    port: 0\nrules: ['MATCH,DIRECT']\n",
    )
    .unwrap();
    for file in ["Country.mmdb", "GeoLite2-ASN.mmdb", "geosite.dat"] {
        std::fs::write(home.join(file), []).unwrap();
    }
    let address = format!(
        r"\\.\pipe\FlClashMeowCore_{}",
        uuid::Uuid::new_v4().simple()
    );
    let mut pipe = ServerOptions::new()
        .first_pipe_instance(true)
        .reject_remote_clients(true)
        .create(&address)
        .unwrap();
    let mut process = tokio::process::Command::new(env!("CARGO_BIN_EXE_flclash-meow-host"))
        .arg(&address)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), pipe.connect())
        .await
        .unwrap()
        .unwrap();
    let initialized = call(&mut pipe, "initClash", json!({"home-dir":home,"version":1})).await;
    assert!(initialized.get("error").is_none(), "{initialized}");
    let profile = call(&mut pipe, "getProfileConfig", json!(1)).await;
    let retained = call(&mut pipe, "getProfileConfig", json!(2)).await;
    let configured = call(&mut pipe, "setupConfig", Value::Null).await;
    let started = call(&mut pipe, "startListener", Value::Null).await;
    assert!(configured.get("error").is_none(), "{configured}");
    assert!(started.get("error").is_none(), "{started}");
    let state = call(&mut pipe, "getRuntimeState", Value::Null).await;
    let endpoint = state["result"]["listeners"][0]["address"].as_str().unwrap();
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_address = origin.local_addr().unwrap();
    let origin_task = tokio::spawn(async move {
        let (mut stream, _) = origin.accept().await.unwrap();
        let mut request = [0; 1024];
        assert!(stream.read(&mut request).await.unwrap() > 0);
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\nConnection: close\r\n\r\nowned-profile",
            )
            .await
            .unwrap();
    });
    let mut client = TcpStream::connect(endpoint).await.unwrap();
    client
        .write_all(
            format!("GET http://{origin_address}/ HTTP/1.1\r\nHost: {origin_address}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let mut body = String::new();
    tokio::time::timeout(Duration::from_secs(5), client.read_to_string(&mut body))
        .await
        .unwrap()
        .unwrap();
    origin_task.await.unwrap();
    let stopped = call(&mut pipe, "shutdown", Value::Null).await;
    assert_eq!(stopped["result"], true);
    assert!(tokio::time::timeout(Duration::from_secs(5), process.wait())
        .await
        .unwrap()
        .unwrap()
        .success());
    assert_eq!(profile["error"]["code"], "config_read_failed", "{profile}");
    assert!(profile["result"].is_null());
    assert_eq!(retained["result"]["name"], "retained-profile");
    assert!(body.ends_with("owned-profile"), "{body}");
}
