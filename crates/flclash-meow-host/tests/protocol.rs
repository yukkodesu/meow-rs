use flclash_meow_host::protocol::{read_frame, write_frame, MAX_FRAME_SIZE};
use tokio::io::AsyncWriteExt;

#[tokio::test]
async fn unknown_method_and_retained_unsupported_method_have_distinct_wire_errors() {
    use flclash_meow_host::{serve, Host};
    use std::sync::Arc;
    let (mut peer, stream) = tokio::io::duplex(4096);
    let session = tokio::spawn(serve(Arc::new(Host::new()), stream));
    for (method, code) in [
        ("inventedRpc", "unknown_method"),
        ("forceGc", "unsupported_method"),
    ] {
        let request = serde_json::json!({"id":method,"method":method});
        write_frame(&mut peer, request.to_string().as_bytes())
            .await
            .unwrap();
        let response: serde_json::Value =
            serde_json::from_slice(&read_frame(&mut peer).await.unwrap().unwrap()).unwrap();
        assert_eq!(response["id"], method);
        assert_eq!(response["error"]["code"], code);
    }
    drop(peer);
    session.await.unwrap().unwrap();
}

#[tokio::test]
async fn completing_an_rpc_preserves_the_next_fragmented_request() {
    use flclash_meow_host::{serve, Host};
    use serde_json::{json, Value};
    use std::{sync::Arc, time::Duration};

    for split in [1, 9] {
        let (mut peer, stream) = tokio::io::duplex(4096);
        let session = tokio::spawn(serve(Arc::new(Host::new()), stream));
        let first = json!({"id":"first","method":"getCoreInfo"}).to_string();
        let second = json!({"id":"second","method":"getCoreInfo"}).to_string();
        let mut next = (second.len() as u32).to_le_bytes().to_vec();
        next.extend_from_slice(second.as_bytes());
        let mut input = (first.len() as u32).to_le_bytes().to_vec();
        input.extend_from_slice(first.as_bytes());
        input.extend_from_slice(&next[..split]);
        peer.write_all(&input).await.unwrap();
        let response: Value =
            serde_json::from_slice(&read_frame(&mut peer).await.unwrap().unwrap()).unwrap();
        assert_eq!(response["id"], "first");
        assert_eq!(response["result"]["protocolVersion"], 1);
        tokio::task::yield_now().await;
        peer.write_all(&next[split..]).await.unwrap();
        let response = tokio::time::timeout(Duration::from_secs(2), read_frame(&mut peer)).await.unwrap().unwrap().expect("Completing the first RPC must not discard the next request's partial header or payload");
        let response: Value = serde_json::from_slice(&response).unwrap();
        assert_eq!(response["id"], "second");
        assert_eq!(response["result"]["protocolVersion"], 1);
        drop(peer);
        session.await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn fragmented_requests_and_single_encoded_results_round_trip() {
    let (mut peer, mut host) = tokio::io::duplex(32);
    let send = tokio::spawn(async move {
        for byte in b"\x1f\0\0\0{\"id\":\"1\",\"method\":\"getIsInit\"}" {
            peer.write_all(&[*byte]).await.unwrap();
        }
        let response = read_frame(&mut peer).await.unwrap().unwrap();
        serde_json::from_slice::<serde_json::Value>(&response).unwrap()
    });
    let request = read_frame(&mut host).await.unwrap().unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&request).unwrap()["method"],
        "getIsInit"
    );
    write_frame(&mut host, br#"{"id":"1","result":{"initialized":false}}"#)
        .await
        .unwrap();
    assert_eq!(send.await.unwrap()["result"]["initialized"], false);
}

#[tokio::test]
async fn oversize_and_truncated_frames_fail_instead_of_allocating_or_accepting() {
    let (mut peer, mut host) = tokio::io::duplex(16);
    peer.write_all(&((MAX_FRAME_SIZE + 1) as u32).to_le_bytes())
        .await
        .unwrap();
    assert_eq!(
        read_frame(&mut host).await.unwrap_err().kind(),
        std::io::ErrorKind::InvalidData
    );
    let (mut peer, mut host) = tokio::io::duplex(16);
    peer.write_all(b"\x04\0\0\0{}").await.unwrap();
    drop(peer);
    assert_eq!(
        read_frame(&mut host).await.unwrap_err().kind(),
        std::io::ErrorKind::UnexpectedEof
    );
}

#[tokio::test]
async fn session_shutdown_flushes_correlated_acknowledgement_before_eof() {
    use flclash_meow_host::{serve, Host};
    use serde_json::{json, Value};
    use std::sync::Arc;

    let (mut peer, stream) = tokio::io::duplex(32);
    let host = Arc::new(Host::new());
    let session = tokio::spawn(serve(Arc::clone(&host), stream));
    write_frame(&mut peer, br#"{"id":"metadata","method":"getCoreInfo"}"#)
        .await
        .unwrap();
    let metadata: Value =
        serde_json::from_slice(&read_frame(&mut peer).await.unwrap().unwrap()).unwrap();
    assert_eq!(metadata["id"], "metadata");
    assert_eq!(metadata["result"]["protocolVersion"], 1);
    write_frame(&mut peer, br#"{"id":"stop","method":"shutdown"}"#)
        .await
        .unwrap();
    let acknowledgement: Value =
        serde_json::from_slice(&read_frame(&mut peer).await.unwrap().unwrap()).unwrap();
    assert_eq!(acknowledgement, json!({"id":"stop","result":true}));
    assert!(read_frame(&mut peer).await.unwrap().is_none());
    session.await.unwrap().unwrap();
}

#[tokio::test]
async fn external_shutdown_finishes_the_owned_session() {
    use flclash_meow_host::{serve_until, Host};
    use std::sync::Arc;
    let (mut peer, stream) = tokio::io::duplex(32);
    let host = Arc::new(Host::new());
    let (stop, cancellation) = tokio::sync::oneshot::channel();
    let session = tokio::spawn(serve_until(host, stream, async move {
        let _ = cancellation.await;
    }));
    write_frame(&mut peer, br#"{"id":"alive","method":"getCoreInfo"}"#)
        .await
        .unwrap();
    assert!(read_frame(&mut peer).await.unwrap().is_some());
    stop.send(()).unwrap();
    assert!(read_frame(&mut peer).await.unwrap().is_none());
    session.await.unwrap().unwrap();
}

#[tokio::test]
async fn external_shutdown_releases_a_session_when_the_peer_stops_reading() {
    use flclash_meow_host::{serve_until, Host};
    use std::{sync::Arc, time::Duration};
    let (mut peer, stream) = tokio::io::duplex(32);
    let (stop, cancellation) = tokio::sync::oneshot::channel();
    let session = tokio::spawn(serve_until(Arc::new(Host::new()), stream, async move {
        let _ = cancellation.await;
    }));
    for _ in 0..70 {
        tokio::time::timeout(Duration::from_secs(1), write_frame(&mut peer, b"{"))
            .await
            .unwrap()
            .unwrap();
    }
    stop.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(1), session)
        .await
        .expect("A stalled response queue must not prevent session shutdown")
        .unwrap()
        .unwrap();
}
