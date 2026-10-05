use flclash_meow_host::protocol::{read_frame, write_frame, MAX_FRAME_SIZE};
use tokio::io::AsyncWriteExt;

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
