use meow_tunnel::{TunHandle, Tunnel};
use std::sync::{atomic::AtomicUsize, Arc};

#[tokio::test(start_paused = true)]
async fn canceled_stop_retains_the_generation_completion_signal() {
    let tunnel = Tunnel::new(Arc::new(meow_dns::Resolver::new(
        vec![],
        vec![],
        meow_common::DnsMode::Normal,
        meow_trie::DomainTrie::new(),
        false,
        true,
    )));
    let (done, receiver) = tokio::sync::watch::channel(false);
    tunnel
        .set_tun_handle(TunHandle {
            task: tokio::spawn(std::future::pending()),
            core_done: Some(receiver),
            udp_flows: Arc::new(AtomicUsize::new(0)),
        })
        .await
        .unwrap();
    let first = tokio::spawn({
        let tunnel = tunnel.clone();
        async move { tunnel.stop_tun().await }
    });
    tokio::task::yield_now().await;
    tokio::task::yield_now().await;
    first.abort();
    let _ = first.await;
    let second = tokio::spawn({
        let tunnel = tunnel.clone();
        async move { tunnel.stop_tun().await }
    });
    tokio::task::yield_now().await;
    assert!(
        !second.is_finished(),
        "Canceled cleanup lost its core completion signal"
    );
    done.send(true).unwrap();
    second.await.unwrap().unwrap();
}

#[tokio::test(start_paused = true)]
async fn unconfirmed_core_exit_blocks_successors() {
    let tunnel = Tunnel::new(Arc::new(meow_dns::Resolver::new(
        vec![],
        vec![],
        meow_common::DnsMode::Normal,
        meow_trie::DomainTrie::new(),
        false,
        true,
    )));
    let (_done, receiver) = tokio::sync::watch::channel(false);
    tunnel
        .set_tun_handle(TunHandle {
            task: tokio::spawn(std::future::pending()),
            core_done: Some(receiver),
            udp_flows: Arc::new(AtomicUsize::new(0)),
        })
        .await
        .unwrap();
    assert_eq!(
        tunnel.stop_tun().await.unwrap_err().kind(),
        std::io::ErrorKind::TimedOut,
    );
    let successor = tokio::spawn(std::future::pending());
    let abort = successor.abort_handle();
    assert!(tunnel
        .set_tun_handle(TunHandle {
            task: successor,
            core_done: None,
            udp_flows: Arc::new(AtomicUsize::new(0)),
        })
        .await
        .is_err());
    assert!(abort.is_finished());
    assert!(!tunnel.has_tun());
    assert!(tunnel.stop_tun().await.is_err());
}
