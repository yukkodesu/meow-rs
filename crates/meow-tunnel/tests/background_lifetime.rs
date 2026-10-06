use meow_common::DnsMode;
use meow_dns::Resolver;
use meow_trie::DomainTrie;
use meow_tunnel::Tunnel;
use std::{sync::Arc, time::Duration};

#[tokio::test]
async fn background_cleanup_can_finish_while_configured_tunnel_is_retained() {
    let tunnel = Tunnel::new(Arc::new(Resolver::new(
        vec![],
        vec![],
        DnsMode::Normal,
        DomainTrie::new(),
        false,
        true,
    )));
    for _ in 0..3 {
        let task = tunnel.spawn_background_tasks();
        tokio::task::yield_now().await;
        assert!(!task.is_finished());
        task.abort();
        assert!(tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap_err()
            .is_cancelled());
        assert!(!tunnel.has_tun());
    }
}
