use super::Runtime;
use crate::protocol::RpcError;
use serde_json::Value;
use std::sync::Arc;

impl Runtime {
    pub(crate) async fn update_tun(
        &mut self,
        patch: &Value,
        mut intent: tokio::sync::watch::Receiver<u64>,
    ) -> Result<(), RpcError> {
        let updates = patch.as_object().ok_or_else(|| {
            RpcError::new("invalid_arguments", "Expected TUN configuration fields")
        })?;
        let mut raw = self.config.raw.clone();
        let mut tun = serde_json::to_value(&raw.tun)
            .map_err(|error| RpcError::new("invalid_config", error.to_string()))?;
        if tun.is_null() {
            tun = serde_json::json!({});
        }
        tun.as_object_mut()
            .expect("TUN configuration object")
            .extend(updates.clone());
        raw.tun = Some(
            serde_json::from_value(tun)
                .map_err(|error| RpcError::new("invalid_config", error.to_string()))?,
        );
        let next = meow_config::parse_tun_config(raw.tun.as_ref(), raw.max_connections)
            .map_err(|error| RpcError::new("invalid_config", error.to_string()))?;
        if next != self.config.tun {
            let previous = self.config.tun.clone();
            let previous_failure = self.failure.read().clone();
            let binding = meow_api::preinstall_global_route_binding(&raw);
            let interface_changed = binding.interface_changed();
            self.binding = Some(binding);
            self.stop_tun().await.map_err(|error| {
                RpcError::new("resources_release_unconfirmed", error.to_string())
            })?;
            self.config.tun = next;
            if previous_failure
                .as_deref()
                .is_some_and(|failure| failure.starts_with("TUN failed:"))
            {
                *self.failure.write() = None;
            }
            if self.running {
                if let Err(error) = self.start_tun_current(&mut intent).await {
                    self.stop_tun().await.map_err(|error| {
                        RpcError::new("resources_release_unconfirmed", error.to_string())
                    })?;
                    self.config.tun = previous;
                    self.binding =
                        Some(meow_api::preinstall_global_route_binding(&self.config.raw));
                    *self.failure.write() = previous_failure;
                    if error.code != "request_superseded" {
                        self.start_tun_current(&mut intent).await?;
                    }
                    return Err(error);
                }
                if interface_changed {
                    let provider_members = self
                        .state
                        .proxy_providers
                        .iter()
                        .flat_map(|entry| entry.value().proxies())
                        .collect::<Vec<_>>();
                    self.state.tunnel.flush_for_outbound_interface_change(
                        meow_tunnel::TrackedTcp::Cancel,
                        provider_members,
                    );
                }
            }
        }
        self.config.raw.tun = raw.tun.clone();
        self.state.raw_config.write().tun = raw.tun;
        Ok(())
    }

    async fn start_tun_current(
        &mut self,
        intent: &mut tokio::sync::watch::Receiver<u64>,
    ) -> Result<(), RpcError> {
        let superseded = || {
            RpcError::new(
                "request_superseded",
                "A later runtime intent superseded TUN startup",
            )
        };
        if intent.has_changed().unwrap_or(true) {
            return Err(superseded());
        }
        tokio::select! {
            biased;
            _=intent.changed()=>Err(superseded()),
            result=self.start_tun()=>result,
        }
    }

    pub(super) async fn start_tun(&mut self) -> Result<(), RpcError> {
        if self.config.tun.enable {
            let binding = self
                .binding
                .take()
                .unwrap_or_else(|| meow_api::preinstall_global_route_binding(&self.config.raw));
            let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
            let recovery_directory = crate::native::recovery_directory().map_err(|error| {
                RpcError::new("tun_failed", format!("TUN recovery directory: {error}"))
            })?;
            let mut listener = meow_listener::TunListener::new(
                self.state.tunnel.clone(),
                meow_api::tun_config_to_listener_config(&self.config.tun),
                "FlClashMeowTun".into(),
            )
            .with_readiness_signal(ready_tx)
            .with_recovery_directory(recovery_directory);
            if let Some(binding) = binding.into_binding() {
                listener = listener.with_outbound_binding(binding);
            }
            let failure = Arc::clone(&self.failure);
            self.pending_tun = Some(tokio::spawn(async move {
                if let Err(e) = listener.run().await {
                    *failure.write() = Some(format!("TUN failed: {e}"));
                    tracing::error!("TUN failed: {e}");
                }
            }));
            match tokio::time::timeout(meow_api::TUN_STARTUP_TIMEOUT, ready_rx).await {
                Ok(Ok(meow_listener::TunReady::Ready {
                    core_done,
                    udp_flows,
                })) => {
                    self.state
                        .tunnel
                        .set_tun_handle(meow_tunnel::TunHandle {
                            task: self.pending_tun.take().expect("owned pending TUN task"),
                            core_done: Some(core_done),
                            udp_flows,
                        })
                        .await
                        .map_err(|error| {
                            RpcError::new("resources_release_unconfirmed", error.to_string())
                        })?;
                }
                result => {
                    let reason = match result {
                        Ok(Ok(meow_listener::TunReady::Failed(reason))) => reason,
                        _ => "TUN readiness failed or timed out".into(),
                    };
                    return Err(RpcError::new("tun_failed", reason));
                }
            }
        }
        Ok(())
    }

    pub(super) async fn stop_tun(&mut self) -> std::io::Result<()> {
        if let Some(task) = self.pending_tun.as_mut() {
            task.abort();
            if let Err(error) = task.await {
                if !error.is_cancelled() {
                    self.state
                        .tunnel
                        .report_tun_cleanup_failure(error.to_string());
                }
            }
        }
        self.pending_tun = None;
        let mut cleanup = self.state.tunnel.stop_tun().await;
        if let Err(error) = meow_listener::tun::await_tun_core_teardown().await {
            self.state
                .tunnel
                .report_tun_cleanup_failure(error.to_string());
            cleanup = Err(error);
        }
        cleanup
    }
}
