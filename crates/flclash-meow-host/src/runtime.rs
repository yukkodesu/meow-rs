use crate::protocol::RpcError;
use axum::{
    body::{to_bytes, Body},
    http::Request,
    Router,
};
use dashmap::DashMap;
use meow_api::{
    log_stream::LogMessage,
    routes::{AppState, DnsServerHandle},
};
use meow_config::{Config, ListenerSpec, NamedListener};
use meow_listener::SnifferRuntime;
use meow_tunnel::Tunnel;
use parking_lot::RwLock;
use serde_json::{json, Value};
use std::{net::SocketAddr, sync::Arc};
use tokio::{net::TcpListener, sync::broadcast, task::JoinSet};
use tower::ServiceExt;

#[path = "background.rs"]
mod background;

pub struct Runtime {
    pub state: Arc<AppState>,
    pub router: Router,
    config: Config,
    tasks: JoinSet<()>,
    running: bool,
    failure: Arc<RwLock<Option<String>>>,
    binding: Option<meow_api::PreinstalledBinding>,
    background: background::Background,
}

impl Runtime {
    pub fn prepare(
        mut config: Config,
        log_tx: broadcast::Sender<LogMessage>,
        binding: Option<meow_api::PreinstalledBinding>,
        home: std::path::PathBuf,
    ) -> Self {
        let tunnel = Tunnel::new_with_slot(Arc::clone(&config.dns.resolver_slot));
        tunnel.set_dialer_registry(config.provider_dialer_registry.clone());
        tunnel.set_mode(config.general.mode);
        tunnel.update_routing(
            std::mem::take(&mut config.proxies),
            std::mem::take(&mut config.rules),
            config.dialer_registry.clone(),
        );
        let providers = DashMap::new();
        for (name, provider) in std::mem::take(&mut config.proxy_providers) {
            providers.insert(name, provider);
        }
        let state = Arc::new(AppState {
            tunnel,
            secret: None,
            config_path: None,
            raw_config: Arc::new(RwLock::new(config.raw.clone())),
            log_tx,
            proxy_providers: Arc::new(providers),
            provider_dialer_registry: config.provider_dialer_registry.clone(),
            rule_providers: Arc::new(RwLock::new(std::mem::take(&mut config.rule_providers))),
            rule_provider_refresh: Arc::new(Default::default()),
            proxy_provider_refresh: Arc::new(Default::default()),
            listeners: config.listeners.named.clone(),
            external_ui: config.api.external_ui.clone(),
            traffic_feed: Default::default(),
            dns_server: Arc::new(RwLock::new(None)),
        });
        let router = meow_api::routes::create_router(Arc::clone(&state));
        Self {
            state,
            router,
            config,
            tasks: JoinSet::new(),
            running: false,
            failure: Arc::new(RwLock::new(None)),
            binding,
            background: background::Background::new(home),
        }
    }

    pub fn running(&self) -> bool {
        self.running
            && self.failure.read().is_none()
            && (!self.config.tun.enable || self.state.tunnel.has_tun())
    }

    pub fn failure(&self) -> Option<String> {
        self.failure.read().clone()
    }

    pub async fn start(&mut self) -> Result<(), RpcError> {
        if self.running() {
            return Ok(());
        }
        self.stop().await;
        let outcome = self.start_inner().await;
        if outcome.is_err() {
            self.stop().await;
        }
        outcome
    }

    async fn start_inner(&mut self) -> Result<(), RpcError> {
        let mut bound = Vec::new();
        for listener in &self.config.listeners.named {
            if !matches!(
                listener.spec,
                ListenerSpec::Mixed | ListenerSpec::Http | ListenerSpec::Socks5
            ) {
                return Err(RpcError::new(
                    "unsupported_listener",
                    format!(
                        "Listener {} is unavailable in this desktop host",
                        listener.name
                    ),
                ));
            }
            let address = listener_address(listener)?;
            let socket = TcpListener::bind(address)
                .await
                .map_err(|e| RpcError::new("listener_failed", format!("{}: {e}", listener.name)))?;
            let address = socket
                .local_addr()
                .map_err(|e| RpcError::new("listener_failed", e.to_string()))?;
            self.background.listeners.push(json!({"name":listener.name,"type":match listener.spec {ListenerSpec::Mixed=>"mixed",ListenerSpec::Http=>"http",_=>"socks5"},"address":address.to_string()}));
            bound.push((listener.clone(), socket));
        }
        let dns = if let Some(address) = self.config.dns.listen_addr {
            let server = meow_dns::DnsServer::new(Arc::clone(&self.config.dns.resolver), address);
            let bound = server
                .bind()
                .await
                .map_err(|e| RpcError::new("listener_failed", format!("dns.listen: {e}")))?;
            let address = bound
                .local_addr()
                .map_err(|e| RpcError::new("listener_failed", e.to_string()))?;
            self.background.dns = Some(address.to_string());
            Some((server, bound, address))
        } else {
            None
        };
        let api = if let Some(address) = self.config.api.external_controller {
            let socket = TcpListener::bind(address).await.map_err(|e| {
                RpcError::new("listener_failed", format!("external-controller: {e}"))
            })?;
            self.background.controller = Some(
                socket
                    .local_addr()
                    .map_err(|e| RpcError::new("listener_failed", e.to_string()))?
                    .to_string(),
            );
            Some(socket)
        } else {
            None
        };
        if self.config.dns.enabled {
            meow_common::set_host_resolver(Arc::new(
                meow_dns::ResolverHostHook::new_with_proxy_resolver(
                    Arc::clone(&self.config.dns.resolver),
                    self.config.dns.proxy_resolver.clone(),
                ),
            ));
        }
        if self.config.tun.enable {
            let binding = self
                .binding
                .take()
                .unwrap_or_else(|| meow_api::preinstall_global_route_binding(&self.config.raw));
            let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
            let mut listener = meow_listener::TunListener::new(
                self.state.tunnel.clone(),
                meow_api::tun_config_to_listener_config(&self.config.tun),
                "FlClashMeowTun".into(),
            )
            .with_readiness_signal(ready_tx);
            if let Some(binding) = binding.into_binding() {
                listener = listener.with_outbound_binding(binding);
            }
            let task = tokio::spawn(async move {
                if let Err(e) = listener.run().await {
                    tracing::error!("TUN failed: {e}");
                }
            });
            match tokio::time::timeout(meow_api::TUN_STARTUP_TIMEOUT, ready_rx).await {
                Ok(Ok(meow_listener::TunReady::Ready {
                    core_done,
                    udp_flows,
                })) => {
                    self.state
                        .tunnel
                        .set_tun_handle(meow_tunnel::TunHandle {
                            task,
                            core_done: Some(core_done),
                            udp_flows,
                        })
                        .await;
                }
                result => {
                    task.abort();
                    let _ = task.await;
                    let reason = match result {
                        Ok(Ok(meow_listener::TunReady::Failed(reason))) => reason,
                        _ => "TUN readiness failed or timed out".into(),
                    };
                    return Err(RpcError::new("tun_failed", reason));
                }
            }
        }
        let sniffer = Arc::new(SnifferRuntime::new(self.config.sniffer.clone()));
        for (listener, socket) in bound {
            let tunnel = self.state.tunnel.clone();
            let sniffer = Arc::clone(&sniffer);
            let auth = Arc::clone(&self.config.auth);
            let failure = Arc::clone(&self.failure);
            self.tasks.spawn(async move {
                if let Err(e) = serve_listener(socket, listener, tunnel, sniffer, auth).await {
                    *failure.write() = Some(e.to_string());
                }
            });
        }
        if let Some((server, bound, address)) = dns {
            let failure = Arc::clone(&self.failure);
            let task = tokio::spawn(async move {
                if let Err(e) = bound.run().await {
                    *failure.write() = Some(e.to_string());
                }
            });
            *self.state.dns_server.write() = Some(DnsServerHandle {
                listen: address,
                task,
                resolver_slot: server.resolver_slot(),
            });
        }
        if let Some(socket) = api {
            let state = Arc::new(AppState {
                tunnel: self.state.tunnel.clone(),
                secret: self.config.api.secret.clone(),
                config_path: None,
                raw_config: Arc::clone(&self.state.raw_config),
                log_tx: self.state.log_tx.clone(),
                proxy_providers: Arc::clone(&self.state.proxy_providers),
                provider_dialer_registry: self.state.provider_dialer_registry.clone(),
                rule_providers: Arc::clone(&self.state.rule_providers),
                rule_provider_refresh: Arc::clone(&self.state.rule_provider_refresh),
                proxy_provider_refresh: Arc::clone(&self.state.proxy_provider_refresh),
                listeners: self.state.listeners.clone(),
                external_ui: self.state.external_ui.clone(),
                traffic_feed: Default::default(),
                dns_server: Arc::clone(&self.state.dns_server),
            });
            let app = meow_api::routes::create_router(state)
                .layer(axum::middleware::from_fn(restrict_mutations));
            let failure = Arc::clone(&self.failure);
            self.tasks.spawn(async move {
                if let Err(e) = axum::serve(socket, app).await {
                    *failure.write() = Some(e.to_string());
                }
            });
        }
        self.state
            .rule_provider_refresh
            .reconcile(&self.state.rule_providers);
        self.state.proxy_provider_refresh.reconcile(
            &self.state.proxy_providers,
            self.config.raw.proxy_providers.as_ref(),
        );
        self.state
            .tunnel
            .reconcile_health_checks(&meow_config::extract_health_check_specs(
                self.config.raw.proxy_groups.as_deref().unwrap_or(&[]),
            ));
        self.state.tunnel.spawn_background_tasks();
        self.start_background_tasks();
        self.running = true;
        Ok(())
    }

    pub async fn stop(&mut self) {
        self.running = false;
        self.background.clear();
        self.tasks.abort_all();
        while self.tasks.join_next().await.is_some() {}
        let dns = self.state.dns_server.write().take();
        if let Some(dns) = dns {
            dns.task.abort();
            let _ = dns.task.await;
        }
        self.state.tunnel.stop_tun().await;
        self.state.tunnel.statistics().close_all_connections();
        self.state.tunnel.close_all_udp_sessions();
        self.state.tunnel.reconcile_health_checks(&[]);
        self.state
            .rule_provider_refresh
            .reconcile(&Arc::new(RwLock::new(Default::default())));
        self.state
            .proxy_provider_refresh
            .reconcile(&Arc::new(DashMap::new()), None);
        meow_common::clear_host_resolver();
        *self.failure.write() = None;
    }

    pub async fn request(
        router: Router,
        method: &str,
        path: String,
        body: Value,
    ) -> Result<Value, RpcError> {
        let request = Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json")
            .body(if body.is_null() {
                Body::empty()
            } else {
                Body::from(body.to_string())
            })
            .map_err(|e| RpcError::new("invalid_arguments", e.to_string()))?;
        let response = router
            .oneshot(request)
            .await
            .map_err(|e| RpcError::new("runtime_error", e.to_string()))?;
        let status = response.status();
        let bytes = to_bytes(response.into_body(), crate::protocol::MAX_FRAME_SIZE)
            .await
            .map_err(|e| RpcError::new("invalid_response", e.to_string()))?;
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes)
                .map_err(|e| RpcError::new("invalid_response", e.to_string()))?
        };
        if !status.is_success() {
            let code = if status == axum::http::StatusCode::GATEWAY_TIMEOUT {
                "probe_timeout"
            } else if status == axum::http::StatusCode::NOT_FOUND {
                "not_found"
            } else {
                "runtime_error"
            };
            return Err(RpcError {
                code: code.into(),
                message: value
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or(status.as_str())
                    .into(),
                details: json!({"status":status.as_u16()}),
            });
        }
        Ok(value)
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        self.tasks.abort_all();
        if let Some(dns) = self.state.dns_server.write().take() {
            dns.task.abort();
        }
        self.state.tunnel.statistics().close_all_connections();
        self.state.tunnel.close_all_udp_sessions();
    }
}

fn listener_address(listener: &NamedListener) -> Result<SocketAddr, RpcError> {
    if let Ok(address) = listener.listen.parse::<SocketAddr>() {
        return Ok(address);
    }
    let ip = listener.listen.parse().map_err(|_| {
        RpcError::new(
            "invalid_config",
            format!("Invalid listener address: {}", listener.listen),
        )
    })?;
    Ok(SocketAddr::new(ip, listener.port))
}

async fn serve_listener(
    socket: TcpListener,
    listener: NamedListener,
    tunnel: Tunnel,
    sniffer: Arc<SnifferRuntime>,
    auth: Arc<meow_common::AuthConfig>,
) -> std::io::Result<()> {
    let port = socket.local_addr()?.port();
    let mut clients = JoinSet::new();
    loop {
        tokio::select! {
            completed=clients.join_next(), if !clients.is_empty()=>{if let Some(Err(e))=completed {tracing::debug!("Inbound handler ended: {e}");}},
            accepted=socket.accept(), if listener.max_connections==0 || clients.len()<listener.max_connections=>{
                let (stream,source)=accepted?;
                let tunnel=tunnel.clone();let sniffer=Arc::clone(&sniffer);let auth=Arc::clone(&auth);let listener=listener.clone();
                clients.spawn(async move {
                    let mut peek=[0];
                    if !matches!(tokio::time::timeout(meow_listener::DEFAULT_HANDSHAKE_TIMEOUT,stream.peek(&mut peek)).await,Ok(Ok(1))) {return;}
                    let socks=peek[0]==5;
                    if matches!(listener.spec,ListenerSpec::Http) && socks || matches!(listener.spec,ListenerSpec::Socks5) && !socks {return;}
                    if socks {meow_listener::socks5::handle_socks5(&tunnel,stream,source,Some(&sniffer),Some(&auth),&listener.name,port).await;}
                    else {meow_listener::http_proxy::handle_http(&tunnel,stream,source,Some(&sniffer),Some(&auth),&listener.name,port).await;}
                });
            }
        }
    }
}

async fn restrict_mutations(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let path = request.uri().path();
    let method = request.method();
    if method != axum::http::Method::GET
        && !(path.starts_with("/proxies/")
            || path.starts_with("/providers/")
            || path.starts_with("/connections")
            || path == "/configs" && method == axum::http::Method::PATCH
            || path == "/dns/query"
            || path.starts_with("/cache/"))
    {
        return (axum::http::StatusCode::NOT_IMPLEMENTED,axum::Json(json!({"message":"Configuration changes are owned by FlClash-Meow and require a controlled restart"}))).into_response();
    }
    next.run(request).await
}
