mod config;
mod ipc;
mod operations;
pub mod protocol;
mod runtime;
pub use ipc::serve;

use meow_api::log_stream::LogMessage;
use protocol::{Request, Response, RpcError};
use runtime::Runtime;
use serde_json::{json, Value};
use std::{
    collections::VecDeque,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use tokio::sync::{broadcast, watch, Mutex, Semaphore};

#[derive(Default)]
struct State {
    home: Option<PathBuf>,
    runtime: Option<Runtime>,
    closed: bool,
    generation: u64,
    traffic_baseline: (i64, i64),
}

pub struct Host {
    state: Mutex<State>,
    wanted: AtomicBool,
    generation: watch::Sender<u64>,
    log_tx: broadcast::Sender<LogMessage>,
    logs: Arc<parking_lot::Mutex<VecDeque<Value>>>,
    log_subscribed: AtomicBool,
    events: broadcast::Sender<Value>,
    bulk: broadcast::Sender<Value>,
    probes: Arc<Semaphore>,
}

impl Default for Host {
    fn default() -> Self {
        Self::new()
    }
}

impl Host {
    pub fn new() -> Self {
        meow_config::proxy_parser::install_proxy_config_validator(config::validate_provider_node);
        let (generation, _) = watch::channel(0);
        let (log_tx, mut receiver) = broadcast::channel::<LogMessage>(256);
        let (events, _) = broadcast::channel(64);
        let (bulk, _) = broadcast::channel(256);
        let logs = Arc::new(parking_lot::Mutex::new(VecDeque::with_capacity(256)));
        let history = Arc::clone(&logs);
        tokio::spawn(async move {
            loop {
                match receiver.recv().await {
                    Ok(log) => {
                        let value = log_value(&log);
                        let mut logs = history.lock();
                        if logs.len() == 256 {
                            logs.pop_front();
                        }
                        logs.push_back(value);
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });
        Self {
            state: Mutex::new(State::default()),
            wanted: AtomicBool::new(false),
            generation,
            log_tx,
            logs,
            log_subscribed: AtomicBool::new(false),
            events,
            bulk,
            probes: Arc::new(Semaphore::new(4)),
        }
    }

    pub fn log_sender(&self) -> broadcast::Sender<LogMessage> {
        self.log_tx.clone()
    }
    pub fn subscribe_events(&self) -> broadcast::Receiver<Value> {
        self.events.subscribe()
    }
    pub fn subscribe_bulk(&self) -> broadcast::Receiver<Value> {
        self.bulk.subscribe()
    }

    pub async fn call(&self, request: Request) -> Response {
        match request.method.as_str() {
            "startListener" => self.wanted.store(true, Ordering::Release),
            "stopListener" | "shutdown" => {
                self.wanted.store(false, Ordering::Release);
                self.generation.send_modify(|g| *g += 1);
            }
            _ => {}
        }
        let outcome = self.dispatch(&request.method, request.arguments).await;
        match outcome {
            Ok(result) => Response {
                id: request.id,
                result,
                error: None,
            },
            Err(error) => Response {
                id: request.id,
                result: Value::Null,
                error: Some(error),
            },
        }
    }

    async fn dispatch(&self, method: &str, arguments: Value) -> Result<Value, RpcError> {
        if matches!(method, "checkConfig" | "validateConfig") {
            return self.check(method, &arguments).await;
        }
        if matches!(
            method,
            "getProxies"
                | "changeProxy"
                | "unfixProxy"
                | "asyncTestDelay"
                | "getExternalProviders"
                | "getExternalProvider"
                | "updateExternalProvider"
                | "getConnections"
                | "closeConnection"
                | "closeConnections"
                | "resetConnections"
                | "getDnsCache"
        ) {
            return self.runtime_call(method, &arguments).await;
        }
        let mut state = self.state.lock().await;
        if state.closed {
            return Err(RpcError::new("closed", "The host session has closed"));
        }
        match method {
            "getCoreInfo" => Ok(
                json!({"name":"meow-rs","version":"0.22.0","hostVersion":env!("CARGO_PKG_VERSION"),"commit":env!("MEOW_HOST_COMMIT"),"protocolVersion":1,"capabilities":["config-check","proxy-groups","delay","providers","connections","traffic","logs","dns-cache","tun-fake-ip","tun-global-experimental","external-controller"],"statisticsScope":"all","connectionsScope":"tcp","tunModes":["fake-ip","global-experimental"]}),
            ),
            "getRuntimeState" => Ok(
                json!({"initialized":state.home.is_some(),"configured":state.runtime.is_some(),"running":state.runtime.as_ref().is_some_and(Runtime::running),"tunActive":state.runtime.as_ref().is_some_and(|r|r.state.tunnel.has_tun()),"generation":state.generation,"failure":state.runtime.as_ref().and_then(Runtime::failure)}),
            ),
            "getIsInit" => Ok(json!(state.home.is_some())),
            "initClash" => {
                let home = string_field(&arguments, "home-dir")?;
                let path = PathBuf::from(home);
                if !path.is_absolute() {
                    return Err(RpcError::new("invalid_path", "home-dir must be absolute"));
                }
                tokio::fs::create_dir_all(&path)
                    .await
                    .map_err(|e| RpcError::new("initialization_failed", e.to_string()))?;
                let path = path
                    .canonicalize()
                    .map_err(|e| RpcError::new("initialization_failed", e.to_string()))?;
                if state.home.as_ref().is_some_and(|old| *old != path) {
                    return Err(RpcError::new(
                        "already_initialized",
                        "A session cannot switch home directories",
                    ));
                }
                meow_config::set_external_plugins_allowed(false);
                meow_common::set_home_dir(path.clone());
                state.home = Some(path);
                Ok(json!(true))
            }
            "setupConfig" => {
                let home = state.home.as_ref().ok_or_else(|| {
                    RpcError::new(
                        "not_initialized",
                        "Initialize the host before applying a profile",
                    )
                })?;
                let path = config::contained_path(home, "config.yaml")?;
                let content = tokio::fs::read_to_string(&path)
                    .await
                    .map_err(|e| RpcError::new("config_read_failed", e.to_string()))?;
                self.apply(&mut state, &content, &arguments).await?;
                Ok(json!(""))
            }
            "updateConfig" => {
                let runtime = state
                    .runtime
                    .as_ref()
                    .ok_or_else(|| RpcError::new("not_configured", "No profile is configured"))?;
                let mut document = serde_json::to_value(&*runtime.state.raw_config.read())
                    .map_err(|e| RpcError::new("invalid_config", e.to_string()))?;
                let updates = arguments.as_object().ok_or_else(|| {
                    RpcError::new("invalid_arguments", "Expected configuration fields")
                })?;
                if updates
                    .keys()
                    .all(|k| matches!(k.as_str(), "mode" | "log-level"))
                {
                    let router = runtime.router.clone();
                    drop(state);
                    Runtime::request(router, "PATCH", "/configs".into(), arguments).await?;
                } else {
                    for (key, value) in updates {
                        document[key] = value.clone();
                    }
                    let yaml = serde_yaml::to_string(&document)
                        .map_err(|e| RpcError::new("invalid_config", e.to_string()))?;
                    self.apply(&mut state, &yaml, &Value::Null).await?;
                }
                Ok(json!(""))
            }
            "startListener" => {
                let runtime = state.runtime.as_mut().ok_or_else(|| {
                    RpcError::new(
                        "not_configured",
                        "Select and apply a valid profile before starting the proxy",
                    )
                })?;
                if self.wanted.load(Ordering::Acquire) {
                    runtime.start().await?;
                }
                if !self.wanted.load(Ordering::Acquire) {
                    runtime.stop().await;
                    return Err(RpcError::new(
                        "request_superseded",
                        "A later stop superseded startup",
                    ));
                }
                Ok(json!(runtime.running()))
            }
            "stopListener" => {
                if let Some(runtime) = state.runtime.as_mut() {
                    runtime.stop().await;
                }
                Ok(json!(true))
            }
            "getTraffic" | "getTotalTraffic" => {
                if arguments.as_bool() == Some(true) {
                    return Err(RpcError::new(
                        "unsupported_statistic",
                        "Only total inbound traffic is available",
                    ));
                }
                let Some(runtime) = state.runtime.as_ref() else {
                    return Err(RpcError::new("not_configured", "No profile is configured"));
                };
                let statistics = runtime.state.tunnel.statistics();
                let (up, down) = if method == "getTotalTraffic" {
                    let (up, down) = statistics.snapshot();
                    (
                        up.saturating_sub(state.traffic_baseline.0),
                        down.saturating_sub(state.traffic_baseline.1),
                    )
                } else {
                    statistics.sample_traffic();
                    let (up, down, _, _) = statistics.traffic_snapshot();
                    (up, down)
                };
                Ok(json!({"up":up,"down":down}))
            }
            "resetTraffic" => {
                state.traffic_baseline = state
                    .runtime
                    .as_ref()
                    .map_or((0, 0), |r| r.state.tunnel.statistics().snapshot());
                Ok(Value::Null)
            }
            "startLogNotify" => {
                self.log_subscribed.store(true, Ordering::Release);
                Ok(json!(self.logs.lock().iter().collect::<Vec<_>>()))
            }
            "stopLogNotify" => {
                self.log_subscribed.store(false, Ordering::Release);
                Ok(json!(true))
            }
            "getProfileConfig" => {
                let id = arguments
                    .as_i64()
                    .ok_or_else(|| RpcError::new("invalid_arguments", "Expected a profile ID"))?;
                let home = state
                    .home
                    .as_ref()
                    .ok_or_else(|| RpcError::new("not_initialized", "Host is not initialized"))?;
                let path = config::contained_path(home, &format!("profiles/{id}.yaml"))?;
                let text = tokio::fs::read_to_string(path)
                    .await
                    .map_err(|e| RpcError::new("config_read_failed", e.to_string()))?;
                serde_yaml::from_str(&text)
                    .map_err(|e| RpcError::new("invalid_config", e.to_string()))
            }
            "shutdown" => {
                self.shutdown_locked(&mut state).await;
                Ok(json!(true))
            }
            _ => Err(RpcError::new(
                "unsupported_method",
                format!("This host does not support {method}"),
            )),
        }
    }

    async fn check(&self, method: &str, arguments: &Value) -> Result<Value, RpcError> {
        let state = self.state.lock().await;
        if state.closed {
            return Err(RpcError::new("closed", "The host session has closed"));
        }
        let home = state.home.clone();
        drop(state);
        let content = arguments
            .as_str()
            .ok_or_else(|| RpcError::new("invalid_arguments", "Expected a YAML string"))?;
        let (raw, mut check) = config::parse(content, home.as_deref())?;
        if check.valid {
            let result = tokio::task::spawn_blocking(move || {
                meow_config::rebuild_from_raw_with_cache_dir(&raw, home.as_deref(), None)
            })
            .await
            .map_err(|e| RpcError::new("validation_failed", e.to_string()))?;
            if let Err(e) = result {
                check.valid = false;
                check.diagnostics.push(config::Diagnostic {
                    severity: "error",
                    path: "$".into(),
                    reason: e.to_string(),
                    suggestion: "Correct the indicated proxy, group, provider, or rule.",
                });
            }
        }
        if method == "validateConfig" {
            return Ok(json!(check
                .diagnostics
                .iter()
                .filter(|d| d.severity == "error")
                .map(|d| format!("{}: {}", d.path, d.reason))
                .collect::<Vec<_>>()
                .join("\n")));
        }
        serde_json::to_value(check).map_err(|e| RpcError::new("invalid_response", e.to_string()))
    }

    async fn apply(
        &self,
        state: &mut State,
        content: &str,
        selections: &Value,
    ) -> Result<(), RpcError> {
        let home = state
            .home
            .as_ref()
            .ok_or_else(|| RpcError::new("not_initialized", "Host is not initialized"))?;
        let (raw, check) = config::parse(content, Some(home))?;
        ensure_valid(check)?;
        let config = meow_config::build_config(raw, Some(home))
            .await
            .map_err(|e| RpcError::new("invalid_config", e.to_string()))?;
        let mut candidate = Runtime::prepare(config, self.log_tx.clone());
        if let Some(selections) = selections.get("selected-map").and_then(Value::as_object) {
            for (group, node) in selections {
                if let (Some(proxy), Some(node)) =
                    (candidate.state.tunnel.proxy(group), node.as_str())
                {
                    if let Some(selection) = proxy.selection() {
                        if let Err(e) = selection.set(node).await {
                            tracing::warn!("Saved selection {group}/{node} ignored: {e}");
                        }
                    }
                }
            }
        }
        let mut previous = state.runtime.take();
        if let Some(old) = previous.as_mut() {
            old.stop().await;
        }
        if self.wanted.load(Ordering::Acquire) {
            if let Err(error) = candidate.start().await {
                candidate.stop().await;
                let rollback = if self.wanted.load(Ordering::Acquire) {
                    if let Some(old) = previous.as_mut() {
                        old.start().await.map(|()| true)
                    } else {
                        Ok(false)
                    }
                } else {
                    Ok(false)
                };
                state.runtime = previous;
                let mut error = RpcError::new("config_apply_failed", error.message);
                error.details = json!({"restored":matches!(rollback,Ok(true)),"rollbackError":rollback.err().map(|e|e.message)});
                return Err(error);
            }
        }
        if !self.wanted.load(Ordering::Acquire) {
            candidate.stop().await;
        }
        state.runtime = Some(candidate);
        state.generation += 1;
        state.traffic_baseline = (0, 0);
        self.generation.send_modify(|g| *g += 1);
        self.emit("loaded", json!(""));
        Ok(())
    }

    fn emit(&self, kind: &str, data: Value) {
        let _ = self.events.send(json!({"type":kind,"data":data}));
    }
    fn emit_bulk(&self, kind: &str, data: Value) {
        let _ = self.bulk.send(json!({"type":kind,"data":data}));
    }
    pub fn forward_log(&self, log: &LogMessage) {
        if self.log_subscribed.load(Ordering::Acquire) {
            self.emit_bulk("log", log_value(log));
        }
    }
    async fn shutdown_locked(&self, state: &mut State) {
        self.wanted.store(false, Ordering::Release);
        self.generation.send_modify(|g| *g += 1);
        if let Some(runtime) = state.runtime.as_mut() {
            runtime.stop().await;
        }
        state.runtime = None;
        state.closed = true;
    }
    pub async fn shutdown(&self) {
        let mut state = self.state.lock().await;
        self.shutdown_locked(&mut state).await;
    }
}

fn string_field<'a>(arguments: &'a Value, key: &str) -> Result<&'a str, RpcError> {
    arguments
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::new("invalid_arguments", format!("{key} is required")))
}
fn encode(value: &str) -> String {
    percent_encoding::utf8_percent_encode(value, percent_encoding::NON_ALPHANUMERIC).to_string()
}
fn ensure_valid(check: config::CheckResult) -> Result<(), RpcError> {
    if check.valid {
        Ok(())
    } else {
        Err(RpcError {
            code: "invalid_config".into(),
            message: "Configuration contains unsupported fields or behavior".into(),
            details: json!(check),
        })
    }
}
fn log_value(log: &LogMessage) -> Value {
    json!({"LogLevel":log.level.as_str(),"Payload":log.payload,"dateTime":log.time.to_string(),"source":"core"})
}
