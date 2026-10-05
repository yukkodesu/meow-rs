use crate::{encode, string_field, Host, RpcError, Runtime};
use serde_json::{json, Value};
use std::sync::Arc;

impl Host {
    pub(crate) async fn runtime_call(
        &self,
        method: &str,
        arguments: &Value,
    ) -> Result<Value, RpcError> {
        let state = self.state.lock().await;
        if state.closed {
            return Err(RpcError::new("closed", "The host session has closed"));
        }
        if matches!(
            method,
            "changeProxy" | "unfixProxy" | "asyncTestDelay" | "updateExternalProvider"
        ) {
            if let Some(failure) = state.cleanup_failure.as_ref() {
                return Err(RpcError::new("resources_release_unconfirmed", failure));
            }
        }
        let runtime = state
            .runtime
            .as_ref()
            .ok_or_else(|| RpcError::new("not_configured", "No profile is configured"))?;
        let router = runtime.router.clone();
        let app = Arc::clone(&runtime.state);
        let mut generation = self.generation.subscribe();
        drop(state);
        let mut probe_permit = None;
        let (http, path, body) = match method {
            "getProxies" => ("GET", "/proxies".into(), Value::Null),
            "changeProxy" => (
                "PUT",
                format!(
                    "/proxies/{}",
                    encode(string_field(arguments, "group-name")?)
                ),
                json!({"name":string_field(arguments,"proxy-name")?}),
            ),
            "unfixProxy" => (
                "DELETE",
                format!(
                    "/proxies/{}",
                    encode(string_field(arguments, "group-name")?)
                ),
                Value::Null,
            ),
            "asyncTestDelay" => {
                probe_permit = Some(
                    Arc::clone(&self.probes)
                        .try_acquire_owned()
                        .map_err(|_| RpcError::new("busy", "Too many concurrent delay probes"))?,
                );
                let proxy = string_field(arguments, "proxy-name")?;
                let url = string_field(arguments, "test-url")?;
                let timeout = arguments
                    .get("timeout")
                    .and_then(Value::as_u64)
                    .unwrap_or(5000)
                    .clamp(1, 30000);
                let path = if app.tunnel.proxy(proxy).is_some() {
                    format!("/proxies/{}/delay", encode(proxy))
                } else {
                    let mut providers: Vec<_> = app
                        .proxy_providers
                        .iter()
                        .filter(|provider| provider.proxies().iter().any(|p| p.name() == proxy))
                        .map(|provider| provider.key().clone())
                        .collect();
                    providers.sort();
                    let provider = providers.first().ok_or_else(|| {
                        RpcError::new("not_found", format!("Proxy {proxy} does not exist"))
                    })?;
                    format!(
                        "/providers/proxies/{}/{}/healthcheck",
                        encode(provider),
                        encode(proxy)
                    )
                };
                (
                    "GET",
                    format!("{path}?url={}&timeout={timeout}", encode(url)),
                    Value::Null,
                )
            }
            "getExternalProviders" => ("GET", "/providers/proxies".into(), Value::Null),
            "getExternalProvider" | "updateExternalProvider" => {
                let name = arguments
                    .as_str()
                    .ok_or_else(|| RpcError::new("invalid_arguments", "Expected provider name"))?;
                let rule = app.rule_providers.read().contains_key(name);
                (
                    if method == "updateExternalProvider" {
                        "PUT"
                    } else {
                        "GET"
                    },
                    format!(
                        "/providers/{}/{}",
                        if rule { "rules" } else { "proxies" },
                        encode(name)
                    ),
                    Value::Null,
                )
            }
            "getConnections" => ("GET", "/connections".into(), Value::Null),
            "closeConnections" | "resetConnections" => {
                ("DELETE", "/connections".into(), Value::Null)
            }
            "closeConnection" => (
                "DELETE",
                format!(
                    "/connections/{}",
                    encode(arguments.as_str().ok_or_else(|| RpcError::new(
                        "invalid_arguments",
                        "Expected connection ID"
                    ))?)
                ),
                Value::Null,
            ),
            "getDnsCache" => ("GET", "/dns/results".into(), Value::Null),
            _ => return Err(RpcError::new("unsupported_method", method)),
        };
        let mut result = tokio::select! {result=Runtime::request(router.clone(),http,path,body)=>result?,_=generation.changed()=>return Err(RpcError::new("request_cancelled","The runtime changed while this operation was pending"))};
        drop(probe_permit);
        if generation.has_changed().unwrap_or(true) {
            return Err(RpcError::new(
                "request_cancelled",
                "The runtime changed while this operation was pending",
            ));
        }
        match method {
            "getProxies" => {
                let providers = tokio::select! {result=Runtime::request(
                    router.clone(),
                    "GET",
                    "/providers/proxies".into(),
                    Value::Null,
                )=>result?,_=generation.changed()=>return Err(cancelled())};
                if let Some(providers) = providers["providers"].as_object() {
                    let proxies = result["proxies"]
                        .as_object_mut()
                        .ok_or_else(|| RpcError::new("invalid_response", "Missing proxy map"))?;
                    for provider in providers.values() {
                        for node in provider["proxies"].as_array().into_iter().flatten() {
                            if let Some(name) = node["name"].as_str() {
                                proxies.entry(name).or_insert_with(|| node.clone());
                            }
                        }
                    }
                }
                let raw = app.raw_config.read();
                let mut all = vec!["DIRECT".to_string(), "REJECT".to_string()];
                for name in ["GLOBAL", "COMPATIBLE"] {
                    if result["proxies"].get(name).is_some() {
                        all.push(name.into());
                    }
                }
                for group in raw.proxy_groups.as_deref().unwrap_or(&[]) {
                    all.push(group.name.clone());
                }
                for proxy in raw.proxies.as_deref().unwrap_or(&[]) {
                    if let Some(name) = proxy.get("name").and_then(serde_yaml::Value::as_str) {
                        all.push(name.into());
                    }
                }
                result["all"] = json!(all);
            }
            "asyncTestDelay" => {
                result = json!({"name":string_field(arguments,"proxy-name")?,"value":result["delay"],"url":string_field(arguments,"test-url")?});
                self.emit_bulk("delay", &result);
            }
            "getExternalProviders" => {
                let mut providers: Vec<Value> = result["providers"]
                    .as_object()
                    .into_iter()
                    .flat_map(|p| p.values().cloned())
                    .collect();
                let rules = tokio::select! {result=Runtime::request(router,"GET","/providers/rules".into(),Value::Null)=>result?,_=generation.changed()=>return Err(cancelled())};
                providers.extend(
                    rules["providers"]
                        .as_object()
                        .into_iter()
                        .flat_map(|p| p.values().cloned()),
                );
                for provider in &mut providers {
                    normalize_provider(provider);
                }
                result = json!(providers);
            }
            "getExternalProvider" => normalize_provider(&mut result),
            "getConnections" => {
                for connection in result["connections"].as_array_mut().into_iter().flatten() {
                    for port in ["sourcePort", "destinationPort"] {
                        if let Some(number) = connection["metadata"][port].as_u64() {
                            connection["metadata"][port] = json!(number.to_string());
                        }
                    }
                }
            }
            "updateExternalProvider" => {
                self.emit("loaded", arguments);
                result = json!("");
            }
            "changeProxy" => {
                if arguments.get("close-connections").and_then(Value::as_bool) == Some(true) {
                    app.tunnel.statistics().close_all_connections();
                    app.tunnel.close_all_udp_sessions();
                }
                result = json!("");
            }
            "unfixProxy" => result = json!(""),
            "closeConnections" | "resetConnections" | "closeConnection" => result = json!(true),
            _ => {}
        }
        if generation.has_changed().unwrap_or(true) {
            return Err(cancelled());
        }
        Ok(result)
    }
}

fn cancelled() -> RpcError {
    RpcError::new(
        "request_cancelled",
        "The runtime changed while this operation was pending",
    )
}

fn normalize_provider(provider: &mut Value) {
    let vehicle = provider["vehicleType"].clone();
    let updated = provider["updatedAt"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    let count = provider["proxies"].as_array().map_or_else(
        || provider["ruleCount"].as_u64().unwrap_or(0),
        |nodes| nodes.len() as u64,
    );
    provider["vehicle-type"] = vehicle;
    provider["update-at"] = json!(updated);
    provider["count"] = json!(count);
}
