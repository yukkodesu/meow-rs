use super::Runtime;
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::path::PathBuf;
use tokio::time::Instant;

pub(super) struct Background {
    pub home: PathBuf,
    pub listeners: Vec<Value>,
    pub dns: Option<String>,
    pub controller: Option<String>,
    traffic: Mutex<TrafficSample>,
}

struct TrafficSample {
    at: Instant,
    totals: (i64, i64),
    rates: (i64, i64),
}

impl Background {
    pub fn new(home: PathBuf) -> Self {
        Self {
            home,
            listeners: Vec::new(),
            dns: None,
            controller: None,
            traffic: Mutex::new(TrafficSample {
                at: Instant::now(),
                totals: (0, 0),
                rates: (0, 0),
            }),
        }
    }

    pub fn clear(&mut self) {
        self.listeners.clear();
        self.dns = None;
        self.controller = None;
    }
}

impl Runtime {
    pub fn endpoints(&self) -> Value {
        json!({"listeners": self.background.listeners, "dnsListen": self.background.dns, "externalController": self.background.controller})
    }

    pub fn traffic(&self) -> (i64, i64) {
        if !self.running() {
            return (0, 0);
        }
        let mut sample = self.background.traffic.lock();
        let now = Instant::now();
        let elapsed = now.duration_since(sample.at);
        if elapsed.as_secs() >= 1 {
            let totals = self.state.tunnel.statistics().snapshot();
            let nanos = i128::try_from(elapsed.as_nanos()).unwrap_or(i128::MAX);
            let rate = |total: i64, previous: i64| {
                i64::try_from(i128::from(total.saturating_sub(previous)) * 1_000_000_000 / nanos)
                    .unwrap_or(i64::MAX)
            };
            sample.rates = (
                rate(totals.0, sample.totals.0),
                rate(totals.1, sample.totals.1),
            );
            sample.totals = totals;
            sample.at = now;
        }
        sample.rates
    }

    pub(super) fn start_background_tasks(&mut self) {
        *self.background.traffic.lock() = TrafficSample {
            at: Instant::now(),
            totals: self.state.tunnel.statistics().snapshot(),
            rates: (0, 0),
        };
        let geo = self.config.geodata.clone();
        let state = std::sync::Arc::clone(&self.state);
        let home = self.background.home.clone();
        self.tasks.spawn(async move {
            meow_app::geodata_fetch::run_on_startup(
                geo,
                state.tunnel.clone(),
                std::sync::Arc::clone(&state.raw_config),
                std::sync::Arc::clone(&state.rule_providers),
                std::sync::Arc::clone(&state.proxy_providers),
                std::sync::Arc::clone(&state.dns_server),
                Some(home),
            )
            .await;
        });
        if self.config.geodata.auto_update {
            let geo = self.config.geodata.clone();
            let state = std::sync::Arc::clone(&self.state);
            let home = self.background.home.clone();
            self.tasks.spawn(async move {
                meow_app::geodata_fetch::auto_update_loop(
                    geo,
                    state.tunnel.clone(),
                    std::sync::Arc::clone(&state.raw_config),
                    std::sync::Arc::clone(&state.rule_providers),
                    std::sync::Arc::clone(&state.proxy_providers),
                    std::sync::Arc::clone(&state.dns_server),
                    Some(home),
                )
                .await;
            });
        }
    }
}
