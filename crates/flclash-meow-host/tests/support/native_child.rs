use serde_json::{json, Value};
use std::{io, time::Duration};
use tokio::process::Child;

pub async fn observe_exit(child: &mut Child, budget: Duration) -> io::Result<Value> {
    let pid = child.id();
    let status = match child.try_wait()? {
        Some(status) => Some(status),
        None => match tokio::time::timeout(budget, child.wait()).await {
            Ok(status) => Some(status?),
            Err(_) => None,
        },
    };
    Ok(json!({
        "pid":pid,
        "exited":status.is_some(),
        "exitStatus":status.as_ref().map(ToString::to_string),
        "exitCode":status.as_ref().and_then(std::process::ExitStatus::code),
        "exitCodeHex":status.as_ref().and_then(std::process::ExitStatus::code).map(|code| format!("0x{:08x}", code as u32)),
    }))
}
