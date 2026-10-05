use std::time::Duration;
use tokio::process::Command;

#[path = "support/native_child.rs"]
mod native_child;

fn delayed_child(exit: bool) -> Command {
    #[cfg(windows)]
    let mut command = Command::new("powershell.exe");
    #[cfg(windows)]
    command.args([
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        if exit {
            "Start-Sleep -Milliseconds 100; exit 7"
        } else {
            "Start-Sleep -Seconds 30"
        },
    ]);
    #[cfg(unix)]
    let mut command = Command::new("sh");
    #[cfg(unix)]
    command.args([
        "-c",
        if exit {
            "sleep 0.1; exit 7"
        } else {
            "exec sleep 30"
        },
    ]);
    command.kill_on_drop(true);
    command
}

#[tokio::test]
async fn eof_observer_records_a_delayed_child_exit_without_claiming_live_release() {
    let mut exiting = delayed_child(true).spawn().unwrap();
    let observed = native_child::observe_exit(&mut exiting, Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(observed["exited"], true);
    assert_eq!(observed["exitCode"], 7);
    assert_eq!(observed["exitCodeHex"], "0x00000007");
    assert!(!observed["exitStatus"].as_str().unwrap().is_empty());
    assert_eq!(exiting.wait().await.unwrap().code(), Some(7));

    let mut live = delayed_child(false).spawn().unwrap();
    let elapsed = std::time::Instant::now();
    let observed = native_child::observe_exit(&mut live, Duration::from_millis(25))
        .await
        .unwrap();
    assert_eq!(observed["exited"], false);
    assert!(observed["exitCode"].is_null());
    assert!(live.try_wait().unwrap().is_none());
    assert!(elapsed.elapsed() < Duration::from_secs(1));
    live.kill().await.unwrap();
    live.wait().await.unwrap();
}
