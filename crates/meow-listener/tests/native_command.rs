#![cfg(feature = "listener-tun")]
use meow_listener::tun::ownership::owned_command_output;
use std::{process::Command, time::Duration};

#[test]
fn native_child_fixture() {
    match std::env::var("MEOW_NATIVE_CHILD_FIXTURE").as_deref() {
        Ok("wait") => std::thread::sleep(Duration::from_secs(30)),
        Ok("flood") => {
            use std::io::Write;
            let _ = std::io::stdout().write_all(&vec![b'x'; 2 * 1024 * 1024]);
        }
        _ => {}
    }
}

fn child(mode: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.args(["--exact", "native_child_fixture", "--nocapture"]);
    command.env("MEOW_NATIVE_CHILD_FIXTURE", mode);
    command
}

#[test]
fn cleanup_commands_own_and_reap_their_children() {
    let output = owned_command_output(&mut child("success"), Duration::from_secs(5)).unwrap();
    assert!(output.status.success());
    let error = owned_command_output(&mut child("wait"), Duration::from_millis(100)).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    let error = owned_command_output(&mut child("flood"), Duration::from_secs(5)).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::FileTooLarge);
}
