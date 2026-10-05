use meow_common::managed_files::WindowsCaller;
use std::{
    io,
    os::windows::io::{AsHandle, AsRawHandle, FromRawHandle, OwnedHandle},
};
use tokio::net::windows::named_pipe::NamedPipeClient;
use windows_sys::Win32::{
    Foundation::{HANDLE, STILL_ACTIVE},
    Security::{TOKEN_DUPLICATE, TOKEN_QUERY},
    System::{
        Pipes::GetNamedPipeServerProcessId,
        Threading::{
            GetExitCodeProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
        },
    },
};

pub struct WindowsPeer {
    process: OwnedHandle,
    pid: u32,
    pub(crate) caller: WindowsCaller,
}

impl WindowsPeer {
    pub fn from_pipe_client(pipe: &NamedPipeClient) -> io::Result<Self> {
        let pid = server_pid(pipe)?;
        let process =
            owned_handle(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) })?;
        let mut token = std::ptr::null_mut();
        if unsafe {
            OpenProcessToken(
                process.as_raw_handle().cast(),
                TOKEN_QUERY | TOKEN_DUPLICATE,
                &mut token,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let token = owned_handle(token)?;
        let caller = WindowsCaller::duplicate(token.as_handle())?;
        if server_pid(pipe)? != pid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "IPC server process identity changed",
            ));
        }
        let peer = Self {
            process,
            pid,
            caller,
        };
        peer.ensure_alive()?;
        Ok(peer)
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn ensure_alive(&self) -> io::Result<()> {
        let mut exit = 0;
        if unsafe { GetExitCodeProcess(self.process.as_raw_handle().cast(), &mut exit) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if exit != STILL_ACTIVE as u32 {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "The authenticated IPC server process exited",
            ));
        }
        Ok(())
    }
}

fn server_pid(pipe: &NamedPipeClient) -> io::Result<u32> {
    let mut pid = 0;
    if unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle().cast(), &mut pid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if pid == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "IPC server has no process identity",
        ));
    }
    Ok(pid)
}

fn owned_handle(handle: HANDLE) -> io::Result<OwnedHandle> {
    if handle.is_null() {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}
