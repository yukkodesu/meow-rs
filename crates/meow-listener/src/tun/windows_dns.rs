use std::{io, net::IpAddr, ptr};
use windows_sys::{
    core::GUID,
    Win32::{
        Foundation::{ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_SUCCESS},
        NetworkManagement::{
            IpHelper::{
                ConvertInterfaceGuidToLuid, DNS_INTERFACE_SETTINGS,
                DNS_INTERFACE_SETTINGS_VERSION1, DNS_SETTING_IPV6, DNS_SETTING_NAMESERVER,
            },
            Ndis::NET_LUID_LH,
        },
        System::{
            LibraryLoader::{GetModuleHandleW, GetProcAddress},
            Registry::{
                RegCloseKey, RegGetValueW, RegOpenKeyExW, HKEY, HKEY_LOCAL_MACHINE,
                KEY_QUERY_VALUE, RRF_RT_REG_SZ,
            },
        },
    },
};

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

fn adapter_guid(value: &str) -> io::Result<GUID> {
    let guid = GUID::from_u128(
        u128::from_str_radix(&value.replace('-', ""), 16).map_err(io::Error::other)?,
    );
    let mut luid = NET_LUID_LH::default();
    let result = unsafe { ConvertInterfaceGuidToLuid(&guid, &mut luid) };
    if result != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(result as i32));
    }
    Ok(guid)
}

struct RegistryKey(HKEY);

impl Drop for RegistryKey {
    fn drop(&mut self) {
        unsafe { RegCloseKey(self.0) };
    }
}

pub(super) fn read(guid: &str, family: &str) -> io::Result<Vec<IpAddr>> {
    adapter_guid(guid)?;
    let service = if family == "IPv4" { "Tcpip" } else { "Tcpip6" };
    let key = wide(&format!(
        "SYSTEM\\CurrentControlSet\\Services\\{service}\\Parameters\\Interfaces\\{{{guid}}}"
    ));
    let value = wide("NameServer");
    let mut handle = ptr::null_mut();
    let result = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            0,
            KEY_QUERY_VALUE,
            &mut handle,
        )
    };
    if result != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(result as i32));
    }
    let handle = RegistryKey(handle);
    let mut buffer = vec![0u16; 256];
    loop {
        let mut bytes = (buffer.len() * size_of::<u16>()) as u32;
        let result = unsafe {
            RegGetValueW(
                handle.0,
                ptr::null(),
                value.as_ptr(),
                RRF_RT_REG_SZ,
                ptr::null_mut(),
                buffer.as_mut_ptr().cast(),
                &mut bytes,
            )
        };
        match result {
            ERROR_SUCCESS => {
                let end = buffer.iter().position(|v| *v == 0).unwrap_or(buffer.len());
                let text = String::from_utf16(&buffer[..end]).map_err(io::Error::other)?;
                return parse_addresses(&text);
            }
            ERROR_FILE_NOT_FOUND => return Ok(Vec::new()),
            ERROR_MORE_DATA if bytes <= 65536 => buffer.resize(bytes as usize / 2 + 1, 0),
            _ => return Err(io::Error::from_raw_os_error(result as i32)),
        }
    }
}

fn parse_addresses(text: &str) -> io::Result<Vec<IpAddr>> {
    text.split(|c: char| c == ',' || c == ';' || c.is_whitespace())
        .filter(|part| !part.is_empty())
        .map(|part| part.parse().map_err(io::Error::other))
        .collect()
}

type SetDns = unsafe extern "system" fn(GUID, *const DNS_INTERFACE_SETTINGS) -> u32;

pub(super) fn write(guid: &str, family: &str, addresses: &[IpAddr]) -> io::Result<bool> {
    let guid = adapter_guid(guid)?;
    let module = unsafe { GetModuleHandleW(wide("iphlpapi.dll").as_ptr()) };
    if module.is_null() {
        return Err(io::Error::last_os_error());
    }
    let Some(function) =
        (unsafe { GetProcAddress(module, c"SetInterfaceDnsSettings".as_ptr().cast()) })
    else {
        return Ok(false);
    };
    let set_dns: SetDns = unsafe { std::mem::transmute(function) };
    let text = addresses
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let mut servers = wide(&text);
    let settings = DNS_INTERFACE_SETTINGS {
        Version: DNS_INTERFACE_SETTINGS_VERSION1,
        Flags: u64::from(DNS_SETTING_NAMESERVER)
            | if family == "IPv6" {
                u64::from(DNS_SETTING_IPV6)
            } else {
                0
            },
        NameServer: servers.as_mut_ptr(),
        ..Default::default()
    };
    let result = unsafe { set_dns(guid, &settings) };
    if result != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(result as i32));
    }
    Ok(true)
}
