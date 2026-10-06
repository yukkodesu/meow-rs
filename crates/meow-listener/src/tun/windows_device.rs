use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use std::{io, net::IpAddr};
use windows_sys::Win32::{
    Foundation::ERROR_SUCCESS,
    NetworkManagement::IpHelper::{
        CreateUnicastIpAddressEntry, GetIpInterfaceEntry, InitializeUnicastIpAddressEntry,
        SetIpInterfaceEntry, MIB_IPINTERFACE_ROW, MIB_UNICASTIPADDRESS_ROW,
    },
    Networking::WinSock::{IpDadStatePreferred, AF_INET, AF_INET6},
};

fn check(result: u32) -> io::Result<()> {
    if result == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(result as i32))
    }
}

pub(super) fn configure_addresses(
    index: u32,
    ipv4: Ipv4Net,
    ipv6: Option<Ipv6Net>,
) -> io::Result<()> {
    for network in std::iter::once(IpNet::V4(ipv4)).chain(ipv6.map(IpNet::V6)) {
        let family = if network.addr().is_ipv4() {
            AF_INET
        } else {
            AF_INET6
        };
        let mut interface = MIB_IPINTERFACE_ROW {
            Family: family,
            InterfaceIndex: index,
            ..Default::default()
        };
        check(unsafe { GetIpInterfaceEntry(&mut interface) })?;
        interface.DadTransmits = 0;
        // Windows can return an IPv4 site prefix that SetIpInterfaceEntry rejects.
        interface.SitePrefixLength = 0;
        check(unsafe { SetIpInterfaceEntry(&mut interface) })?;

        let mut address = MIB_UNICASTIPADDRESS_ROW::default();
        unsafe { InitializeUnicastIpAddressEntry(&mut address) };
        address.InterfaceIndex = index;
        address.OnLinkPrefixLength = network.prefix_len();
        address.DadState = IpDadStatePreferred;
        address.ValidLifetime = u32::MAX;
        address.PreferredLifetime = u32::MAX;
        match network.addr() {
            IpAddr::V4(ip) => {
                address.Address.Ipv4.sin_family = AF_INET;
                address.Address.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(ip.octets());
            }
            IpAddr::V6(ip) => {
                address.Address.Ipv6.sin6_family = AF_INET6;
                address.Address.Ipv6.sin6_addr.u.Byte = ip.octets();
            }
        }
        check(unsafe { CreateUnicastIpAddressEntry(&address) })?;
    }
    Ok(())
}
