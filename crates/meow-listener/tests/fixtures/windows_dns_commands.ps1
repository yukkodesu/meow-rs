$script:queryFailure = $false
function Get-NetAdapter {
    foreach ($index in 1..3) {
        [pscustomobject]@{
            InterfaceIndex = $index
            InterfaceGuid = [guid](('11111111-1111-1111-1111-111111111111',
                '22222222-2222-2222-2222-222222222222',
                '33333333-3333-3333-3333-333333333333')[$index - 1])
        }
    }
}
function Get-DnsClientServerAddress {
    param([int]$InterfaceIndex, [string]$AddressFamily)
    if ($script:queryFailure) { throw 'DNS provider query failed' }
    $records = @(
        [pscustomobject]@{InterfaceIndex=1; AddressFamily=2; ServerAddresses=@('192.0.2.53')},
        [pscustomobject]@{InterfaceIndex=1; AddressFamily=23; ServerAddresses=@('2001:db8::53')},
        [pscustomobject]@{InterfaceIndex=2; AddressFamily=23; ServerAddresses=@('2001:db8::54')},
        [pscustomobject]@{InterfaceIndex=3; AddressFamily=2; ServerAddresses=@()}
    )
    if ($InterfaceIndex) {
        $code = if ($AddressFamily -eq 'IPv4') { 2 } else { 23 }
        $found = @($records | Where-Object { $_.InterfaceIndex -eq $InterfaceIndex -and $_.AddressFamily -eq $code })
        if ($found.Count -eq 0) { throw 'CmdletizationQuery_NotFound: DNS address-family object is absent' }
        return $found
    }
    return $records
}
