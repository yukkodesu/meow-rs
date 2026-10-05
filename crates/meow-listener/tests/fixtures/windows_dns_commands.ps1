$script:queryFailure = $false
$script:adapterQueryFailure = $false
$script:invalidGuid = $false
function Get-NetAdapter {
    if ($script:adapterQueryFailure) { throw 'Adapter provider query failed' }
    foreach ($index in 1..3) {
        [pscustomobject]@{
            InterfaceIndex = $index
            InterfaceGuid = $(if ($script:invalidGuid -and $index -eq 1) { 'not-a-guid' }
                elseif ($index -eq 2) { [guid]'22222222-2222-2222-2222-222222222222' }
                else { ('{11111111-1111-1111-1111-111111111111}',
                    '{22222222-2222-2222-2222-222222222222}',
                    '{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}')[$index - 1] })
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
