$adapters = @{}
foreach ($adapter in @(Get-NetAdapter)) {
    if ($adapter.InterfaceIndex -eq $excludedInterfaceIndex) { continue }
    $adapters[$adapter.InterfaceIndex.ToString()] = ([guid]$adapter.InterfaceGuid).ToString('D')
}
$families = @{2='IPv4'; 23='IPv6'}
$ids = @(Get-DnsClientServerAddress | ForEach-Object {
    $guid = $adapters[$_.InterfaceIndex.ToString()]
    $family = $families[[int]$_.AddressFamily]
    if ($guid -and $family -and $_.ServerAddresses.Count -gt 0) {
        $guid.ToString() + '|' + $family
    }
})
ConvertTo-Json -InputObject $ids -Compress
