$result = @(foreach ($adapter in @(Get-NetAdapter)) {
    $guid = ([guid]$adapter.InterfaceGuid).ToString('D')
    foreach ($family in 'Tcpip','Tcpip6') {
        $path = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $family + '\Parameters\Interfaces\{' + $guid + '}'
        try {
            $key = Get-Item -LiteralPath $path -ErrorAction Stop
        } catch [System.Management.Automation.ItemNotFoundException] {
            continue
        }
        [pscustomobject]@{adapter=$guid;family=$family;servers=$key.GetValue('NameServer','')}
    }
})
if ($result.Count -eq 0) { throw 'Native DNS snapshot captured no adapter registry resources' }
ConvertTo-Json -InputObject @($result | Sort-Object adapter,family) -Compress
