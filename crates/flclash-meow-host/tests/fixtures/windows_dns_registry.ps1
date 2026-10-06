$script:registryFailure = $false
$script:adapterFailure = $false
$script:noKeys = $false
$script:values = @{
    'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{11111111-1111-1111-1111-111111111111}' = '192.0.2.53'
    'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\{11111111-1111-1111-1111-111111111111}' = ''
    'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}' = '198.51.100.53'
}
function Get-NetAdapter {
    if ($script:adapterFailure) { throw 'Adapter snapshot provider failed' }
    [pscustomobject]@{InterfaceGuid='{11111111-1111-1111-1111-111111111111}'}
    [pscustomobject]@{InterfaceGuid='{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}'}
}
function Get-Item {
    [CmdletBinding()]
    param([Parameter(Position=0)][string]$LiteralPath)
    if ($script:registryFailure) { throw [UnauthorizedAccessException]::new('Registry snapshot access denied') }
    if ($script:noKeys -or !$script:values.ContainsKey($LiteralPath)) {
        Write-Error -Exception ([System.Management.Automation.ItemNotFoundException]::new('DNS family registry key absent'))
        return
    }
    [pscustomobject]@{value=$script:values[$LiteralPath]} |
        Add-Member -MemberType ScriptMethod -Name GetValue -Value {param($name,$default) $this.value} -PassThru
}
