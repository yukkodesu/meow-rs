$adapter = @(Get-NetAdapter | Where-Object {
    ([guid]$_.InterfaceGuid).ToString('D') -eq $guid
})
if ($adapter.Count -ne 1) {
    throw 'Owned DNS adapter missing or ambiguous; restoration cannot be confirmed'
}
