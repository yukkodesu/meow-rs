$base = [Environment]::GetFolderPath('CommonApplicationData')
$product = Join-Path $base 'FlClash-Meow'
$recovery = Join-Path $product 'tun'
$trusted = @('S-1-5-32-544', 'S-1-5-18')

function Assert-TrustedItem($item) {
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'Recovery resource is a reparse point'
    }
    $acl = Get-Acl -LiteralPath $item.FullName
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted) {
        throw 'Recovery resource has an untrusted owner'
    }
    $writes = [Security.AccessControl.FileSystemRights]::Write -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership
    foreach ($rule in $acl.Access) {
        $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        if ($rule.AccessControlType -eq 'Allow' -and $sid -notin $trusted -and ($rule.FileSystemRights -band $writes)) {
            throw 'Recovery resource permits untrusted writes'
        }
    }
}

foreach ($directory in @($product, $recovery)) {
    if (!(Test-Path -LiteralPath $directory)) {
        $acl = New-Object Security.AccessControl.DirectorySecurity
        $acl.SetAccessRuleProtection($true, $false)
        $admin = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
        $acl.SetOwner($admin)
        foreach ($sid in $trusted) {
            $identity = New-Object Security.Principal.SecurityIdentifier($sid)
            $rule = New-Object Security.AccessControl.FileSystemAccessRule($identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
            $acl.AddAccessRule($rule)
        }
        $users = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-545')
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($users, 'ReadAndExecute', 'ContainerInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
        $null = [IO.Directory]::CreateDirectory($directory, $acl)
    }
    Assert-TrustedItem (Get-Item -LiteralPath $directory -Force)
    $acl = Get-Acl -LiteralPath $directory
    $users = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-545')
    $rule = New-Object Security.AccessControl.FileSystemAccessRule($users, 'ReadAndExecute', 'ContainerInherit', 'None', 'Allow')
    $acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $directory -AclObject $acl
}

foreach ($name in @('dns.json', 'routes.json', 'dns.pending', 'routes.pending', 'resources.lock')) {
    $file = Join-Path $recovery $name
    if (Test-Path -LiteralPath $file) {
        Assert-TrustedItem (Get-Item -LiteralPath $file -Force)
    }
}
$recovery
