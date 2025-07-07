# Let's obtain all the actual user's groups first by their name, not SID:
$myIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$myGroups = $myIdentity.Groups | ForEach-Object {
    try {
        $_.Translate([System.Security.Principal.NTAccount]).Value
    } catch {
        $_.Value
    }
}
$myGroups += $myIdentity.Name  # Add the user directly

# Let's iterate all CLSID keys:
$base = "HKLM:\Software\Classes\CLSID"
$clsids = Get-ChildItem -Path $base -ErrorAction SilentlyContinue

foreach ($clsid in $clsids) {
    $inprocPath = Join-Path $clsid.PSPath "InprocServer32"
    
    if (Test-Path $inprocPath) {
        try {
            $acl = Get-Acl $inprocPath
            foreach ($access in $acl.Access) {
                $identity = $access.IdentityReference.Value
                $rights = $access.RegistryRights

                # Does the actual user or group have WRITE PERMISSIONS (W or RW)?:
                if ($myGroups -contains $identity -and $rights -match "SetValue|WriteKey|FullControl") {
                    Write-Host "[PWN] Writable CLSID found!"
                    Write-Host "      Key: $inprocPath"
                    Write-Host "      Who: $identity"
                    Write-Host "      Rights: $rights`n"
                }
            }
        } catch {
            continue
        }
    }
}
