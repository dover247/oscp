# File Transfer Protocol

### Anonymous Access

_Check for anonymous login guest, ftp, anonymous, anonymous@anonymous.com_

```
ftp $ip
```

### File Download

_Type "passive" if needed to remove passive mode to be able to continue to access ftp. type "binary" first then get to download files_

```
ftp> passive
ftp> binary
```

_Recursively download files via ftp_

```
wget -r ftp://user:pass@ip/
```

_If you find password-protected zip files use zip2john followed by john the hash_

```
zip2john file.zip >> hashes.txt
john hashes.txt
```

### File upload remote code execution

_If ftp allows uploading of files and the webserver has an local file inclusion vulnerability you can upload a php shell and call the file from the webserver to gain a reverse shell maybe it’ll have functionality that auto-executes uploaded files periodically._

_ProFTPd 1.3.5 - 'mod\_copy' Remote Command Execution_

### Meta Data

_Extract meta data and may contain email addresses_

```
exiftool file
```
